import io
import json
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

import report_writer
from module.contracts import cookie_dict, cookie_header, normalize_finding, public_parameters
from module import scanner_tools
from module.analysis_stub import TOOL_SCHEMA as STUB_TOOL_SCHEMA, analyze_endpoint_stub
from module.tool_registry import SCANNERS, TOOL_SCHEMAS, execute_tool
from module.ssrf.scanner import SSRFScanner


ARGS = {
    "url": "http://127.0.0.1:8080/search",
    "method": "GET",
    "parameters": [{"name": "content", "location": "query"}],
}


class ScannerIntegrationTest(unittest.TestCase):
    def test_original_stub_contract_dispatches_to_the_real_scanner(self):
        finding = {
            "scanner_id": "sqli", "name": "SQL Injection", "url": ARGS["url"],
            "method": "GET", "parameters": ARGS["parameters"], "vuln": "PASS",
            "result": "차단됨", "severity": "NONE", "details": {},
        }
        self.assertEqual(
            set(STUB_TOOL_SCHEMA["parameters"]["required"]),
            {"url", "method", "parameters", "vulnerability_type"},
        )
        with patch("module.analysis_stub.execute_tool", return_value=[finding]) as execute:
            result = analyze_endpoint_stub(**ARGS, vulnerability_type="sqli")
        self.assertEqual(result, [finding])
        execute.assert_called_once_with(
            "scan_sqli", ARGS, session_cookie="", options=None,
        )

    def test_all_function_tools_use_the_common_input_without_cookie(self):
        self.assertEqual(len(TOOL_SCHEMAS), 9)
        for schema in TOOL_SCHEMAS:
            properties = schema["parameters"]["properties"]
            self.assertEqual(set(properties), {"url", "method", "parameters"})
            self.assertEqual(
                set(schema["parameters"]["required"]),
                {"url", "method", "parameters"},
            )
            self.assertNotIn("session_cookie", json.dumps(schema))

    def test_parameter_values_are_removed_from_public_output(self):
        parameters = [{"name": "keyword", "location": "query", "value": "private"}]
        self.assertEqual(public_parameters(parameters), [{"name": "keyword", "location": "query"}])

    def test_value_only_cookie_uses_the_lab_session_cookie_name(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(cookie_dict("opaque-session-value"), {
                "sslc_lab_session": "opaque-session-value",
            })
            self.assertEqual(
                cookie_header("opaque-session-value"),
                "sslc_lab_session=opaque-session-value",
            )

    def test_sqli_receives_value_only_session_cookie(self):
        native = {
            "url": ARGS["url"], "method": "GET", "parameters": "content",
            "vuln": "SAFE", "result": {"evidence": "미탐지"}, "severity": "NONE",
        }
        with patch.object(scanner_tools, "run_sqli_native", return_value=native) as run:
            scanner_tools.scan_sqli(
                ARGS["url"], "GET", ARGS["parameters"], "opaque-session-value",
            )
        self.assertEqual(run.call_args.args[3], {
            "sslc_lab_session": "opaque-session-value",
        })

    def test_aliases_are_normalized_to_four_vulnerability_states(self):
        finding = normalize_finding(
            {"vuln": "SAFE", "result": "차단됨"},
            scanner_id="test",
            name="Test",
            fallback_url=ARGS["url"],
            fallback_method="GET",
            fallback_parameters=ARGS["parameters"],
        )
        self.assertEqual(finding["vuln"], "PASS")
        self.assertEqual(finding["result"], "차단됨")

    def test_scanner_exception_does_not_expose_cookie(self):
        def fail(**kwargs):
            raise RuntimeError("session=private-cookie")

        with patch.dict(SCANNERS, {"scan_sqli": fail}):
            findings = execute_tool(
                "scan_sqli", ARGS, session_cookie="session=private-cookie",
            )
        serialized = json.dumps(findings, ensure_ascii=False)
        self.assertEqual(findings[0]["vuln"], "ERROR")
        self.assertNotIn("private-cookie", serialized)

    def test_sqli_adapter_preserves_common_parameter_location(self):
        native = {
            "url": ARGS["url"], "method": "POST", "parameters": "content",
            "vuln": "SAFE", "result": {"evidence": "미탐지"}, "severity": "NONE",
        }
        with patch.object(scanner_tools, "run_sqli_native", return_value=native):
            findings = scanner_tools.scan_sqli(
                ARGS["url"], "POST", [{"name": "content", "location": "body"}], "",
            )
        self.assertEqual(findings[0]["vuln"], "PASS")
        self.assertEqual(findings[0]["parameters"], [{"name": "content", "location": "body"}])

    def test_xss_request_error_is_not_reported_as_pass(self):
        raw = {
            "url": ARGS["url"], "method": "GET", "parameters": {"content": ""},
            "vuln": False,
            "result": [{"parameter": "content", "vulnerable": False, "reason": "request error: Timeout"}],
        }
        with patch.object(scanner_tools.ReflectedXSSScanner, "scan", return_value=raw):
            findings = scanner_tools.scan_reflected_xss(
                ARGS["url"], "GET", ARGS["parameters"], "",
            )
        self.assertEqual(findings[0]["vuln"], "ERROR")

    def test_xss_adapter_runs_context_check_and_reports_reflection(self):
        def reflect(_scanner, _target, _parameter, value):
            return SimpleNamespace(text=f"<html>{value}</html>")

        with patch.object(scanner_tools.ReflectedXSSScanner, "_send", reflect):
            findings = scanner_tools.scan_reflected_xss(
                ARGS["url"], "GET", ARGS["parameters"], "",
            )
        self.assertEqual(findings[0]["vuln"], "VULNERABLE")
        self.assertIn("raw_result", findings[0]["details"])

    def test_ssrf_uses_verifier_evidence_without_internal_ai(self):
        response = SimpleNamespace(
            status_code=200,
            headers={},
            text="ok",
            elapsed=SimpleNamespace(total_seconds=lambda: 0.1),
            content=b"ok",
        )
        scanner = SSRFScanner({
            "url": "http://127.0.0.1:8080/pre-course/write",
            "method": "POST",
            "parameters": {"url": "http://internal-service:9000/health"},
        })
        with patch.object(scanner, "send_request", return_value=response), \
                patch.object(scanner, "check_verifier", side_effect=lambda scan_id: {
                    "received": True, "id": scan_id, "path": f"/check/{scan_id}",
                }):
            with redirect_stdout(io.StringIO()):
                result = scanner.scan()
        scanner.session.close()
        self.assertEqual(result["vuln"], "VULNERABLE")
        self.assertIn("서버 측 요청", result["result"])

    def test_account_based_scanners_return_review_without_private_config(self):
        with patch.dict("os.environ", {}, clear=True):
            fileio = scanner_tools.scan_fileio(ARGS["url"], "GET", ARGS["parameters"])
            authz = scanner_tools.scan_authz(ARGS["url"], "GET", ARGS["parameters"])
        self.assertEqual(fileio[0]["vuln"], "REVIEW")
        self.assertEqual(authz[0]["vuln"], "REVIEW")

    def test_fileio_can_use_in_memory_lab_password(self):
        config = {
            "accounts": {
                "victim": {"userId": "student1", "password_env": "PRIVATE"},
            }
        }
        raw = [{
            "result": "SAFE", "reason": "차단됨", "url": ARGS["url"],
            "method": "GET", "parameters": [], "severity": "NONE",
        }]
        with patch.object(scanner_tools, "_load_example_config", return_value=config), \
                patch.object(scanner_tools, "run_fileio_native", return_value=raw) as run:
            findings = scanner_tools.scan_fileio(
                ARGS["url"], "GET", ARGS["parameters"],
                options={"lab_password": "runtime-secret"},
            )
        account = run.call_args.args[0]["accounts"]["victim"]
        self.assertEqual(account["password"], "runtime-secret")
        self.assertNotIn("password_env", account)
        self.assertNotIn("runtime-secret", json.dumps(findings, ensure_ascii=False))

    def test_authz_compares_two_runtime_sessions_without_storing_cookies(self):
        def http_response(body, status=200, location=""):
            return SimpleNamespace(
                status_code=status,
                text=body,
                content=body.encode("utf-8"),
                headers={"Location": location} if location else {},
            )

        protected = "private-profile:" + "x" * 120
        with patch.object(scanner_tools, "_request", side_effect=[
            http_response(protected),
            http_response(protected),
            http_response("", 302, "/login"),
        ]):
            findings = scanner_tools.scan_authz(
                "http://127.0.0.1:8080/api/profiles/1",
                "GET",
                [{"name": "id", "location": "path"}],
                "owner-cookie",
                {"authz_attacker_cookie": "attacker-cookie"},
            )
        self.assertEqual(findings[0]["vuln"], "VULNERABLE")
        serialized = json.dumps(findings, ensure_ascii=False)
        self.assertNotIn("owner-cookie", serialized)
        self.assertNotIn("attacker-cookie", serialized)

    def test_final_report_has_common_and_dashboard_views_and_redacts_secrets(self):
        analysis = {
            "model": "test-model",
            "summary": "완료",
            "tool_call_count": 1,
            "tool_results": [{
                "scanner_id": "sqli", "name": "SQL Injection",
                "url": ARGS["url"], "method": "GET", "parameters": ARGS["parameters"],
                "vuln": "VULNERABLE", "result": "반복 증거 확인", "severity": "HIGH",
                "details": {"session_cookie": "private-cookie"},
            }],
        }
        report = report_writer.build_scan_report("http://127.0.0.1:8080", analysis)
        self.assertEqual(report["summary"]["vulnerable"], 1)
        self.assertTrue(report["results"][0]["vulnerable"])
        self.assertEqual(report["findings"][0]["details"]["session_cookie"], "[REDACTED]")
        self.assertNotIn("private-cookie", json.dumps(report))

        passed = dict(analysis)
        passed["tool_results"] = [dict(analysis["tool_results"][0], vuln="PASS")]
        passed_report = report_writer.build_scan_report("http://127.0.0.1:8080", passed)
        self.assertFalse(passed_report["results"][0]["vulnerable"])
        self.assertEqual(passed_report["results"][0]["findings"], [])


if __name__ == "__main__":
    unittest.main()
