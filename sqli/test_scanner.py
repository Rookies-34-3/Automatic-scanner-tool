"""외부 사이트에 접속하지 않고 판정과 로그인 흐름을 검증한다."""
import unittest
import contextlib
import io
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from scanner import Scanner, ScanError, format_finding, main, run


def response(body, status=200):
    result = requests.Response()
    result.status_code = status
    result._content = body.encode("utf-8")
    result.encoding = "utf-8"
    return result


def board(text):
    return response(f"<table><tbody><tr><td>{text}</td></tr></tbody></table>")


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.target = {"path": "/my-class/board/qna", "parameter": "content"}
        self.scanner = Scanner({
            "base_url": "http://localhost:8080", "delay": 0,
            "login_path": "/login", "username": "student1", "targets": [self.target],
        })
        self.addCleanup(self.scanner.session.close)

    def run_scan(self, responder):
        self.scanner.request = Mock(side_effect=lambda method, path, params: responder(params["content"]))
        return self.scanner.scan(self.target, "TEST")

    def test_error_with_http_500(self):
        result = self.run_scan(lambda p: response("You have an error in your SQL syntax", 500) if p else board("게시물"))
        self.assertEqual(result["result"], "VULNERABLE")
        self.assertEqual(result["status_code"], 500)

    def test_boolean_without_error(self):
        def serve(payload):
            if not payload or "1=1" in payload:
                return board("게시물 A 게시물 B")
            return board("검색 결과 없음")
        result = self.run_scan(serve)
        self.assertEqual(result["result"], "VULNERABLE")
        self.assertIn("boolean", [c["type"] for c in result["details"]["checks"]])

    def test_error_then_boolean_both_confirmed(self):
        def serve(payload):
            if payload == "'":
                return response("You have an error in your SQL syntax", 500)
            return board("게시물" if not payload or "1=1" in payload else "검색 결과 없음")
        result = self.run_scan(serve)
        self.assertEqual(result["result"], "VULNERABLE")
        checks = result["details"]["checks"]
        self.assertEqual([(c["type"], c["confirmed"]) for c in checks],
                         [("error", True), ("boolean", True)])
        self.assertEqual(result["payload"], "'")
        self.assertIn("MySQL 오류", result["evidence"])
        self.assertIn("참 조건", result["evidence"])
        public = format_finding(result, "http://localhost/search")
        self.assertEqual(public["result"]["checks"], checks)
        self.assertEqual(public["vuln"], "VULNERABLE")

    def test_error_confirmed_boolean_no_evidence(self):
        result = self.run_scan(lambda p: response("You have an error in your SQL syntax", 500)
                               if p == "'" else board("동일 결과"))
        self.assertEqual(result["result"], "VULNERABLE")
        self.assertEqual([c["confirmed"] for c in result["details"]["checks"]], [True, False, False])

    def test_error_confirmed_boolean_failures_preserve_evidence(self):
        for mode in ("unstable", "timeout", "redirect", "missing_region", "baseline_changed"):
            counter = iter(range(100))
            baseline_count = 0
            def serve(payload):
                nonlocal baseline_count
                if payload == "'":
                    return response("You have an error in your SQL syntax", 500)
                if not payload:
                    baseline_count += 1
                    if mode == "missing_region":
                        return response("<p>no table</p>")
                    return board(str(baseline_count) if mode == "baseline_changed" else "게시물")
                if mode == "timeout":
                    raise ScanError("네트워크 요청 실패: Timeout")
                if mode == "redirect":
                    return response("", 302)
                return board(str(next(counter)))
            with self.subTest(mode=mode):
                result = self.run_scan(serve)
                self.assertEqual(result["result"], "VULNERABLE")
                self.assertIn("MySQL 오류", result["evidence"])
                self.assertEqual(result["payload"], "'")
                check = result["details"]["checks"][-1]
                self.assertEqual(check["type"], "boolean")
                self.assertFalse(check["completed"])
                self.assertTrue(check["reason"])

    def test_safe_with_reflected_search_term(self):
        def serve(payload):
            return response(f'<input value="{payload}"><table><tbody>{"검색 결과 없음" if payload else "게시물"}</tbody></table>')
        self.assertEqual(self.run_scan(serve)["result"], "SAFE")

    def test_access_denied(self):
        self.assertEqual(self.run_scan(lambda p: response("Forbidden", 403))["result"], "N/A")

    def test_error_not_reproduced(self):
        replies = iter([board("게시물"), response("You have an error in your SQL syntax"), board("게시물")])
        self.assertEqual(self.run_scan(lambda p: next(replies))["result"], "N/A")

    def test_redirect(self):
        self.assertEqual(self.run_scan(lambda p: response("", 302))["result"], "N/A")

    def test_missing_results_selector(self):
        self.assertEqual(self.run_scan(lambda p: response("<p>게시판</p>"))["result"], "N/A")

    def test_baseline_error(self):
        result = self.run_scan(lambda p: response("You have an error in your SQL syntax"))
        self.assertEqual(result["result"], "N/A")

    def test_dynamic_baseline(self):
        counter = iter(range(100))
        self.assertEqual(self.run_scan(lambda p: board(str(next(counter))))["result"], "N/A")

    def test_login_csrf_and_session(self):
        self.scanner.request = Mock(side_effect=[
            response('<input name="csrf_token" value="abc">'),
            response("", 302), board("게시물"),
        ])
        self.scanner.login("test-password")
        sent = self.scanner.request.call_args_list[1].kwargs["data"]
        self.assertEqual(sent, {"userId": "student1", "password": "test-password", "csrf_token": "abc"})

    def test_login_redirect_is_not_enough(self):
        self.scanner.request = Mock(side_effect=[
            response('<input name="csrf_token" value="abc">'), response("", 302), response("", 302),
        ])
        with self.assertRaises(ScanError):
            self.scanner.login("wrong")

    def test_timeout(self):
        self.scanner.session.request = Mock(side_effect=requests.Timeout())
        with self.assertRaisesRegex(ScanError, "Timeout"):
            self.scanner.request("GET", self.target["path"])

    def test_other_origin_rejected(self):
        with self.assertRaises(ScanError):
            self.scanner.request("GET", "http://other.invalid/login")


class ToolTests(unittest.TestCase):
    def call_tool(self, method, responder, url="http://localhost:8080/search"):
        session = requests.Session()
        session.request = Mock(side_effect=lambda method, url, **kwargs: responder(kwargs))
        session.close = Mock()
        with patch("scanner.requests.Session", return_value=session), \
                patch("scanner.time.sleep"), patch.object(Scanner, "login") as login:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                result = run(url, method, "content", {"session": "test-cookie"})
        login.assert_not_called()
        session.close.assert_called_once()
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(session.cookies.get("session"), "test-cookie")
        self.assertNotIn("test-cookie", json.dumps(result))
        self.assertIsInstance(result["result"], dict)
        self.assertEqual(result["url"], url)
        self.assertEqual(result["parameters"], "content")
        return result, session

    def test_get_error_and_query_preservation(self):
        result, session = self.call_tool("GET", lambda kw: board("게시물") if not kw["params"]["content"]
                                        else response("You have an error in your SQL syntax", 500),
                                        "http://localhost:8080/search?content=old&page=2")
        self.assertEqual(result["vuln"], "VULNERABLE")
        self.assertEqual(result["result"]["status_code"], 500)
        self.assertEqual(result["result"]["checks"][0], {"type": "error", "confirmed": True})
        self.assertEqual(result["result"]["checks"][-1]["type"], "boolean")
        self.assertFalse(result["result"]["checks"][-1]["completed"])
        self.assertEqual(session.request.call_args_list[0].args, ("GET", "http://localhost:8080/search?page=2"))

    def test_post_boolean(self):
        def serve(kwargs):
            self.assertNotIn("params", kwargs)
            payload = kwargs["data"]["content"]
            return board("게시물" if not payload or "1=1" in payload else "검색 결과 없음")
        result, session = self.call_tool("post", serve)
        self.assertEqual(result["method"], "POST")
        self.assertEqual(result["vuln"], "VULNERABLE")
        self.assertTrue(result["result"]["checks"][-1]["confirmed"])
        self.assertTrue(all(call.args[0] == "POST" for call in session.request.call_args_list))

    def test_safe_and_session_failure(self):
        result, _ = self.call_tool("GET", lambda kw: board("동일한 결과"))
        self.assertEqual(result["vuln"], "SAFE")
        result, _ = self.call_tool("GET", lambda kw: response("", 302))
        self.assertEqual(result["vuln"], "N/A")
        self.assertIn("인증", result["result"]["evidence"])

    def test_mapping_preserves_metadata(self):
        old = {"method": "GET", "parameter": "content", "result": "N/A", "payload": None,
               "status_code": None, "evidence": "실패", "details": {"phase": "login"},
               "scan_id": "TEST", "category": "SQL Injection", "severity": "INFO",
               "scanned_at": "time", "remediation": "바인딩"}
        mapped = format_finding(old, "http://localhost/search")
        for key in ("scan_id", "category", "severity", "scanned_at", "remediation"):
            self.assertEqual(mapped[key], old[key])
        self.assertEqual(mapped["result"]["phase"], "login")
        self.assertEqual(mapped["result"]["checks"], [])
        self.assertEqual(old["result"], "N/A")

    def test_invalid_input_never_requests(self):
        with patch("scanner.requests.Session") as session:
            for args in [("relative", "GET", "content", {}),
                         ("http://localhost", "DELETE", "content", {}),
                         ("http://localhost", "GET", ["content"], {}),
                         ("http://localhost", "GET", "content", "session=value")]:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    run(*args)
            session.assert_not_called()

    def test_cli_keeps_login_and_writes_common_format(self):
        with tempfile.TemporaryDirectory() as temp:
            output_path = Path(temp) / "findings.json"
            config_path = Path(__file__).with_name("config.json")
            for login_error, expected in [(None, "SAFE"), (ScanError("로그인 실패"), "N/A")]:
                with patch("sys.argv", ["scanner.py", "--config", str(config_path), "--output", str(output_path)]), \
                        patch("scanner.os.environ.get", return_value="test-password"), \
                        patch.object(Scanner, "login", side_effect=login_error) as login, \
                        patch.object(Scanner, "request", side_effect=lambda *a, **kw: board("동일 결과")), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    exit_code = main()
                login.assert_called_once_with("test-password")
                data = json.loads(output_path.read_text(encoding="utf-8"))
                self.assertEqual(data, json.loads(output.getvalue()))
                self.assertTrue(all(item["vuln"] == expected for item in data))
                self.assertTrue(all(isinstance(item["result"], dict) for item in data))
                self.assertEqual(exit_code, 2 if login_error else 0)


if __name__ == "__main__":
    unittest.main()
