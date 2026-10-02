import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline.runner import (
    PipelineConfigError,
    adapt_endpoints,
    aggregate_results,
    load_pipeline_config,
    normalize_result,
    prepare_runtime_config,
)


class NormalizeTests(unittest.TestCase):
    def test_sqli_list_is_normalized(self):
        raw = [
            {
                "category": "SQL Injection",
                "target_url": "/search",
                "result": "SAFE",
                "evidence": "증거 미탐지",
            },
            {
                "category": "SQL Injection",
                "target_url": "/qna",
                "result": "N/A",
                "evidence": "판정 불가",
            },
        ]
        result = normalize_result("sqli", raw, "http://localhost")
        self.assertEqual(result["summary"]["pass"], 1)
        self.assertEqual(result["summary"]["review"], 1)
        self.assertEqual(result["findings"][0]["url"], "http://localhost/search")
        self.assertEqual(result["findings"][0]["details"]["source_result"], "SAFE")
        self.assertEqual(
            set(result["findings"][0]),
            {"scanner_id", "name", "url", "method", "parameters", "result", "severity", "reason", "details"},
        )

    def test_existing_envelope_is_normalized(self):
        raw = {
            "tool": "AuthNScanner",
            "version": "2.0.0",
            "findings": [{"name": "admin", "result": "VULNERABLE"}],
        }
        result = normalize_result("authn", raw, "http://localhost")
        self.assertEqual(result["tool"], "AuthNScanner")
        self.assertEqual(result["summary"]["vulnerable"], 1)

    def test_aggregate_prioritizes_vulnerability(self):
        passed = normalize_result(
            "authn", {"findings": [{"name": "a", "result": "PASS"}]}, "http://localhost"
        )
        vulnerable = normalize_result(
            "sqli", [{"name": "b", "result": "VULNERABLE"}], "http://localhost"
        )
        aggregate = aggregate_results("SCAN-TEST", "http://localhost", [passed, vulnerable])
        self.assertEqual(aggregate["result"], "VULNERABLE")
        self.assertEqual(aggregate["summary"]["total"], 2)

    def test_common_sqli_input_is_adapted(self):
        endpoints = [{
            "url": "http://localhost/search",
            "method": "GET",
            "parameters": [{"name": "keyword", "location": "query"}],
        }]
        adapted = adapt_endpoints("sqli", endpoints, "http://localhost", [])
        self.assertEqual(adapted, [{"path": "/search", "parameter": "keyword"}])

    def test_authz_options_remain_in_native_config(self):
        existing = [{
            "name": "profile",
            "method": "GET",
            "path": "/api/profiles/{user_id}",
            "owner_account": "owner",
            "attacker_account": "other_user",
            "sensitive_fields": ["email"],
        }]
        common = [{
            "url": "http://localhost/api/profiles/{user_id}",
            "method": "GET",
            "parameters": [{"name": "user_id", "location": "path"}],
        }]
        adapted = adapt_endpoints("authz", common, "http://localhost", existing)
        self.assertEqual(adapted[0]["sensitive_fields"], ["email"])
        self.assertEqual(adapted[0]["owner_account"], "owner")

    def test_common_input_rejects_extra_fields(self):
        endpoint = {
            "url": "http://localhost/admin",
            "method": "GET",
            "parameters": [],
            "required_markers": ["admin"],
        }
        with self.assertRaises(PipelineConfigError):
            adapt_endpoints("authn", [endpoint], "http://localhost", [])

    def test_common_input_rejects_other_origin(self):
        endpoint = {"url": "http://other.invalid/admin", "method": "GET", "parameters": []}
        with self.assertRaises(PipelineConfigError):
            adapt_endpoints("authn", [endpoint], "http://localhost", [])

    def test_example_configs_use_common_input_schema(self):
        repo_root = Path(__file__).resolve().parents[2]
        for schema_name in ("endpoint-input.schema.json", "finding-output.schema.json"):
            self.assertIsInstance(
                json.loads((repo_root / "pipeline" / schema_name).read_text(encoding="utf-8")),
                dict,
            )
        for name in ("config.example.json", "config.aws.json"):
            config = load_pipeline_config(repo_root / "pipeline" / name)
            for scanner in config["scanners"]:
                for endpoint in scanner["endpoints"]:
                    self.assertEqual(set(endpoint), {"url", "method", "parameters"})

    def test_runtime_config_preserves_authn_private_options(self):
        repo_root = Path(__file__).resolve().parents[2]
        entry = {
            "id": "authn",
            "config": "authn-scanner/examples/config.example.json",
            "endpoints": [{
                "url": "http://127.0.0.1:8080/admin",
                "method": "GET",
                "parameters": [],
            }],
        }
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SSLC_LAB_PASSWORD": "test-only"}
        ):
            _, runtime = prepare_runtime_config(
                repo_root, Path(directory), "http://127.0.0.1:8080", entry
            )
        self.assertEqual(runtime["tests"][0]["path"], "/admin")
        self.assertIn("관리자 대시보드", runtime["tests"][0]["required_markers"])


if __name__ == "__main__":
    unittest.main()
