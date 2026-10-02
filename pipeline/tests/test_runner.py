import unittest

from pipeline.runner import aggregate_results, normalize_result


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
        self.assertEqual(result["findings"][0]["path"], "/search")
        self.assertEqual(result["findings"][0]["source_result"], "SAFE")

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


if __name__ == "__main__":
    unittest.main()
