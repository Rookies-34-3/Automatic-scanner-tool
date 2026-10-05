import html
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import requests

from module.xss.reflected_xss import ReflectedXSSScanner, _FormUnavailable


class XSSOutputTests(unittest.TestCase):
    def setUp(self):
        self.scanner = ReflectedXSSScanner()
        self.addCleanup(self.scanner.session.close)
        self.target = {"url": "http://example.test/search", "method": "GET",
                       "parameters": {"title": "", "body": "", "url": ""}}

    def test_repeated_http_rejections_are_grouped_with_parameters(self):
        for status, explanation in ((400, "CSRF"), (401, "로그인"), (403, "접근 권한"),
                                    (404, "경로"), (429, "횟수 제한"), (500, "서버 오류")):
            with patch.object(self.scanner, "_send", return_value=SimpleNamespace(status_code=status, text="")):
                result = self.scanner.scan(self.target)
            self.assertEqual(result["vuln"], "REVIEW")
            self.assertEqual(result["result"].count(f"HTTP {status}"), 1)
            self.assertIn(explanation, result["result"])
            self.assertIn("title, body, url", result["result"])
            self.assertEqual(len(result["details"]["raw_result"]), 3)

    def test_payload_rejection_is_also_korean_and_review(self):
        def send(target, parameter, value):
            return SimpleNamespace(status_code=403 if value.startswith("<svg") else 200, text=value)
        with patch.object(self.scanner, "_send", side_effect=send):
            result = self.scanner.scan(self.target)
        self.assertEqual(result["vuln"], "REVIEW")
        self.assertIn("HTTP 403", result["result"])
        self.assertEqual(result["details"]["raw_result"][0]["stage"], "payload")

    def test_vulnerable_result_describes_reflection_and_keeps_raw_evidence(self):
        with patch.object(self.scanner, "_send", side_effect=lambda target, parameter, value: SimpleNamespace(text=f"<html>{value}</html>")):
            result = self.scanner.scan(self.target)
        self.assertIs(result["vuln"], True)
        self.assertIn("HTML 본문에 인코딩 없이", result["result"])
        self.assertIn("<svg onload=alert(1337)>", result["details"]["raw_result"][0]["evidence"])
        self.assertEqual(json.loads(json.dumps(result, ensure_ascii=False))["result"], result["result"])

    def test_encoded_payload_has_korean_reason(self):
        with patch.object(self.scanner, "_send", side_effect=lambda target, parameter, value: SimpleNamespace(text=html.escape(value))):
            result = self.scanner.scan(self.target)
        self.assertIs(result["vuln"], False)
        self.assertIn("인코딩 처리", result["result"])
        self.assertIn("&lt;svg", result["details"]["raw_result"][0]["evidence"])

    def test_missing_reflection_has_korean_reason(self):
        with patch.object(self.scanner, "_send", return_value=SimpleNamespace(text="no reflection")):
            result = self.scanner.scan(self.target)
        self.assertIs(result["vuln"], False)
        self.assertIn("검사 입력값이 응답에 나타나지 않아", result["result"])

    def test_missing_payload_has_korean_reason(self):
        with patch.object(self.scanner, "_send", side_effect=lambda target, parameter, value: SimpleNamespace(text="filtered" if value.startswith("<svg") else value)):
            result = self.scanner.scan(self.target)
        self.assertIs(result["vuln"], False)
        self.assertIn("검사용 XSS 코드는 그대로 출력되지 않았습니다", result["result"])

    def test_network_errors_remain_errors_with_korean_reason(self):
        for error, explanation in ((requests.Timeout("timeout"), "제한 시간"),
                                   (requests.ConnectionError("connection"), "연결하지 못해")):
            with patch.object(self.scanner, "_send", side_effect=error):
                result = self.scanner.scan(self.target)
            self.assertEqual(result["vuln"], "ERROR")
            self.assertIn(explanation, result["result"])
            self.assertEqual(result["details"]["raw_result"][0]["error_detail"], str(error))

    def test_missing_form_has_specific_korean_reason(self):
        with patch.object(self.scanner, "_form_parameters", side_effect=_FormUnavailable()):
            result = self.scanner.scan(dict(self.target, method="POST"))
        self.assertEqual(result["vuln"], "ERROR")
        self.assertIn("POST 폼을 찾지 못해", result["result"])

    def test_no_parameters_is_review(self):
        result = self.scanner.scan(dict(self.target, parameters={}))
        self.assertEqual(result["vuln"], "REVIEW")
        self.assertIn("입력 항목이 없어", result["result"])


if __name__ == "__main__":
    unittest.main()
