import html
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import requests

from module.xss.reflected_xss import ReflectedXSSScanner, _FormUnavailable


def page(url, text, status=200):
    response = requests.Response()
    response.url = url
    response.status_code = status
    response._content = text.encode()
    response.encoding = "utf-8"
    return response


class XSSOutputTests(unittest.TestCase):
    def setUp(self):
        self.scanner = ReflectedXSSScanner()
        self.addCleanup(self.scanner.session.close)
        self.target = {"url": "http://example.test/search", "method": "GET",
                       "parameters": {"title": "", "body": "", "url": ""}}
        get_patch = patch.object(self.scanner.session, "get", return_value=page(self.target["url"], ""))
        get_patch.start()
        self.addCleanup(get_patch.stop)

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


class XSSFormTests(unittest.TestCase):
    def setUp(self):
        self.scanner = ReflectedXSSScanner()
        self.addCleanup(self.scanner.session.close)

    def test_post_fills_companion_fields_and_refreshes_csrf(self):
        url = "http://example.test/customer/contact/write"
        target = {"url": url, "method": "POST", "parameters": dict.fromkeys(
            ("csrf_token", "category", "title", "body", "file", "is_secret"), "")}
        form = '''<form method="post" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="{token}">
        <select name="category" required><option value="" selected>선택해주세요</option>
        <option disabled>선택 불가</option><option>기타</option></select>
        <input name="title" required maxlength="200"><textarea name="body" required></textarea>
        <input type="file" name="file"><input type="checkbox" name="is_secret" value="1">
        </form>'''
        count = 0

        def get(*args, **kwargs):
            nonlocal count
            count += 1
            return page(url, form.format(token=f"token-{count}"))

        def post(*args, **kwargs):
            data = kwargs["data"]
            self.assertEqual(data["csrf_token"], f"token-{count}")
            self.assertEqual(data["category"], "기타")
            self.assertTrue(data["title"])
            self.assertTrue(data["body"])
            self.assertNotIn("file", data)
            self.assertNotIn("is_secret", data)
            # 필수값 검증을 통과한 뒤 검사값을 인코딩해 출력하는 웹을 재현한다.
            return page(url, html.escape(data["title"] + data["body"]))

        with patch.object(self.scanner.session, "get", side_effect=get), \
                patch.object(self.scanner.session, "post", side_effect=post) as send:
            result = self.scanner.scan(target)
        self.assertIs(result["vuln"], False)
        self.assertEqual([item["parameter"] for item in result["details"]["raw_result"]], ["title", "body"])
        self.assertEqual(send.call_count, 4)
        self.assertEqual(count, 5)
        self.assertEqual(target["parameters"]["title"], "")

    def test_get_category_buttons_are_preserved_and_not_probed(self):
        url = "http://example.test/customer/contact"
        target = {"url": url, "method": "GET", "parameters": {"category": "", "content": ""}}
        form = '<form method="get"><button name="category" value="">전체</button><button name="category" value="기타">기타</button><input name="content"></form>'

        def get(*args, **kwargs):
            if "params" not in kwargs:
                return page(url, form)
            self.assertEqual(kwargs["params"]["category"], "")
            return page(url, html.escape(kwargs["params"]["content"]))

        with patch.object(self.scanner.session, "get", side_effect=get):
            result = self.scanner.scan(target)
        self.assertIs(result["vuln"], False)
        self.assertEqual(result["details"]["skipped_parameters"], ["category"])
        self.assertEqual([item["parameter"] for item in result["details"]["raw_result"]], ["content"])

    def test_preserves_supplied_companion_values_and_valid_selection(self):
        url = "http://example.test/write"
        target = {"url": url, "method": "POST", "parameters": {"title": "existing", "body": "keep", "category": "B"}}
        form = '<form method="post"><input name="title" required><textarea name="body" required></textarea><select name="category" required><option>A</option><option>B</option></select></form>'
        with patch.object(self.scanner.session, "get", return_value=page(url, form)), \
                patch.object(self.scanner.session, "post", return_value=page(url, "")) as send:
            self.scanner._send(target, "title", "probe")
        self.assertEqual(send.call_args.kwargs["data"], {"title": "probe", "body": "keep", "category": "B"})

    def test_rejection_includes_server_validation_message(self):
        target = {"url": "http://example.test/search", "method": "GET", "parameters": {"content": ""}}
        error = page(target["url"], '<div class="lab-error"><h1>400</h1><p>분류, 제목과 내용을 확인해주세요.</p></div>', 400)
        with patch.object(self.scanner.session, "get", return_value=page(target["url"], "")), \
                patch.object(self.scanner, "_send", return_value=error):
            result = self.scanner.scan(target)
        self.assertEqual(result["vuln"], "REVIEW")
        self.assertIn("서버 설명: 분류, 제목과 내용을 확인해주세요.", result["result"])
        self.assertEqual(result["details"]["raw_result"][0]["server_message"], "분류, 제목과 내용을 확인해주세요.")
        self.assertNotIn("CSRF", result["result"])

    def test_required_text_values_respect_length_and_input_type(self):
        url = "http://example.test/write"
        form = '<form method="post"><input name="title" required minlength="20" maxlength="25"><input name="email" type="email" required><input name="age" type="number" min="18" required></form>'
        with patch.object(self.scanner.session, "get", return_value=page(url, form)):
            values, _ = self.scanner._form_parameters({"url": url, "method": "POST", "parameters": {}})
        self.assertTrue(20 <= len(values["title"]) <= 25)
        self.assertEqual(values["email"], "rookiescan@example.test")
        self.assertEqual(values["age"], "18")


if __name__ == "__main__":
    unittest.main()
