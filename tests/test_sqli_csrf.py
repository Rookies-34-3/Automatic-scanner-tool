import unittest
from types import SimpleNamespace
from unittest.mock import patch

from module.sqli.scanner import Scanner


class SqliCsrfTest(unittest.TestCase):
    def test_post_keeps_companion_fields_and_replaces_only_target(self):
        scanner = Scanner({"base_url": "https://lab.example", "delay": 0})
        calls = []
        post_count = 0

        def request(method, path, **kwargs):
            nonlocal post_count
            calls.append((method, path, kwargs))
            if method == "GET":
                return SimpleNamespace(
                    status_code=200,
                    text=('''<form method="post">'''
                          '''<input type="hidden" name="csrf_token" value="fresh-token">'''
                          '''<select name="category" required><option value="">선택</option>'''
                          '''<option value="기타">기타</option></select>'''
                          '''<input name="title" required><textarea name="body" required></textarea>'''
                          '''<button name="action" value="preview">미리보기</button></form>'''),
                )
            post_count += 1
            return SimpleNamespace(
                status_code=200 if post_count == 1 else 400,
                text="<tbody><tr><td>정상 결과</td></tr></tbody>" if post_count == 1 else "잘못된 요청",
            )

        with patch.object(scanner, "request", side_effect=request):
            scanner.scan({
                "path": "https://lab.example/write",
                "method": "POST",
                "parameter": "title",
            }, "SCAN-test")

        self.assertEqual([call[0] for call in calls], ["GET", "POST"] * 5)
        self.assertEqual(calls[1][2]["data"], {
            "csrf_token": "fresh-token", "category": "기타", "title": "ROOKIESCAN",
            "body": "ROOKIESCAN", "action": "preview",
        })
        self.assertEqual(calls[3][2]["data"], {
            "csrf_token": "fresh-token", "category": "기타", "title": "'",
            "body": "ROOKIESCAN", "action": "preview",
        })
        self.assertEqual(
            [calls[index][2]["data"]["title"] for index in (1, 3, 5, 7, 9)],
            ["ROOKIESCAN", "'", "'", '"', '"'],
        )

    def test_csrf_control_is_not_scanned(self):
        scanner = Scanner({"base_url": "https://lab.example", "delay": 0})
        with patch.object(scanner, "request") as request:
            result = scanner.scan({
                "path": "https://lab.example/write",
                "method": "POST",
                "parameter": "csrf_token",
            }, "SCAN-test")

        request.assert_not_called()
        self.assertIn("검사에서 제외", result["evidence"])


if __name__ == "__main__":
    unittest.main()
