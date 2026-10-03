import unittest
from types import SimpleNamespace
from unittest.mock import patch

from module.sqli.scanner import Scanner


class SqliCsrfTest(unittest.TestCase):
    def test_post_reads_form_and_sends_current_csrf_token(self):
        scanner = Scanner({"base_url": "https://lab.example", "delay": 0})
        calls = []

        def request(method, path, **kwargs):
            calls.append((method, path, kwargs))
            if method == "GET":
                return SimpleNamespace(
                    status_code=200,
                    text=('''<form method="post"><input type="hidden" name="csrf_token" '''
                          '''value="fresh-token"><input name="title"></form>'''),
                )
            return SimpleNamespace(status_code=400, text="잘못된 요청")

        with patch.object(scanner, "request", side_effect=request):
            scanner.scan({
                "path": "https://lab.example/write",
                "method": "POST",
                "parameter": "title",
            }, "SCAN-test")

        self.assertEqual([call[0] for call in calls], ["GET", "POST"])
        self.assertEqual(calls[1][2]["data"], {"csrf_token": "fresh-token", "title": ""})

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
