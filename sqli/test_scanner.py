"""외부 사이트에 접속하지 않고 판정과 로그인 흐름을 검증한다."""
import unittest
from unittest.mock import Mock

import requests

from scanner import Scanner, ScanError


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


if __name__ == "__main__":
    unittest.main()
