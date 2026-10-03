import unittest
from unittest.mock import Mock, patch

import requests

from scan.admin_exposure.scanner import run


def make_response(body="", status_code=200, headers=None):
    response = Mock()
    response.status_code = status_code
    response.text = body
    response.headers = headers or {}
    return response


ADMIN_HTML = """
<html>
<body data-active="admin">
    <h1>관리자 페이지</h1>
    <h1>관리자 대시보드</h1>
    <section class="lab-admin-section">
        사용자 관리
    </section>
</body>
</html>
"""


class AdminExposureTests(unittest.TestCase):

    def test_admin_page_is_vulnerable(self):
        session = Mock()
        session.get.return_value = make_response(ADMIN_HTML)

        with patch(
            "scan.admin_exposure.scanner.requests.Session",
            return_value=session
        ):
            result = run(
                "http://localhost/admin",
                "GET",
                {},
                {}
            )

        self.assertEqual(result["vuln"], "VULNERABLE")
        self.assertIn("관리자 페이지", result["result"])
        self.assertEqual(result["status_code"], 200)

        self.assertEqual(
            result["details"]["indicator_count"],
            4
        )
        self.assertEqual(
            result["details"]["required_indicator_count"],
            2
        )

        self.assertEqual(
            result["details"]["matched_indicators"],
            [
                'data-active="admin"',
                "관리자 페이지",
                "관리자 대시보드",
                "lab-admin-section",
            ]
        )

        session.get.assert_called_once_with(
            "http://localhost/admin",
            timeout=5,
            allow_redirects=False
        )
        session.close.assert_called_once()

    def test_normal_page_is_safe(self):
        session = Mock()
        session.get.return_value = make_response(
            "<html><title>로그인</title><body>로그인</body></html>"
        )

        with patch(
            "scan.admin_exposure.scanner.requests.Session",
            return_value=session
        ):
            result = run(
                "http://localhost/login",
                "GET",
                {},
                {}
            )

        self.assertEqual(result["vuln"], "SAFE")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(
            result["details"]["matched_indicators"],
            []
        )
        self.assertEqual(
            result["details"]["indicator_count"],
            0
        )
        self.assertEqual(
            result["details"]["required_indicator_count"],
            2
        )

        session.get.assert_called_once_with(
            "http://localhost/login",
            timeout=5,
            allow_redirects=False
        )
        session.close.assert_called_once()

    def test_forbidden_page_is_safe(self):
        session = Mock()
        session.get.return_value = make_response(
            "Forbidden",
            status_code=403
        )

        with patch(
            "scan.admin_exposure.scanner.requests.Session",
            return_value=session
        ):
            result = run(
                "http://localhost/admin",
                "GET",
                {},
                {}
            )

        self.assertEqual(result["vuln"], "SAFE")
        self.assertEqual(result["status_code"], 403)
        self.assertTrue(
            result["details"]["access_denied"]
        )

        session.get.assert_called_once_with(
            "http://localhost/admin",
            timeout=5,
            allow_redirects=False
        )
        session.close.assert_called_once()

    def test_login_redirect_is_safe(self):
        session = Mock()
        session.get.return_value = make_response(
            "",
            status_code=302,
            headers={"Location": "/login"}
        )

        with patch(
            "scan.admin_exposure.scanner.requests.Session",
            return_value=session
        ):
            result = run(
                "http://localhost/admin",
                "GET",
                {},
                {}
            )

        self.assertEqual(result["vuln"], "SAFE")
        self.assertEqual(result["status_code"], 302)
        self.assertEqual(
            result["details"]["redirect_location"],
            "/login"
        )
        self.assertIn(
            "리다이렉트",
            result["result"]
        )

    def test_non_get_method_returns_na(self):
        with patch(
            "scan.admin_exposure.scanner.requests.Session"
        ) as session:
            result = run(
                "http://localhost/admin",
                "POST",
                {},
                {}
            )

        self.assertEqual(result["vuln"], "N/A")
        self.assertIsNone(result["status_code"])
        self.assertEqual(
            result["details"]["reason"],
            "unsupported_method"
        )
        session.assert_not_called()

    def test_http_request_failure_returns_na(self):
        session = Mock()
        session.get.side_effect = requests.RequestException(
            "request failed"
        )

        with patch(
            "scan.admin_exposure.scanner.requests.Session",
            return_value=session
        ):
            result = run(
                "http://localhost/admin",
                "GET",
                {},
                {}
            )

        self.assertEqual(result["vuln"], "N/A")
        self.assertIsNone(result["status_code"])
        self.assertEqual(
            result["details"]["reason"],
            "request_failed"
        )
        self.assertEqual(
            result["details"]["error_type"],
            "RequestException"
        )
        session.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()