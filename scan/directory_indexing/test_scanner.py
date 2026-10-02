import unittest
from unittest.mock import Mock, patch

import requests

from scan.directory_indexing.scanner import run


def make_response(body, status_code=200, headers=None):
    response = Mock()
    response.status_code = status_code
    response.text = body
    response.headers = headers or {}
    return response


class DirectoryIndexingTests(unittest.TestCase):

    def test_index_page_is_vulnerable(self):
        session = Mock()
        session.get.return_value = make_response(
            "<html><title>Index of /uploads/</title></html>"
        )

        with patch(
            "scan.directory_indexing.scanner.requests.Session",
            return_value=session
        ):
            result = run(
                "http://localhost/uploads/",
                "GET",
                {},
                {}
            )

        self.assertEqual(result["vuln"], "VULNERABLE")
        self.assertIn("Index of", result["result"])
        session.get.assert_called_once_with(
            "http://localhost/uploads/",
            timeout=5
        )
        session.close.assert_called_once()

    def test_normal_page_is_safe(self):
        session = Mock()
        session.get.return_value = make_response(
            "<html><title>Login</title><body>로그인</body></html>"
        )

        with patch(
            "scan.directory_indexing.scanner.requests.Session",
            return_value=session
        ):
            result = run(
                "http://localhost/login",
                "GET",
                {},
                {}
            )

        self.assertEqual(result["vuln"], "SAFE")
        session.get.assert_called_once_with(
            "http://localhost/login",
            timeout=5
        )

    def test_non_get_method_returns_na(self):
        with patch(
            "scan.directory_indexing.scanner.requests.Session"
        ) as session:
            result = run(
                "http://localhost/uploads/",
                "POST",
                {},
                {}
            )

        self.assertEqual(result["vuln"], "N/A")
        session.assert_not_called()

    def test_http_request_failure_returns_na(self):
        session = Mock()
        session.get.side_effect = requests.RequestException("request failed")

        with patch(
            "scan.directory_indexing.scanner.requests.Session",
            return_value=session
        ):
            result = run(
                "http://localhost/uploads/",
                "GET",
                {},
                {}
            )

        self.assertEqual(result["vuln"], "N/A")


if __name__ == "__main__":
    unittest.main()