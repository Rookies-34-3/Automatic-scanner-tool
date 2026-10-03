import json
import sys
import threading
import unittest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from authn_scanner.engine import ScanConfigError, jwt_test_cases, run_scan  # noqa: E402


PROFILE = {"username": "alice", "email": "alice@example.test", "team": "dev"}


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        valid = self.headers.get("Authorization") == "Bearer valid-token"
        if self.path == "/secure" and not valid:
            self.respond(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        self.respond(HTTPStatus.OK, PROFILE)

    def respond(self, status, data):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
        host, port = cls.server.server_address
        cls.base_url = f"http://{host}:{port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def config(self):
        return {
            "base_url": self.base_url,
            "valid_credential": {"token": "valid-token"},
            "tests": [
                {"name": "vulnerable", "path": "/vulnerable", "sensitive_fields": ["username", "email"]},
                {"name": "secure", "path": "/secure", "sensitive_fields": ["username", "email"]},
            ],
        }

    def test_detects_vulnerable_and_secure_authentication(self):
        result = run_scan(self.config())
        self.assertEqual(result["summary"]["vulnerable"], 1)
        self.assertEqual(result["summary"]["pass"], 1)
        self.assertEqual(result["findings"][0]["severity"], "HIGH")
        self.assertEqual(result["findings"][0]["vuln"], "VULNERABLE")
        self.assertTrue(
            {"url", "method", "parameters", "vuln", "result"}.issubset(
                result["findings"][0]
            )
        )

    def test_rejects_state_changing_method(self):
        config = self.config()
        config["tests"][0]["method"] = "POST"
        with self.assertRaises(ScanConfigError):
            run_scan(config)

    def test_result_does_not_contain_valid_token(self):
        result = run_scan(self.config())
        self.assertNotIn("valid-token", json.dumps(result))
        self.assertNotIn("session_cookie", json.dumps(result))

    def test_jwt_cases_are_added_only_for_jwt_shape(self):
        self.assertEqual(jwt_test_cases("opaque-token"), [])
        self.assertEqual(len(jwt_test_cases("header.payload.signature")), 2)


if __name__ == "__main__":
    unittest.main()
