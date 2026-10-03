import json
import sys
import threading
import unittest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from authz_scanner.engine import ScanConfigError, run_scan  # noqa: E402


DOCUMENT = {
    "id": 2001,
    "owner": "bob",
    "title": "재무 문서",
    "content": "테스트 비밀",
}


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        authorization = self.headers.get("Authorization", "")
        if authorization not in {"Bearer alice-token", "Bearer bob-token"}:
            self.respond(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if self.path.startswith("/secure/") and authorization != "Bearer bob-token":
            self.respond(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return
        self.respond(HTTPStatus.OK, DOCUMENT)

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
            "accounts": {
                "alice": {"token": "alice-token"},
                "bob": {"token": "bob-token"},
            },
            "tests": [
                {
                    "name": "vulnerable",
                    "path": "/vulnerable/{document_id}",
                    "variables": {"document_id": 2001},
                    "owner_account": "bob",
                    "attacker_account": "alice",
                    "sensitive_fields": ["id", "owner", "content"],
                },
                {
                    "name": "secure",
                    "path": "/secure/{document_id}",
                    "variables": {"document_id": 2001},
                    "owner_account": "bob",
                    "attacker_account": "alice",
                    "sensitive_fields": ["id", "owner", "content"],
                },
            ],
        }

    def test_detects_vulnerable_and_secure_endpoints(self):
        result = run_scan(self.config())
        self.assertEqual(result["summary"]["vulnerable"], 1)
        self.assertEqual(result["summary"]["pass"], 1)
        self.assertEqual(result["findings"][0]["severity"], "HIGH")
        self.assertEqual(result["findings"][1]["vuln"], "PASS")
        self.assertTrue(
            {"url", "method", "parameters", "vuln", "result"}.issubset(
                result["findings"][0]
            )
        )

    def test_rejects_state_changing_method(self):
        config = self.config()
        config["tests"][0]["method"] = "DELETE"
        with self.assertRaises(ScanConfigError):
            run_scan(config)

    def test_result_does_not_contain_tokens(self):
        result = run_scan(self.config())
        self.assertNotIn("alice-token", json.dumps(result))
        self.assertNotIn("bob-token", json.dumps(result))
        self.assertNotIn("session_cookie", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
