import unittest
from unittest.mock import patch

from scan.portscan.scanner import run


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class PortScanTests(unittest.TestCase):

    def test_allowed_open_port_is_safe(self):
        with patch(
            "scan.portscan.scanner.socket.create_connection",
            return_value=FakeSocket()
        ) as connect:
            result = run(
                "http://localhost:8080",
                "SCAN",
                {
                    "ports": [8080],
                    "allowed_ports": [8080]
                },
                {}
            )

        self.assertEqual(result["vuln"], "SAFE")
        self.assertEqual(result["status_code"], None)
        self.assertEqual(
            result["result"],
            "접근 가능한 포트: [8080]. "
            "허용되지 않은 포트가 확인되었습니다: []"
        )

        self.assertEqual(
            result["details"]["host"],
            "localhost"
        )
        self.assertEqual(
            result["details"]["scanned_ports"],
            [8080]
        )
        self.assertEqual(
            result["details"]["open_ports"],
            [8080]
        )
        self.assertEqual(
            result["details"]["allowed_ports"],
            [8080]
        )
        self.assertEqual(
            result["details"]["unexpected_ports"],
            []
        )
        self.assertEqual(
            result["details"]["timeout"],
            1.0
        )

        connect.assert_called_once_with(
            ("localhost", 8080),
            timeout=1.0
        )

    def test_unexpected_open_port_is_vulnerable(self):
        with patch(
            "scan.portscan.scanner.socket.create_connection",
            return_value=FakeSocket()
        ) as connect:
            result = run(
                "http://localhost:8080",
                "SCAN",
                {
                    "ports": [8080],
                    "allowed_ports": [80]
                },
                {}
            )

        self.assertEqual(result["vuln"], "VULNERABLE")
        self.assertEqual(result["status_code"], None)

        self.assertEqual(
            result["details"]["scanned_ports"],
            [8080]
        )
        self.assertEqual(
            result["details"]["open_ports"],
            [8080]
        )
        self.assertEqual(
            result["details"]["allowed_ports"],
            [80]
        )
        self.assertEqual(
            result["details"]["unexpected_ports"],
            [8080]
        )

        self.assertIn("8080", result["result"])

        connect.assert_called_once_with(
            ("localhost", 8080),
            timeout=1.0
        )

    def test_closed_port_is_safe(self):
        with patch(
            "scan.portscan.scanner.socket.create_connection",
            side_effect=ConnectionRefusedError()
        ) as connect:
            result = run(
                "http://localhost:8080",
                "SCAN",
                {
                    "ports": [8080],
                    "allowed_ports": [80]
                },
                {}
            )

        self.assertEqual(result["vuln"], "SAFE")
        self.assertEqual(result["status_code"], None)

        self.assertEqual(
            result["details"]["scanned_ports"],
            [8080]
        )
        self.assertEqual(
            result["details"]["open_ports"],
            []
        )
        self.assertEqual(
            result["details"]["allowed_ports"],
            [80]
        )
        self.assertEqual(
            result["details"]["unexpected_ports"],
            []
        )

        self.assertEqual(
            result["result"],
            "접근 가능한 포트: []. "
            "허용되지 않은 포트가 확인되었습니다: []"
        )

        connect.assert_called_once_with(
            ("localhost", 8080),
            timeout=1.0
        )

    def test_invalid_port_returns_na(self):
        with patch(
            "scan.portscan.scanner.socket.create_connection"
        ) as connect:
            result = run(
                "http://localhost",
                "SCAN",
                {
                    "ports": [99999],
                    "allowed_ports": [80]
                },
                {}
            )

        self.assertEqual(result["vuln"], "N/A")
        self.assertEqual(result["status_code"], None)
        self.assertEqual(
            result["details"]["reason"],
            "invalid_ports"
        )
        self.assertEqual(
            result["details"]["ports"],
            [99999]
        )

        connect.assert_not_called()

    def test_invalid_parameters_returns_na(self):
        with patch(
            "scan.portscan.scanner.socket.create_connection"
        ) as connect:
            result = run(
                "http://localhost",
                "SCAN",
                ["80"],
                {}
            )

        self.assertEqual(result["vuln"], "N/A")
        self.assertEqual(result["status_code"], None)
        self.assertIn(
            "parameters는 객체(dict) 형태여야 합니다",
            result["result"]
        )
        self.assertEqual(
            result["details"]["reason"],
            "invalid_parameters"
        )

        connect.assert_not_called()

    def test_url_without_scheme_is_supported(self):
        with patch(
            "scan.portscan.scanner.socket.create_connection",
            return_value=FakeSocket()
        ) as connect:
            result = run(
                "localhost:8080",
                "SCAN",
                {
                    "ports": [8080],
                    "allowed_ports": [8080]
                },
                {}
            )

        self.assertEqual(result["vuln"], "SAFE")
        self.assertEqual(result["status_code"], None)
        self.assertEqual(
            result["details"]["host"],
            "localhost"
        )
        self.assertEqual(
            result["details"]["open_ports"],
            [8080]
        )

        connect.assert_called_once_with(
            ("localhost", 8080),
            timeout=1.0
        )


if __name__ == "__main__":
    unittest.main()