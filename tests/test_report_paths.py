import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import app as dashboard
import report_writer


class ReportPathsTest(unittest.TestCase):
    def test_repeated_scan_updates_fixed_file_with_redacted_latest_result(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(report_writer, "__file__", str(root / "report_writer.py")):
                first = report_writer.save_scan_report({"target": "first"}, "https://first.example")
                second = report_writer.save_scan_report(
                    {"target": "second", "cookie": "private-value"}, "https://second.example",
                )
            self.assertEqual(first, second)
            self.assertEqual(second, root / "output" / "scan-results.json")
            self.assertEqual(json.loads(second.read_text()), {"target": "second", "cookie": "[REDACTED]"})

    def test_default_and_absolute_paths_load_same_saved_report(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(report_writer, "__file__", str(root / "report_writer.py")):
                path = report_writer.save_scan_report({"target": "latest"}, "https://example.com")
            with patch.object(dashboard, "APP_DIR", root):
                self.assertEqual(dashboard.resolve_input_path(dashboard.SCANNER_RESULT_FILENAME), path)
                self.assertEqual(dashboard.load_configured_json(dashboard.SCANNER_RESULT_FILENAME), {"target": "latest"})
                self.assertEqual(dashboard.load_configured_json(str(path)), {"target": "latest"})

    def test_serialization_error_preserves_previous_report(self):
        with TemporaryDirectory() as directory:
            with patch.object(report_writer, "__file__", str(Path(directory) / "report_writer.py")):
                path = report_writer.save_scan_report({"target": "previous"}, "https://example.com")
                with self.assertRaises(TypeError):
                    report_writer.save_scan_report({"invalid": object()}, "https://example.com")
            self.assertEqual(json.loads(path.read_text()), {"target": "previous"})


if __name__ == "__main__":
    unittest.main()
