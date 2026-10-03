import json
import tempfile
import unittest
from pathlib import Path

from app import ROOT, app, load_findings, summarize


class DashboardTests(unittest.TestCase):
    def test_sample_render_and_escape(self):
        rows, warnings = load_findings([ROOT / "samples/findings.json"])
        self.assertEqual(warnings, [])
        self.assertEqual(summarize(rows)["results"], {"VULNERABLE": 4, "SAFE": 2, "N/A": 1})
        page = app.test_client().get("/?sample=1")
        self.assertEqual(page.status_code, 200)
        self.assertIn("&lt;script&gt;", page.get_data(as_text=True))
        self.assertNotIn("<script>alert", page.get_data(as_text=True))

    def test_new_format(self):
        old = json.loads((ROOT / "samples/findings.json").read_text(encoding="utf-8"))[0]
        new = dict(old, url=old["target_url"], parameters=[old["parameter"]], vuln=old["result"],
                   result={key: old[key] for key in ("payload", "evidence", "status_code")})
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "findings.json"
            path.write_text(json.dumps([new]), encoding="utf-8")
            rows, warnings = load_findings([path])
            self.assertEqual(warnings, [])
            for key in ("result", "parameter", "target_url", "evidence"):
                self.assertEqual(rows[0][key], old[key])

    def test_missing_and_invalid(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "findings.json"
            self.assertTrue(load_findings([path])[1])
            path.write_text("{}", encoding="utf-8")
            self.assertTrue(load_findings([path])[1])
            path.write_text('[{"result": []}]', encoding="utf-8")
            self.assertTrue(load_findings([path])[1])


if __name__ == "__main__":
    unittest.main()
