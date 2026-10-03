import json
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from openai import OpenAIError
from openai.types.responses import ResponseFunctionToolCall
import openai_module
import report_writer


URL = "http://127.0.0.1:8080/search"
PARAMETERS = [{"name": "content", "location": "query"}]
PAYLOAD = {"candidate_status": "unverified", "groups": [{
    "method": "GET", "path_template": "/search", "candidate_tools": ["sqli", "xss"],
    "discovered_count": 1, "request_variants": [{"sample_url": URL, "parameters": PARAMETERS}],
}]}


def selection(url=URL, method="GET", parameters=None, vulnerability_type="sqli"):
    call = ResponseFunctionToolCall(
        type="function_call", name="analyze_endpoint_stub", id="fc_test",
        call_id=f"call_{vulnerability_type}",
        arguments=json.dumps({"url": url, "method": method, "vulnerability_type": vulnerability_type,
                              "parameters": PARAMETERS if parameters is None else parameters}),
    )
    return SimpleNamespace(status="completed", output=[call])


class OpenAIAnalysisTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.output_dir = Path(temporary.name) / "output"
        writer_patch = patch.object(report_writer, "__file__", str(Path(temporary.name) / "report_writer.py"))
        writer_patch.start()
        self.addCleanup(writer_patch.stop)

    def saved_report(self):
        paths = list(self.output_dir.glob("analysis-results-*.json"))
        self.assertEqual(len(paths), 1)
        return json.loads(paths[0].read_text(encoding="utf-8"))

    def client(self, first=None):
        client = MagicMock()
        client.with_options.return_value = client
        client.__enter__.return_value = client
        selection_count = 0

        def create(**kwargs):
            nonlocal selection_count
            if kwargs["tool_choice"] == "none":
                return SimpleNamespace(status="completed", output_text="임시 호출 완료. 미검증입니다.")
            selection_count += 1
            if first is not None and selection_count == 1:
                return first
            return selection(**json.loads(kwargs["input"][0]["content"]))

        client.responses.create.side_effect = create
        return client

    def test_each_candidate_returns_its_result_to_ai_with_matching_call_id(self):
        client = self.client()
        progress = []
        with patch.object(openai_module, "get_openai_client", return_value=client):
            report = openai_module.analyze_sinks(PAYLOAD, progress.append)
        self.assertEqual(client.responses.create.call_count, 4)
        self.assertEqual(len(progress), 2)
        self.assertIn("SQL Injection", progress[0])
        self.assertIn("XSS", progress[1])
        self.assertEqual(report["task_count"], 2)
        self.assertEqual(report["completed_count"], 2)
        self.assertEqual(self.saved_report(), report)
        self.assertEqual([item["vulnerability_type"] for item in report["results"]], ["sqli", "xss"])
        for index, item in enumerate(report["results"]):
            self.assertFalse(item["result"]["verified"])
            self.assertEqual(item["verdict"], "inconclusive")
            continuation = client.responses.create.call_args_list[index * 2 + 1].kwargs
            self.assertEqual(continuation["tool_choice"], "none")
            self.assertFalse(continuation["store"])
            self.assertEqual(continuation["input"][-2]["type"], "function_call")
            self.assertEqual(continuation["input"][-1]["call_id"], f"call_{item['vulnerability_type']}")
            returned = json.loads(continuation["input"][-1]["output"])
            self.assertEqual(returned, {k: v for k, v in item["result"].items() if k != "ai_summary"})

    def test_changed_request_is_recorded_as_error_and_next_candidate_runs(self):
        for first in (selection(url=URL + "/unknown"), selection(parameters=[{"name": "other", "location": "query"}]),
                      selection(vulnerability_type="xss")):
            with self.subTest(arguments=first.output[0].arguments):
                client = self.client(first)
                with patch.object(openai_module, "get_openai_client", return_value=client), \
                        patch.object(openai_module, "analyze_endpoint_stub", wraps=openai_module.analyze_endpoint_stub) as tool:
                    report = openai_module.analyze_sinks(PAYLOAD)
                self.assertEqual(tool.call_count, 1)
                self.assertEqual(tool.call_args.kwargs["vulnerability_type"], "xss")
                self.assertEqual(report["results"][0]["verdict"], "error")
                self.assertIn("수집 결과와 일치하지", report["results"][0]["result"]["error"])
                self.assertEqual(report["results"][1]["verdict"], "inconclusive")
                self.assertEqual(report["status"], "completed_with_errors")
                self.assertEqual(client.responses.create.call_count, 3)
                path = self.output_dir / report["result_file"]
                self.assertEqual(json.loads(path.read_text(encoding="utf-8")), report)

    def test_incomplete_summary_keeps_stub_result_and_records_error(self):
        client = self.client()
        client.responses.create.side_effect = [
            selection(), SimpleNamespace(status="incomplete", output_text=""),
            selection(vulnerability_type="xss"),
            SimpleNamespace(status="completed", output_text="다음 후보도 미검증입니다."),
        ]
        with patch.object(openai_module, "get_openai_client", return_value=client):
            report = openai_module.analyze_sinks(PAYLOAD)
        self.assertEqual(report["results"][0]["verdict"], "error")
        self.assertEqual(report["results"][0]["result"]["status"], "stub")
        self.assertIn("AI 요약이 완료되지", report["results"][0]["result"]["error"])
        self.assertEqual(report["results"][1]["verdict"], "inconclusive")
        self.assertEqual(self.saved_report(), report)

    def test_variant_tools_skips_errors_and_incremental_file_updates(self):
        payload = deepcopy(PAYLOAD)
        payload["groups"][0]["request_variants"].extend([
            {"sample_url": URL + "/preview", "parameters": [], "candidate_tools": ["ssrf"]},
            {"sample_url": URL + "/plain", "parameters": [], "candidate_tools": []},
        ])
        client = self.client()
        create = client.responses.create.side_effect

        def fail_xss(**kwargs):
            if kwargs["tool_choice"] != "none" and json.loads(kwargs["input"][0]["content"])["vulnerability_type"] == "xss":
                raise OpenAIError("private-test-key")
            return create(**kwargs)

        client.responses.create.side_effect = fail_xss
        snapshots = []

        def progress(message):
            snapshots.append(self.saved_report())

        with patch.object(openai_module, "get_openai_client", return_value=client):
            report = openai_module.analyze_sinks(payload, progress, source_json="original-sinks.json")
        self.assertEqual([s["completed_count"] for s in snapshots], [0, 1, 2, 3])
        self.assertEqual([item["verdict"] for item in snapshots[0]["results"]], ["pending"] * 4)
        self.assertEqual([item["verdict"] for item in report["results"]], ["inconclusive", "error", "inconclusive", "skipped"])
        self.assertEqual([item["vulnerability_type"] for item in report["results"]], ["sqli", "xss", "ssrf", None])
        self.assertEqual(report["source_json"], "original-sinks.json")
        self.assertEqual(report["completed_count"], 4)
        self.assertEqual(client.responses.create.call_count, 5)
        self.assertNotIn("private-test-key", json.dumps(report))
        self.assertEqual(self.saved_report(), report)

    def test_interruption_leaves_completed_result_and_pending_items_on_disk(self):
        client = self.client()
        client.responses.create.side_effect = [
            selection(), SimpleNamespace(status="completed", output_text="미검증입니다."), KeyboardInterrupt(),
        ]
        with patch.object(openai_module, "get_openai_client", return_value=client):
            with self.assertRaises(KeyboardInterrupt):
                openai_module.analyze_sinks(PAYLOAD)
        saved = self.saved_report()
        self.assertEqual(saved["completed_count"], 1)
        self.assertEqual(saved["status"], "running")
        self.assertEqual([item["verdict"] for item in saved["results"]], ["inconclusive", "pending"])

    def test_requests_without_candidates_are_saved_without_an_api_client(self):
        payload = deepcopy(PAYLOAD)
        payload["groups"][0]["candidate_tools"] = []
        with patch.object(openai_module, "get_openai_client") as get_client:
            report = openai_module.analyze_sinks(payload)
        get_client.assert_not_called()
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["results"][0]["verdict"], "skipped")
        self.assertEqual(self.saved_report(), report)
