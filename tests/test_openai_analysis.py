import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from openai.types.responses import ResponseFunctionToolCall
import openai_module


URL = "http://127.0.0.1:8080/search"
PARAMETERS = [{"name": "content", "location": "query"}]
PAYLOAD = {"candidate_status": "unverified", "groups": [{
    "method": "GET", "path_template": "/search", "candidate_tools": ["sqli", "xss"],
    "discovered_count": 1, "request_variants": [{"sample_url": URL, "parameters": PARAMETERS}],
}]}


def selection(url=URL, parameters=None):
    call = ResponseFunctionToolCall(
        type="function_call", name="analyze_endpoint_stub", call_id="call_test", id="fc_test",
        arguments=json.dumps({"url": url, "method": "GET", "parameters": PARAMETERS if parameters is None else parameters}),
    )
    return SimpleNamespace(status="completed", output=[call])


class OpenAIAnalysisTest(unittest.TestCase):
    def client(self, first):
        client = MagicMock()
        client.with_options.return_value = client
        client.__enter__.return_value = client
        client.responses.create.side_effect = [first, SimpleNamespace(
            status="completed", model="gpt-6.1-sol", output_text="임시 호출 완료. 미검증입니다.",
        )]
        return client

    def test_tool_result_returns_to_ai_with_matching_call_id(self):
        client = self.client(selection())
        progress = []
        with patch.object(openai_module, "get_openai_client", return_value=client):
            report = openai_module.analyze_sinks(PAYLOAD, progress.append)
        self.assertEqual(client.responses.create.call_count, 2)
        self.assertEqual(len(progress), 4)
        self.assertEqual(report["group_count"], 1)
        self.assertFalse(report["tool_results"][0]["verified"])
        self.assertEqual(report["tool_results"][0]["status"], "stub")
        continuation = client.responses.create.call_args.kwargs
        self.assertEqual(continuation["tool_choice"], "none")
        self.assertFalse(continuation["store"])
        self.assertEqual(continuation["input"][-2]["type"], "function_call")
        self.assertEqual(continuation["input"][-1]["call_id"], "call_test")
        self.assertEqual(json.loads(continuation["input"][-1]["output"]), report["tool_results"][0])

    def test_uncollected_url_or_parameter_is_rejected_before_tool_execution(self):
        for first in (selection(url=URL + "/unknown"), selection(parameters=[{"name": "other", "location": "query"}])):
            with self.subTest(arguments=first.output[0].arguments):
                client = self.client(first)
                with patch.object(openai_module, "get_openai_client", return_value=client), \
                        patch.object(openai_module, "analyze_endpoint_stub") as tool:
                    with self.assertRaisesRegex(ValueError, "수집 결과와 일치하지"):
                        openai_module.analyze_sinks(PAYLOAD)
                    tool.assert_not_called()
                self.assertEqual(client.responses.create.call_count, 1)

    def test_incomplete_summary_is_not_returned_as_a_finished_report(self):
        client = self.client(selection())
        client.responses.create.side_effect = [selection(), SimpleNamespace(status="incomplete", output_text="")]
        with patch.object(openai_module, "get_openai_client", return_value=client):
            with self.assertRaisesRegex(ValueError, "AI 요약이 완료되지"):
                openai_module.analyze_sinks(PAYLOAD)
