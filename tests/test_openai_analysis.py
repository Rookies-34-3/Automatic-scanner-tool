import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from openai.types.responses import ResponseFunctionToolCall

import openai_module


URL = "http://127.0.0.1:8080/search"
PARAMETERS = [{"name": "content", "location": "query"}]
PAYLOAD = {"candidate_status": "unverified", "groups": [{
    "method": "GET",
    "path_template": "/search",
    "candidate_tools": ["sqli", "xss"],
    "discovered_count": 1,
    "request_variants": [{"sample_url": URL, "parameters": PARAMETERS}],
}]}
FINDING = {
    "scanner_id": "sqli",
    "name": "SQL Injection",
    "url": URL,
    "method": "GET",
    "parameters": PARAMETERS,
    "vuln": "PASS",
    "result": "증거가 확인되지 않았습니다.",
    "severity": "NONE",
    "details": {},
}


def selection(url=URL, parameters=None, name="scan_sqli"):
    call = ResponseFunctionToolCall(
        type="function_call",
        name=name,
        call_id="call_test",
        id="fc_test",
        arguments=json.dumps({
            "url": url,
            "method": "GET",
            "parameters": PARAMETERS if parameters is None else parameters,
        }),
    )
    return SimpleNamespace(status="completed", output=[call])


class OpenAIAnalysisTest(unittest.TestCase):
    def client(self, first):
        client = MagicMock()
        client.with_options.return_value = client
        client.__enter__.return_value = client
        client.responses.create.side_effect = [first, SimpleNamespace(
            status="completed",
            model="gpt-6.1-sol",
            output_text="실제 스캐너 호출 결과를 정리했습니다.",
        )]
        return client

    def test_tool_result_returns_to_ai_with_matching_call_id(self):
        client = self.client(selection())
        progress = []
        with patch.object(openai_module, "get_openai_client", return_value=client), \
                patch.object(openai_module, "execute_tool", return_value=[FINDING]) as execute:
            report = openai_module.analyze_sinks(
                PAYLOAD,
                session_cookie="private-cookie",
                on_progress=progress.append,
            )
        execute.assert_called_once()
        self.assertEqual(execute.call_args.kwargs["session_cookie"], "private-cookie")
        self.assertEqual(client.responses.create.call_count, 2)
        self.assertEqual(report["tool_call_count"], 1)
        self.assertEqual(report["tool_results"], [FINDING])
        continuation = client.responses.create.call_args.kwargs
        self.assertEqual(continuation["tool_choice"], "none")
        self.assertFalse(continuation["store"])
        self.assertEqual(continuation["input"][-2]["type"], "function_call")
        self.assertEqual(continuation["input"][-1]["call_id"], "call_test")
        self.assertEqual(json.loads(continuation["input"][-1]["output"]), [FINDING])
        self.assertNotIn("private-cookie", json.dumps(continuation, default=str))

    def test_uncollected_or_mismatched_tool_is_rejected_before_execution(self):
        invalid = (
            selection(url=URL + "/unknown"),
            selection(parameters=[{"name": "other", "location": "query"}]),
            selection(name="scan_ssrf"),
        )
        for first in invalid:
            with self.subTest(arguments=first.output[0].arguments, name=first.output[0].name):
                client = self.client(first)
                with patch.object(openai_module, "get_openai_client", return_value=client), \
                        patch.object(openai_module, "execute_tool") as execute:
                    with self.assertRaisesRegex(ValueError, "Sink 탐색 결과"):
                        openai_module.analyze_sinks(PAYLOAD)
                    execute.assert_not_called()
                self.assertEqual(client.responses.create.call_count, 1)

    def test_incomplete_summary_is_not_returned_as_finished(self):
        client = self.client(selection())
        client.responses.create.side_effect = [
            selection(),
            SimpleNamespace(status="incomplete", output_text=""),
        ]
        with patch.object(openai_module, "get_openai_client", return_value=client), \
                patch.object(openai_module, "execute_tool", return_value=[FINDING]):
            with self.assertRaisesRegex(ValueError, "AI 요약이 완료되지"):
                openai_module.analyze_sinks(PAYLOAD)


if __name__ == "__main__":
    unittest.main()
