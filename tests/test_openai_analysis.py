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


def selection_for_payload(payload):
    calls = []
    index = 0
    for group in payload["groups"]:
        for variant in group["request_variants"]:
            for candidate in variant.get("candidate_tools", group.get("candidate_tools", [])):
                index += 1
                name = "scan_reflected_xss" if candidate == "xss" else f"scan_{candidate}"
                calls.append(ResponseFunctionToolCall(
                    type="function_call",
                    name=name,
                    call_id=f"call_{index}_{variant['sample_url']}",
                    id=f"fc_{index}",
                    arguments=json.dumps({
                        "url": variant["sample_url"],
                        "method": group["method"],
                        "parameters": variant["parameters"],
                    }),
                ))
    return SimpleNamespace(status="completed", output=calls)


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
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(
            {call.args[0] for call in execute.call_args_list},
            {"scan_sqli", "scan_reflected_xss"},
        )
        self.assertTrue(all(
            call.kwargs["session_cookie"] == "private-cookie"
            for call in execute.call_args_list
        ))
        self.assertEqual(client.responses.create.call_count, 2)
        self.assertEqual(report["tool_call_count"], 2)
        self.assertEqual(report["tool_results"], [FINDING, FINDING])
        continuation = client.responses.create.call_args.kwargs
        self.assertEqual(continuation["tool_choice"], "none")
        self.assertFalse(continuation["store"])
        self.assertEqual(continuation["input"][-3]["type"], "function_call")
        self.assertEqual(continuation["input"][-2]["call_id"], "call_test")
        self.assertEqual(json.loads(continuation["input"][-2]["output"]), [FINDING])
        supplemental = json.loads(continuation["input"][-1]["content"])
        self.assertEqual(supplemental["supplemental_tool_results"], [FINDING])
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

    def test_large_candidate_set_is_split_into_safe_selection_batches(self):
        payload = {"candidate_status": "unverified", "groups": []}
        for index in range(41):
            payload["groups"].append({
                "method": "GET",
                "path_template": f"/search/{index}",
                "candidate_tools": ["sqli"],
                "discovered_count": 1,
                "request_variants": [{
                    "sample_url": f"{URL}/{index}",
                    "parameters": PARAMETERS,
                }],
            })

        client = MagicMock()
        client.with_options.return_value = client
        client.__enter__.return_value = client

        def create(**kwargs):
            if kwargs["tool_choice"] == "none":
                return SimpleNamespace(
                    status="completed", model="gpt-6.1-sol", output_text="분할 실행 완료",
                )
            return selection_for_payload(json.loads(kwargs["input"][0]["content"]))

        client.responses.create.side_effect = create
        with patch.object(openai_module, "get_openai_client", return_value=client), \
                patch.object(openai_module, "execute_tool", return_value=[FINDING]) as execute:
            report = openai_module.analyze_sinks(payload)

        self.assertEqual(report["selection_batch_count"], 3)
        self.assertEqual(report["tool_call_count"], 41)
        self.assertEqual(execute.call_count, 41)
        self.assertEqual(client.responses.create.call_count, 4)
        selection_requests = client.responses.create.call_args_list[:-1]
        self.assertTrue(all(
            len(json.loads(call.kwargs["input"][0]["content"])["groups"]) <= 20
            for call in selection_requests
        ))


if __name__ == "__main__":
    unittest.main()
