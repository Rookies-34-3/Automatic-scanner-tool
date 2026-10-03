import unittest
import json
import re
from email.message import Message
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

from streamlit.testing.v1 import AppTest
from openai import OpenAIError
import openai_module
import report_writer
import sink_finder


APP = Path(__file__).resolve().parents[1] / "streamlit_app.py"


def response(body="", status=200):
    result = BytesIO(body.encode("utf-8"))
    result.code = status
    result.headers = Message()
    result.headers["Content-Type"] = "text/html; charset=utf-8"
    return result


def scan(app=None):
    app = app or AppTest.from_file(str(APP)).run()
    app.text_input[0].set_value("http://127.0.0.1:8080/")
    app.text_input[1].set_value("test-cookie")
    return app.button[0].click().run()


def analysis_report(payload, session_cookie="", scanner_options=None, on_progress=None):
    if on_progress:
        on_progress("스캐너 처리 완료")
    return {
        "model": "gpt-6.1-sol", "group_count": len(payload["groups"]),
        "tool_call_count": 1,
        "summary": "입력 지점에 실제 스캐너를 실행했습니다.",
        "tool_results": [{
            "scanner_id": "sqli", "name": "SQL Injection",
            "url": "http://127.0.0.1:8080/search", "method": "GET",
            "parameters": [{"name": "content", "location": "query"}],
            "vuln": "PASS", "result": "취약점 증거가 확인되지 않았습니다.",
            "severity": "NONE", "details": {},
        }],
    }


class StreamlitFlowTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        writer_path = Path(temporary.name) / "report_writer.py"
        writer_patch = patch.object(report_writer, "__file__", str(writer_path))
        writer_patch.start()
        self.addCleanup(writer_patch.stop)

    def test_sink_json_is_saved_with_host_and_unique_identifier(self):
        opener = SimpleNamespace(open=lambda request, timeout: response("<title>Page</title>"))
        with patch("urllib.request.build_opener", return_value=opener):
            app = scan()
            first = Path(app.session_state["sink_json_path"])
            self.assertTrue(first.exists())
            self.assertTrue(re.fullmatch(
                r"openai-sinks-127\.0\.0\.1-8080-\d{8}-\d{6}-[0-9a-f]{8}\.json", first.name,
            ))
            saved = json.loads(first.read_text(encoding="utf-8"))
            self.assertEqual(saved, app.session_state["openai_sinks"])
            self.assertNotIn("test-cookie", first.read_text(encoding="utf-8"))
            app.button[0].click().run()
            app = scan(app)
            second = Path(app.session_state["sink_json_path"])
        self.assertNotEqual(first, second)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_aws_https_target_is_allowed_and_crawl_stays_on_same_origin(self):
        requested = []

        def open_page(request, timeout):
            requested.append(request.full_url)
            if urlsplit(request.full_url).path == "/":
                return response(
                    '<a href="/search">Search</a>'
                    '<a href="https://other.example/outside">Outside</a>'
                )
            return response("<title>Page</title>")

        opener = SimpleNamespace(open=open_page)
        with patch.object(sink_finder, "build_opener", return_value=opener):
            results = sink_finder.find_sinks(
                "https://rookiescan.example/", "session=test", seed_paths=[],
            )

        self.assertTrue(results)
        self.assertIn("https://rookiescan.example/search", requested)
        self.assertTrue(all(urlsplit(url).hostname == "rookiescan.example" for url in requested))

    def test_reloads_stale_finder_and_runs_real_collection(self):
        pages = {
            "/": '<form action="/search"><input name="content" type="search"></form>'
                 '<a href="/detail/1">One</a><a href="/detail/2">Two</a>',
            "/detail/1": "<title>One</title>",
            "/detail/2": "<title>Two</title>",
            "/admin": "<title>Admin</title>",
            "/uploads/": "<title>Index of /uploads/</title>",
        }

        def open_page(request, timeout):
            self.assertEqual(request.get_method(), "GET")
            path = urlsplit(request.full_url).path
            return response(pages.get(path, ""), 200 if path in pages else 404)

        with patch.object(sink_finder, "find_sinks", return_value=None) as stale_finder:
            with patch("urllib.request.build_opener", return_value=SimpleNamespace(open=open_page)):
                app = scan()
                self.assertEqual(len(app.dataframe[0].value), 5)
                self.assertFalse(app.text_input)
                self.assertEqual(app.caption[0].value, "발견한 엔드포인트 6개 → OpenAI 전달 그룹 5개")
                json_path = Path(app.session_state["sink_json_path"])
                saved = json.loads(json_path.read_text(encoding="utf-8"))
                saved["source_marker"] = "loaded_from_json"
                json_path.write_text(json.dumps(saved), encoding="utf-8")
                with patch("importlib.reload", side_effect=lambda module: module), \
                        patch.object(openai_module, "analyze_sinks", side_effect=analysis_report) as analyze, \
                        patch.object(sink_finder, "find_sinks") as rerun_finder:
                    app.button[1].click().run()
                    app.run()
                    analyze.assert_called_once()
                    self.assertEqual(analyze.call_args.args[0]["source_marker"], "loaded_from_json")
                    rerun_finder.assert_not_called()
            stale_finder.assert_not_called()
        self.assertFalse(app.exception)
        self.assertFalse(app.error)
        self.assertEqual(len(app.session_state["sinks"]), 6)
        self.assertEqual(len(app.session_state["openai_sinks"]["groups"]), 5)
        self.assertEqual(len(app.dataframe), 1)
        self.assertEqual([heading.value for heading in app.subheader], ["분석 보고서"])
        self.assertEqual(app.session_state["analysis_result"]["tool_results"][0]["vuln"], "PASS")
        self.assertTrue(any("스캐너 호출 1회" in item.value for item in app.caption))
        final_path = Path(app.session_state["analysis_result"]["json_path"])
        self.assertTrue(final_path.exists())
        self.assertNotIn("test-cookie", final_path.read_text(encoding="utf-8"))

    def test_none_is_visible_and_preserves_previous_results(self):
        app = AppTest.from_file(str(APP)).run()
        previous = [{"url": "previous-result"}]
        previous_summary = {"candidate_status": "unverified", "groups": [{
            "method": "GET", "path_template": "/previous", "discovered_count": 1,
            "candidate_tools": [], "request_variants": [{
                "parameters": [], "sample_url": "http://127.0.0.1:8080/previous",
            }],
        }]}
        app.session_state["sinks"] = previous
        app.session_state["openai_sinks"] = previous_summary
        with patch("importlib.reload", side_effect=lambda module: module):
            with patch.object(sink_finder, "find_sinks", return_value=None):
                app = scan(app)
        self.assertFalse(app.exception)
        self.assertEqual(len(app.error), 1)
        self.assertIn("올바른 목록", app.error[0].value)
        self.assertFalse(app.caption)
        self.assertEqual(app.session_state["sinks"], previous)
        self.assertEqual(app.session_state["openai_sinks"], previous_summary)

    def test_back_restores_inputs_without_collecting_again(self):
        requests = []

        def open_page(request, timeout):
            requests.append(request.full_url)
            return response("<title>Page</title>")

        with patch("urllib.request.build_opener", return_value=SimpleNamespace(open=open_page)):
            app = scan()
            self.assertFalse(app.exception)
            with patch("importlib.reload", side_effect=lambda module: module), \
                    patch.object(openai_module, "analyze_sinks", side_effect=analysis_report) as analyze:
                app.button[1].click().run()
                app.button[0].click().run()
                self.assertEqual([heading.value for heading in app.subheader], ["Sink 탐색 보고서"])
                self.assertEqual(len(app.dataframe), 1)
                app.button[1].click().run()
                self.assertEqual([heading.value for heading in app.subheader], ["분석 보고서"])
                analyze.assert_called_once()
            self.assertIn("analysis_result", app.session_state)
            count = len(requests)
            app.button[0].click().run()
            self.assertFalse(app.exception)
            self.assertEqual(len(requests), count)
            self.assertEqual([heading.value for heading in app.subheader], ["Sink 탐색 보고서"])
            app.button[0].click().run()
        self.assertEqual(app.text_input[0].value, "http://127.0.0.1:8080/")
        self.assertEqual(app.text_input[1].value, "test-cookie")
        self.assertEqual(app.button[0].label, "Sink 찾기")
        self.assertFalse(app.dataframe)
        with patch("urllib.request.build_opener", return_value=SimpleNamespace(open=open_page)):
            scan(app)
        self.assertNotIn("analysis_result", app.session_state)

    def test_analysis_error_is_visible_without_exposing_credentials(self):
        with patch("urllib.request.build_opener", return_value=SimpleNamespace(open=lambda request, timeout: response())):
            app = scan()
        with patch("importlib.reload", side_effect=lambda module: module), \
                patch.object(openai_module, "analyze_sinks", side_effect=OpenAIError("private-test-key")) as analyze:
            app.button[1].click().run()
            app.run()
            analyze.assert_called_once()
        self.assertFalse(app.exception)
        self.assertEqual(len(app.error), 1)
        self.assertIn("OpenAI 요청에 실패", app.error[0].value)
        self.assertNotIn("private-test-key", app.error[0].value)
        self.assertNotIn("analysis_result", app.session_state)
        self.assertEqual([heading.value for heading in app.subheader], ["취약점 분석 실패"])
        self.assertEqual([button.label for button in app.button], ["뒤로가기", "다시 시도"])
        with patch("importlib.reload", side_effect=lambda module: module), \
                patch.object(openai_module, "analyze_sinks", side_effect=analysis_report) as retry:
            app.button[1].click().run()
            retry.assert_called_once()
        self.assertFalse(app.error)
        self.assertIn("analysis_result", app.session_state)
        self.assertNotIn("analysis_error", app.session_state)

    def test_session_failure_is_visible(self):
        opener = SimpleNamespace(open=lambda request, timeout: response(status=401))
        with patch("urllib.request.build_opener", return_value=opener):
            app = scan()
        self.assertFalse(app.exception)
        self.assertEqual(len(app.error), 1)
        self.assertIn("session_expired", app.error[0].value)
        self.assertFalse(app.caption)


if __name__ == "__main__":
    unittest.main()
