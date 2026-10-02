import unittest
from email.message import Message
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

from streamlit.testing.v1 import AppTest
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


class StreamlitFlowTest(unittest.TestCase):
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
                with patch.object(sink_finder, "find_sinks") as rerun_finder:
                    app.button[1].click().run()
                    rerun_finder.assert_not_called()
            stale_finder.assert_not_called()
        self.assertFalse(app.exception)
        self.assertFalse(app.error)
        self.assertEqual(len(app.session_state["sinks"]), 6)
        self.assertEqual(len(app.session_state["openai_sinks"]["groups"]), 5)
        self.assertEqual(app.caption[0].value, "발견한 엔드포인트 6개 → OpenAI 전달 그룹 5개")
        self.assertEqual(app.info[0].value, "취약점 분석 기능은 준비 중입니다.")

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
            count = len(requests)
            app.button[0].click().run()
            self.assertFalse(app.exception)
            self.assertEqual(len(requests), count)
        self.assertEqual(app.text_input[0].value, "http://127.0.0.1:8080/")
        self.assertEqual(app.text_input[1].value, "test-cookie")
        self.assertEqual(app.button[0].label, "Sink 찾기")
        self.assertFalse(app.dataframe)

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
