"""로그인된 정상 폼 요청으로 내부 서비스 접근 증거를 확인한다."""

from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from .config import EXPECTED_MARKERS, PROBE_URL, TIMEOUT


class SSRFScanner:
    def __init__(self, input_data):
        self.target_url = input_data["url"]
        self.method = input_data["method"].upper()
        self.parameters = dict(input_data.get("parameters") or {})
        self.parameter_name = input_data.get("ssrf_parameter", "url")
        self.session_cookie = input_data.get("session_cookie", "")
        self.probe_url = input_data.get("probe_url") or self.parameters.get(
            self.parameter_name
        ) or PROBE_URL
        markers = input_data.get("expected_markers") or EXPECTED_MARKERS
        if isinstance(markers, str):
            markers = [item.strip() for item in markers.split("|") if item.strip()]
        self.expected_markers = tuple(markers)
        self.timeout = float(input_data.get("timeout", TIMEOUT))
        self.session = requests.Session()

    def set_session_cookie(self):
        """문자열 또는 객체로 받은 쿠키를 현재 HTTP 세션에 넣는다."""
        if isinstance(self.session_cookie, dict):
            self.session.cookies.update(self.session_cookie)
            return
        if not isinstance(self.session_cookie, str):
            return
        for cookie in self.session_cookie.split(";"):
            if "=" not in cookie:
                continue
            name, value = cookie.split("=", 1)
            if name.strip():
                self.session.cookies.set(name.strip(), value.strip())

    @staticmethod
    def _origin(url):
        parts = urlsplit(url)
        return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)

    def _result(self, vuln, reason, details=None):
        return {
            "url": self.target_url,
            "method": self.method,
            "parameters": self.parameters,
            "vuln": vuln,
            "result": reason,
            "severity": "HIGH" if vuln == "VULNERABLE" else "INFO",
            "details": details or {},
        }

    def _form_request(self):
        """대상 화면에서 URL 입력 폼과 최신 CSRF 값을 수집한다."""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
        except requests.RequestException:
            return None, "SSRF 입력 폼을 가져오지 못했습니다."
        if response.status_code != 200:
            return None, f"SSRF 입력 폼 GET 요청이 HTTP {response.status_code}를 반환했습니다."
        response_url = getattr(response, "url", self.target_url)
        if urlsplit(response_url).path.rstrip("/").endswith("/login"):
            return None, "세션이 로그인 화면으로 이동해 SSRF 입력 폼을 가져오지 못했습니다."

        soup = BeautifulSoup(response.text, "html.parser")
        form = next(
            (candidate for candidate in soup.find_all("form")
             if candidate.find(attrs={"name": self.parameter_name})),
            None,
        )
        if form is None:
            return None, f"{self.parameter_name} 입력 필드가 있는 폼을 찾지 못했습니다."

        action_url = urljoin(response_url, form.get("action") or self.target_url)
        if self._origin(action_url) != self._origin(self.target_url):
            return None, "폼 전송 주소가 대상과 다른 출처여서 검사를 중단했습니다."

        data = {}
        preview_action = False
        for control in form.find_all(["input", "textarea", "select", "button"]):
            name = control.get("name")
            if not name or control.has_attr("disabled"):
                continue
            kind = (control.get("type") or "").lower()
            if control.name == "button" or kind in {"submit", "button", "reset"}:
                if name == "action" and control.get("value") == "preview":
                    preview_action = True
                continue
            if kind == "file" or (
                kind in {"checkbox", "radio"} and not control.has_attr("checked")
            ):
                continue
            if control.name == "textarea":
                value = control.get_text()
            elif control.name == "select":
                option = control.find("option", selected=True) or control.find("option")
                value = option.get("value", option.get_text()) if option else ""
            else:
                value = control.get("value", "")
            data[name] = value

        for name, value in self.parameters.items():
            lowered = str(name).lower()
            if value not in (None, "") and name != self.parameter_name \
                    and name != "action" and "csrf" not in lowered and "token" not in lowered:
                data[name] = value
        data[self.parameter_name] = self.probe_url
        # 제목을 비워 두면 대상 앱이 내부 응답의 og:title을 채워 검증 증거가 노출된다.
        if "title" in data:
            data["title"] = ""
        if preview_action or "action" in data or "action" in self.parameters:
            data["action"] = "preview"

        form_method = (form.get("method") or "GET").upper()
        if form_method != self.method:
            return None, f"수집한 폼 메서드 {form_method}가 Sink 메서드 {self.method}와 다릅니다."
        return (action_url, form_method, data, response.status_code), None

    def scan(self):
        """내부 서비스 고유 문구가 대상 응답에 나타나는지 확인한다."""
        self.set_session_cookie()
        prepared, error = self._form_request()
        if error:
            return self._result("REVIEW", error)

        action_url, method, data, form_status = prepared
        request_data = {"params": data} if method in {"GET", "HEAD"} else {"data": data}
        try:
            response = self.session.request(
                method,
                action_url,
                timeout=self.timeout,
                allow_redirects=True,
                **request_data,
            )
        except requests.Timeout:
            return self._result(
                "REVIEW",
                f"SSRF 검증 요청이 {self.timeout:g}초 안에 완료되지 않았습니다.",
                {"probe_url": self.probe_url, "form_status": form_status},
            )
        except requests.RequestException:
            return self._result(
                "REVIEW",
                "SSRF 검증 HTTP 요청을 완료하지 못했습니다.",
                {"probe_url": self.probe_url, "form_status": form_status},
            )

        final_url = getattr(response, "url", action_url)
        details = {
            "probe_url": self.probe_url,
            "parameter": self.parameter_name,
            "action": "preview",
            "form_status": form_status,
            "target_status": response.status_code,
            "final_url": final_url,
        }
        if urlsplit(final_url).path.rstrip("/").endswith("/login"):
            return self._result("REVIEW", "세션이 로그인 화면으로 이동해 SSRF 검증을 완료하지 못했습니다.", details)
        if response.status_code >= 400:
            return self._result(
                "REVIEW",
                f"정상 폼으로 구성한 SSRF 검증 요청이 HTTP {response.status_code}를 반환했습니다.",
                details,
            )

        lowered = response.text.lower()
        marker = next((item for item in self.expected_markers if item.lower() in lowered), None)
        if marker:
            details["evidence_marker"] = marker
            return self._result(
                "VULNERABLE",
                f"대상 응답에서 내부 서비스 접근 증거 `{marker}`를 확인했습니다.",
                details,
            )

        alert = BeautifulSoup(response.text, "html.parser").select_one("[role=alert]")
        if alert:
            details["application_message"] = alert.get_text(" ", strip=True)[:300]
        return self._result(
            "REVIEW",
            "정상 폼 요청은 완료됐지만 내부 서비스 접근 증거를 찾지 못했습니다.",
            details,
        )
