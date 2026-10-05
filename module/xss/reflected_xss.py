import argparse
import copy
import html
import json
import uuid
import re
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup


class ReflectedXSSScanner:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Reflected-XSS-Scanner/1.0"
        })

    def scan(self, target):
        target = copy.deepcopy(target)
        self.session.cookies.clear()
        login = urlsplit(target["url"]).path.rstrip("/") == "/login"
        # 로그인 실패 응답을 검사해야 하므로 기존 인증 세션을 사용하지 않는다.
        if login:
            target["session_cookie"] = ""
        else:
            for cookie in target.get("session_cookie", "").split(";"):
                name, sep, value = cookie.strip().partition("=")
                if sep:
                    self.session.cookies.set(name, value, domain=urlsplit(target["url"]).hostname, path="/")
        candidates = list(target["parameters"])
        if target["method"].upper() == "POST":
            try:
                _, controls = self._form_parameters(target)
                candidates = [name for name in candidates if name not in controls]
            except requests.RequestException as exc:
                return {"url": target["url"], "method": "POST", "parameters": target["parameters"],
                        "vuln": "ERROR", "result": [{"vulnerable": False, "reason": f"request error: {exc}"}]}
        results = []

        for parameter in candidates:
            results.append(self._scan_parameter(target, parameter))

        return {
            "url": target["url"],
            "method": target["method"].upper(),
            "parameters": target["parameters"],
            "vuln": (True if any(result["vulnerable"] for result in results)
                     else "ERROR" if any("request error" in result.get("reason", "") for result in results)
                     else "REVIEW" if not results or any(result.get("inconclusive") for result in results)
                     else False),
            "result": results
        }

    def _scan_parameter(self, target, parameter):
        canary = f"XSS_CANARY_{uuid.uuid4().hex[:8]}"

        try:
            response = self._send(target, parameter, canary)
        except requests.RequestException as e:
            return {
                "parameter": parameter,
                "vulnerable": False,
                "reason": f"request error: {e}"
            }

        if getattr(response, "status_code", 200) >= 400:
            return {"parameter": parameter, "vulnerable": False, "inconclusive": True,
                    "reason": f"probe rejected: HTTP {response.status_code}"}

        # 1. 입력값 반사 여부 확인
        if canary not in response.text:
            return {
                "parameter": parameter,
                "vulnerable": False,
                "reason": "input value was not reflected in response"
            }

        # 2. 반사되는 Context 확인
        context = self._detect_context(response.text, canary)

        # 3. Context에 맞는 Payload 선택
        payload = self._get_payload(context)

        try:
            payload_response = self._send(target, parameter, payload)
        except requests.RequestException as e:
            return {
                "parameter": parameter,
                "vulnerable": False,
                "context": context,
                "reason": f"payload request error: {e}"
            }

        if getattr(payload_response, "status_code", 200) >= 400:
            return {"parameter": parameter, "vulnerable": False, "inconclusive": True,
                    "reason": f"payload rejected: HTTP {payload_response.status_code}"}

        # 4. Payload가 그대로 반사되는지 확인
        if payload in payload_response.text:
            return {
                "parameter": parameter,
                "vulnerable": True,
                "context": context,
                "payload": payload,
                "evidence": self._get_evidence(
                    payload_response.text,
                    payload
                )
            }

        encoded_payload = html.escape(payload, quote=True)

        if encoded_payload in payload_response.text:
            return {
                "parameter": parameter,
                "vulnerable": False,
                "context": context,
                "payload": payload,
                "reason": "payload was HTML-encoded",
                "evidence": self._get_evidence(
                    payload_response.text,
                    encoded_payload
                )
            }

        return {
            "parameter": parameter,
            "vulnerable": False,
            "context": context,
            "payload": payload,
            "reason": "payload was not reflected"
        }

    def _form_parameters(self, target):
        response = self.session.get(target["url"], timeout=self.timeout, allow_redirects=True)
        response.raise_for_status()
        forms = BeautifulSoup(response.text, "html.parser").find_all("form")
        form = next((form for form in forms
                     if form.get("method", "GET").upper() == "POST"
                     and urlsplit(urljoin(response.url, form.get("action", "")))[:3]
                     == urlsplit(target["url"])[:3]), None)
        if form is None:
            raise requests.RequestException("matching POST form unavailable; cannot validate submission")
        values, controls = {}, set()
        for field in form.select("input[name], textarea[name], select[name], button[name]"):
            name = field["name"]
            kind = field.get("type", "text").lower()
            if field.has_attr("disabled") or (kind in {"checkbox", "radio"} and not field.has_attr("checked")):
                continue
            if field.name == "textarea":
                value = field.get_text()
            elif field.name == "select":
                option = field.find("option", selected=True) or field.find("option")
                value = option.get("value", option.get_text()) if option else ""
            else:
                value = field.get("value", "")
            values[name] = value
            if kind in {"hidden", "password", "submit", "button", "reset"} or field.name == "button" or re.search(r"csrf|token|password", name, re.I):
                controls.add(name)
            if kind == "password" and not value:
                values[name] = "RookiesScan_invalid_password_1!"
        return values, controls

    def _send(self, target, parameter, value):
        parameters = copy.deepcopy(target["parameters"])
        if target["method"].upper() == "POST":
            form_values, _ = self._form_parameters(target)
            # 매 요청마다 토큰을 갱신하고 함께 제출해야 하는 필드를 유지한다.
            parameters.update(form_values)
        parameters[parameter] = value

        headers = {}

        method = target["method"].upper()

        if method == "GET":
            return self.session.get(
                target["url"],
                params=parameters,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True
            )

        if method == "POST":
            return self.session.post(
                target["url"],
                data=parameters,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True
            )

        raise ValueError(f"Unsupported method: {method}")

    @staticmethod
    def _detect_context(response, marker):
        index = response.find(marker)

        if index == -1:
            return "UNKNOWN"

        lower = response.lower()

        # <script>...</script>
        script_start = lower.rfind("<script", 0, index)
        script_end = lower.rfind("</script", 0, index)

        if script_start > script_end:
            return "JAVASCRIPT"

        # 현재 Marker가 HTML Tag 내부인지 확인
        tag_start = response.rfind("<", 0, index)
        tag_end = response.rfind(">", 0, index)

        if tag_start > tag_end:
            return "HTML_ATTRIBUTE"

        return "HTML_TEXT"

    @staticmethod
    def _get_payload(context):
        payloads = {
            "HTML_TEXT":
                "<svg onload=alert(1337)>",

            "HTML_ATTRIBUTE":
                "\" autofocus onfocus=alert(1337) x=\"",

            "JAVASCRIPT":
                "\";alert(1337);//",

            "UNKNOWN":
                "<svg onload=alert(1337)>"
        }

        return payloads.get(context, payloads["UNKNOWN"])

    @staticmethod
    def _get_evidence(response, value, size=100):
        index = response.find(value)

        if index == -1:
            return None

        start = max(0, index - size)
        end = min(
            len(response),
            index + len(value) + size
        )

        return response[start:end]


def load_input(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return json.load(f)


def save_result(filename, result):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(
            result,
            f,
            indent=2,
            ensure_ascii=False
        )


def main():
    parser = argparse.ArgumentParser(
        description="Reflected XSS Scanner"
    )

    parser.add_argument(
        "input",
        help="Input JSON file"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="xss_result.json",
        help="Output JSON file"
    )

    args = parser.parse_args()

    target = load_input(args.input)

    scanner = ReflectedXSSScanner()
    result = scanner.scan(target)

    save_result(args.output, result)

    print(f"[+] URL    : {result['url']}")
    print(f"[+] Method : {result['method']}")
    print(f"[+] Vuln   : {result['vuln']}")
    print(f"[+] Output : {args.output}")


if __name__ == "__main__":
    main()
