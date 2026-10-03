import argparse
import copy
import html
import json
import uuid

import requests


class ReflectedXSSScanner:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Reflected-XSS-Scanner/1.0"
        })

    def scan(self, target):
        results = []

        for parameter in target["parameters"]:
            results.append(self._scan_parameter(target, parameter))

        return {
            "url": target["url"],
            "method": target["method"].upper(),
            "parameters": target["parameters"],
            "vuln": any(result["vulnerable"] for result in results),
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

    def _send(self, target, parameter, value):
        parameters = copy.deepcopy(target["parameters"])
        parameters[parameter] = value

        headers = {}

        session_cookie = target.get("session_cookie", "")

        if session_cookie:
            headers["Cookie"] = session_cookie

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