import argparse
import copy
import html
import json
import re
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

        for point in target.get("injection_points", []):
            results.append(self._scan_point(target, point))

        return {
            "endpoint_id": target.get("endpoint_id"),
            "url": target["url"],
            "method": target.get("method", "GET").upper(),
            "findings": results,
        }

    def _scan_point(self, target, point):
        location = point["location"]
        name = point["name"]

        if location not in ("query", "body"):
            return {
                "location": location,
                "parameter": name,
                "status": "unsupported",
                "reason": "현재 MVP는 query/body만 지원합니다.",
            }

        canary = f"XSS_CANARY_{uuid.uuid4().hex[:8]}"

        try:
            response = self._send_with_value(
                target,
                location,
                name,
                canary,
            )
        except requests.RequestException as exc:
            return {
                "location": location,
                "parameter": name,
                "status": "error",
                "error": str(exc),
            }

        if canary not in response.text:
            return {
                "location": location,
                "parameter": name,
                "status": "not_reflected",
                "http_status": response.status_code,
            }

        context = self._detect_context(response.text, canary)
        payloads = self._get_payloads(context)

        payload_results = []

        for payload in payloads:
            try:
                payload_response = self._send_with_value(
                    target,
                    location,
                    name,
                    payload,
                )
            except requests.RequestException as exc:
                payload_results.append({
                    "payload": payload,
                    "result": "error",
                    "error": str(exc),
                })
                continue

            reflection = self._check_payload_reflection(
                payload_response.text,
                payload,
            )

            payload_results.append({
                "payload": payload,
                "result": reflection,
                "http_status": payload_response.status_code,
                "evidence": self._get_evidence(
                    payload_response.text,
                    payload,
                ),
            })

        raw_reflected = any(
            item["result"] == "raw_reflected"
            for item in payload_results
        )

        return {
            "location": location,
            "parameter": name,
            "status": "likely" if raw_reflected else "reflected",
            "context": context,
            "http_status": response.status_code,
            "payload_tests": payload_results,
        }

    def _send_with_value(self, target, location, name, value):
        request_target = copy.deepcopy(target)

        query = request_target.get("query", {})
        body = request_target.get("body", {})
        headers = request_target.get("headers", {})
        cookies = request_target.get("cookies", {})

        if location == "query":
            query[name] = value

        elif location == "body":
            body[name] = value

        method = request_target.get("method", "GET").upper()

        request_args = {
            "method": method,
            "url": request_target["url"],
            "params": query,
            "headers": headers,
            "cookies": cookies,
            "timeout": self.timeout,
            "allow_redirects": True,
        }

        content_type = self._get_content_type(headers)

        if method not in ("GET", "HEAD"):
            if "application/json" in content_type:
                request_args["json"] = body
            else:
                request_args["data"] = body

        return self.session.request(**request_args)

    @staticmethod
    def _get_content_type(headers):
        for key, value in headers.items():
            if key.lower() == "content-type":
                return value.lower()

        return ""

    @staticmethod
    def _detect_context(response_text, marker):
        index = response_text.find(marker)

        if index == -1:
            return "UNKNOWN"

        lower_text = response_text.lower()

        # <script> 내부인지 확인
        script_start = lower_text.rfind("<script", 0, index)
        script_end = lower_text.rfind("</script", 0, index)

        if script_start > script_end:
            return "JAVASCRIPT"

        # HTML 태그 내부인지 확인
        tag_start = response_text.rfind("<", 0, index)
        tag_end = response_text.rfind(">", 0, index)

        if tag_start > tag_end:
            before_marker = response_text[tag_start:index]

            match = re.search(
                r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*["\']?[^"\']*$',
                before_marker,
            )

            if match:
                attribute_name = match.group(1).lower()

                if attribute_name in (
                    "href",
                    "src",
                    "action",
                    "formaction",
                ):
                    return "URL_ATTRIBUTE"

                return "HTML_ATTRIBUTE"

            return "HTML_TAG"

        return "HTML_TEXT"

    @staticmethod
    def _get_payloads(context):
        payload_map = {
            "HTML_TEXT": [
                "<svg onload=alert(1337)>",
            ],

            "HTML_ATTRIBUTE": [
                '" autofocus onfocus=alert(1337) x="',
            ],

            "URL_ATTRIBUTE": [
                "javascript:alert(1337)",
            ],

            "JAVASCRIPT": [
                '";alert(1337);//',
            ],

            "HTML_TAG": [
                "<svg onload=alert(1337)>",
            ],

            "UNKNOWN": [
                "<svg onload=alert(1337)>",
            ],
        }

        return payload_map.get(context, payload_map["UNKNOWN"])

    @staticmethod
    def _check_payload_reflection(response_text, payload):
        if payload in response_text:
            return "raw_reflected"

        encoded = html.escape(payload, quote=True)

        if encoded in response_text:
            return "html_encoded"

        return "not_reflected"

    @staticmethod
    def _get_evidence(response_text, payload, size=80):
        index = response_text.find(payload)

        if index == -1:
            encoded = html.escape(payload, quote=True)
            index = response_text.find(encoded)

            if index == -1:
                return None

        start = max(0, index - size)
        end = min(len(response_text), index + len(payload) + size)

        return response_text[start:end]


def load_targets(filename):
    with open(filename, "r", encoding="utf-8") as file:
        data = json.load(file)

    if "targets" in data:
        return data["targets"]

    return [data]


def save_results(filename, results):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(
            results,
            file,
            indent=2,
            ensure_ascii=False,
        )


def main():
    parser = argparse.ArgumentParser(
        description="Reflected XSS Scanner"
    )

    parser.add_argument(
        "input",
        help="Endpoint JSON 파일",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="xss_results.json",
        help="결과 JSON 파일",
    )

    args = parser.parse_args()

    targets = load_targets(args.input)

    scanner = ReflectedXSSScanner()

    results = []

    for target in targets:
        print(
            f"[+] Scanning: "
            f"{target.get('endpoint_id', target['url'])}"
        )

        result = scanner.scan(target)
        results.append(result)

        for finding in result["findings"]:
            print(
                f"    {finding.get('parameter')} "
                f"-> {finding.get('status')}"
            )

    save_results(args.output, results)

    print(f"\n[+] Result saved: {args.output}")


if __name__ == "__main__":
    main()