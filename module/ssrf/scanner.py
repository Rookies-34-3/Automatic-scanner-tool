import os
import re
import uuid

import requests

from .config import (
    TIMEOUT,
    VERIFIER_PAYLOAD_URL,
    VERIFIER_STATUS_URL,
    VERIFIER_TIMEOUT,
)


class SSRFScanner:

    def __init__(self, input_data):

        self.input_data = input_data

        self.target_url = input_data["url"]

        self.method = input_data["method"].upper()

        self.parameters = input_data.get(
            "parameters",
            {}
        )

        self.parameter_name = input_data.get(
            "ssrf_parameter",
            "url"
        )

        self.session_cookie = input_data.get(
            "session_cookie",
            ""
        )

        self.verifier_payload_url = input_data.get(
            "verifier_payload_url"
        ) or os.getenv(
            "SSRF_VERIFIER_PAYLOAD_URL",
            VERIFIER_PAYLOAD_URL
        )

        self.verifier_status_url = input_data.get(
            "verifier_status_url"
        ) or os.getenv(
            "SSRF_VERIFIER_STATUS_URL",
            VERIFIER_STATUS_URL
        )

        self.session = requests.Session()

    # ==========================================
    # Session Cookie 설정
    # ==========================================

    def set_session_cookie(self):

        if not self.session_cookie:
            return

        # 문자열 형태
        # "session=abc123; token=xyz"
        if isinstance(
            self.session_cookie,
            str
        ):

            cookies = (
                self.session_cookie
                .split(";")
            )

            for cookie in cookies:

                cookie = cookie.strip()

                if "=" not in cookie:
                    continue

                name, value = (
                    cookie.split(
                        "=",
                        1
                    )
                )

                self.session.cookies.set(
                    name.strip(),
                    value.strip()
                )

        # JSON object 형태
        elif isinstance(
            self.session_cookie,
            dict
        ):

            for name, value in (
                self.session_cookie.items()
            ):

                self.session.cookies.set(
                    name,
                    value
                )

    # ==========================================
    # CSRF Token 추출
    # ==========================================

    def extract_csrf_token(self, html):

        match = re.search(
            r'name=["\']csrf_token["\']\s+'
            r'type=["\']hidden["\']\s+'
            r'value=["\']([^"\']+)',
            html
        )

        if not match:

            match = re.search(
                r'name=["\']csrf_token["\']'
                r'[^>]*value=["\']([^"\']+)',
                html
            )

        if match:
            return match.group(1)

        return None

    # ==========================================
    # CSRF Token 획득
    # ==========================================

    def get_csrf_token(self):

        try:

            response = self.session.get(
                self.target_url,
                timeout=TIMEOUT
            )

        except requests.RequestException as e:

            print(
                f"[-] CSRF 페이지 요청 실패: {e}"
            )

            return None

        if response.status_code != 200:

            print(
                f"[-] 페이지 요청 실패: "
                f"{response.status_code}"
            )

            return None

        token = self.extract_csrf_token(
            response.text
        )

        return token

    # ==========================================
    # HTTP 요청
    # ==========================================

    def send_request(self, url):

        parameters = dict(
            self.parameters
        )

        csrf_token = (
            self.get_csrf_token()
        )

        if csrf_token:

            parameters["csrf_token"] = (
                csrf_token
            )

        try:

            if self.method == "GET":

                response = self.session.get(
                    url,
                    params=parameters,
                    timeout=TIMEOUT
                )

            elif self.method == "POST":

                response = self.session.post(
                    url,
                    data=parameters,
                    timeout=TIMEOUT
                )

            elif self.method == "PUT":

                response = self.session.put(
                    url,
                    data=parameters,
                    timeout=TIMEOUT
                )

            elif self.method == "DELETE":

                response = self.session.delete(
                    url,
                    params=parameters,
                    timeout=TIMEOUT
                )

            else:

                raise ValueError(
                    f"지원하지 않는 HTTP Method: "
                    f"{self.method}"
                )

            return response

        except requests.RequestException as e:

            print(
                f"[-] HTTP 요청 실패: {e}"
            )

            return None

    # ==========================================
    # SSRF Verifier 상태 확인
    # ==========================================

    def check_verifier(self, verification_id):

        status_url = (
            f"{self.verifier_status_url.rstrip('/')}/"
            f"{verification_id}"
        )

        try:

            response = requests.get(
                status_url,
                timeout=VERIFIER_TIMEOUT
            )

            if response.status_code != 200:

                print(
                    f"[-] Verifier 상태 조회 실패: "
                    f"HTTP {response.status_code}"
                )

                return {
                    "received": False,
                    "status_code": response.status_code,
                    "error": "Verifier status API가 정상 응답하지 않았습니다."
                }

            data = response.json()

            return {
                "received": bool(data.get("received")),
                "status_code": response.status_code,
                "time": data.get("time"),
                "client": data.get("client"),
                "method": data.get("method"),
                "path": data.get("path"),
                "id": data.get("id", verification_id)
            }

        except (requests.RequestException, ValueError) as e:

            print(
                f"[-] Verifier 상태 조회 실패: {e}"
            )

            return {
                "received": False,
                "status_code": None,
                "error": str(e)
            }

    # ==========================================
    # 응답 데이터 수집
    # ==========================================

    def collect_response(
        self,
        response
    ):

        if response is None:
            return None

        return {
            "status_code": response.status_code,
            "response_time": response.elapsed.total_seconds(),
            "content_length": len(response.content),
        }

    # ==========================================
    # SSRF Scanner
    # ==========================================

    def scan(self):

        print("=" * 60)
        print("SSRF Scanner")
        print("=" * 60)

        print(
            f"URL       : {self.target_url}"
        )

        print(
            f"Method    : {self.method}"
        )

        print(
            f"Parameters: {self.parameters}"
        )

        print()

        # ======================================
        # 세션 쿠키 설정
        # ======================================

        self.set_session_cookie()

        # ======================================
        # 내부 테스트 URL
        # ======================================

        internal_url = self.parameters.get(
            self.parameter_name
        )

        if not internal_url:

            return {
                "url":
                    self.target_url,

                "method":
                    self.method,

                "parameters":
                    self.parameters,

                "vuln":
                    "N/A",

                "result":
                    "SSRF 테스트 URL이 없습니다."
            }

        # ======================================
        # 정상 외부 URL
        # ======================================

        external_url = (
            "https://example.com"
        )

        print(
            "[1] 정상 외부 URL 테스트"
        )

        print(
            f"    URL: {external_url}"
        )

        # 외부 URL을 parameter에 넣어서 요청
        external_parameters = dict(
            self.parameters
        )

        external_parameters[self.parameter_name] = (
            external_url
        )

        original_parameters = (
            self.parameters
        )

        self.parameters = (
            external_parameters
        )

        external_response = (
            self.send_request(
                self.target_url
            )
        )

        self.parameters = (
            original_parameters
        )

        if external_response is None:

            return {
                "url":
                    self.target_url,

                "method":
                    self.method,

                "parameters":
                    original_parameters,

                "vuln":
                    "N/A",

                "result":
                    "외부 URL 요청에 실패했습니다."
            }

        print(
            f"    Status: "
            f"{external_response.status_code}"
        )

        print()

        # ======================================
        # SSRF Verifier 테스트
        # ======================================

        print(
            "[2] SSRF Verifier 테스트"
        )

        verification_id = uuid.uuid4().hex

        verifier_url = (
            f"{self.verifier_payload_url.rstrip('/')}/"
            f"{verification_id}"
        )

        print(
            f"    Verification ID: {verification_id}"
        )

        print(
            f"    Payload URL: {verifier_url}"
        )

        verifier_parameters = dict(
            self.parameters
        )

        verifier_parameters[self.parameter_name] = (
            verifier_url
        )

        self.parameters = (
            verifier_parameters
        )

        verifier_response = (
            self.send_request(
                self.target_url
            )
        )

        self.parameters = (
            original_parameters
        )

        if verifier_response is None:

            return {
                "url":
                    self.target_url,

                "method":
                    self.method,

                "parameters":
                    original_parameters,

                "vuln":
                    "N/A",

                "result":
                    "SSRF Verifier 테스트 요청에 실패했습니다."
            }

        print(
            f"    Target Status: "
            f"{verifier_response.status_code}"
        )

        # 대상 서버가 실제로 verifier에 요청했는지 확인
        verifier_evidence = self.check_verifier(
            verification_id
        )

        print(
            f"    Verifier Received: "
            f"{verifier_evidence.get('received')}"
        )

        print()

        # ======================================
        # 응답 데이터 수집
        # ======================================

        print(
            "[3] HTTP 응답 및 Verifier 데이터 수집"
        )

        analysis_data = {

            "target": {

                "url":
                    self.target_url,

                "method":
                    self.method,

                "parameters":
                    original_parameters
            },

            "external_test": {

                "request_url":
                    external_url,

                "response":
                    self.collect_response(
                        external_response
                    )
            },

            "verifier_test": {

                "verification_id":
                    verification_id,

                "request_url":
                    verifier_url,

                "response":
                    self.collect_response(
                        verifier_response
                    ),

                "verifier_evidence":
                    verifier_evidence,

                "original_test_url":
                    internal_url
            }
        }

        print(
            "[+] 응답 데이터 수집 완료"
        )

        print()

        # Verifier의 관측 결과로 결정론적으로 판정한다. 전역 OpenAI 분석은
        # 통합 파이프라인에서 한 번만 수행하며 스캐너 내부에서는 호출하지 않는다.
        received = bool(verifier_evidence.get("received"))
        reported_id = str(verifier_evidence.get("id") or "")
        reported_path = str(verifier_evidence.get("path") or "")
        id_matches = reported_id == verification_id or reported_path.rstrip("/").endswith(
            "/" + verification_id
        )

        if received and id_matches:
            vuln = "VULNERABLE"
            reason = "SSRF 검증 서버에서 대상 애플리케이션의 서버 측 요청을 확인했습니다."
        elif verifier_evidence.get("error"):
            vuln = "REVIEW"
            reason = "검증 서버의 상태를 확인하지 못해 SSRF 여부를 판정할 수 없습니다."
        elif received:
            vuln = "REVIEW"
            reason = "검증 요청은 관측됐지만 요청 식별자가 일치하지 않아 재확인이 필요합니다."
        else:
            vuln = "PASS"
            reason = "SSRF 검증 서버에서 해당 요청이 관측되지 않았습니다."

        result = {
            "url": self.target_url,
            "method": self.method,
            "parameters": original_parameters,
            "vuln": vuln,
            "result": reason,
            "details": analysis_data,
        }

        print()

        print(
            f"    VULN : "
            f"{result['vuln']}"
        )

        print(
            f"    RESULT: "
            f"{result['result']}"
        )

        return result
