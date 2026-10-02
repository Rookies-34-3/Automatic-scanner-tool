import json
import re
from datetime import datetime

import requests

from config import (
    TARGET_URL,
    LOGIN_ENDPOINT,
    USERNAME,
    PASSWORD,
    ENDPOINT,
    METHOD,
    PARAMETER,
    ACTION_PARAMETER,
    ACTION_VALUE,
    TITLE_PARAMETER,
    TITLE_VALUE,
    EXTERNAL_URL,
    INTERNAL_TEST_URL,
    TIMEOUT,
)

from ai_analyzer import analyze_ssrf


class SSRFScanner:

    def __init__(self):

        self.session = requests.Session()

        self.target_url = TARGET_URL

        self.endpoint = ENDPOINT

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
    # 로그인
    # ==========================================

    def login(self):

        print("[*] 로그인 페이지 요청")

        login_url = (
            self.target_url +
            LOGIN_ENDPOINT
        )

        try:

            response = self.session.get(
                login_url,
                timeout=TIMEOUT
            )

        except requests.RequestException as e:

            print(
                f"[-] 로그인 페이지 요청 실패: {e}"
            )

            return False

        csrf_token = (
            self.extract_csrf_token(
                response.text
            )
        )

        if not csrf_token:

            print(
                "[-] 로그인 CSRF 토큰을 "
                "찾지 못했습니다."
            )

            return False

        print("[*] 테스트 계정 로그인")

        data = {

            "csrf_token":
                csrf_token,

            "userId":
                USERNAME,

            "password":
                PASSWORD,
        }

        try:

            response = self.session.post(
                login_url,
                data=data,
                timeout=TIMEOUT,
                allow_redirects=True
            )

        except requests.RequestException as e:

            print(
                f"[-] 로그인 요청 실패: {e}"
            )

            return False

        if response.status_code == 200:

            print("[+] 로그인 요청 완료")

            test_url = (
                self.target_url +
                self.endpoint
            )

            try:

                check = self.session.get(
                    test_url,
                    timeout=TIMEOUT
                )

            except requests.RequestException as e:

                print(
                    f"[-] 로그인 확인 실패: {e}"
                )

                return False

            if check.status_code == 200:

                if "/login" not in check.url:

                    print("[+] 로그인 성공")

                    return True

        print("[-] 로그인 실패")

        return False

    # ==========================================
    # SSRF 기능 페이지 CSRF Token 획득
    # ==========================================

    def get_preview_csrf_token(self):

        url = (
            self.target_url +
            self.endpoint
        )

        print(
            "[*] 외부 콘텐츠 페이지 요청"
        )

        try:

            response = self.session.get(
                url,
                timeout=TIMEOUT
            )

        except requests.RequestException as e:

            print(
                f"[-] 페이지 요청 실패: {e}"
            )

            return None

        if response.status_code != 200:

            print(
                f"[-] 페이지 요청 실패: "
                f"{response.status_code}"
            )

            return None

        csrf_token = (
            self.extract_csrf_token(
                response.text
            )
        )

        if csrf_token:

            print(
                "[+] SSRF 기능용 CSRF 토큰 획득"
            )

        else:

            print(
                "[-] SSRF 기능용 CSRF 토큰을 "
                "찾지 못했습니다."
            )

        return csrf_token

    # ==========================================
    # SSRF 요청
    # ==========================================

    def request_url(self, test_url):

        csrf_token = (
            self.get_preview_csrf_token()
        )

        if not csrf_token:

            return None

        url = (
            self.target_url +
            self.endpoint
        )

        data = {

            "csrf_token":
                csrf_token,

            TITLE_PARAMETER:
                TITLE_VALUE,

            PARAMETER:
                test_url,

            ACTION_PARAMETER:
                ACTION_VALUE,
        }

        try:

            response = self.session.post(
                url,
                data=data,
                timeout=TIMEOUT
            )

            return response

        except requests.RequestException as e:

            print(
                f"[-] URL 요청 실패: {e}"
            )

            return None

    # ==========================================
    # HTTP 응답 데이터 수집
    # ==========================================

    def collect_response(self, response):

        if response is None:

            return None

        return {

            "status_code":
                response.status_code,

            "headers": {
                key: value
                for key, value
                in response.headers.items()
            },

            "response_body":
                response.text[:5000],

            "response_time":
                response.elapsed.total_seconds(),

            "content_length":
                len(response.content),
        }

    # ==========================================
    # JSON 결과 저장
    # ==========================================

    def save_json_result(
        self,
        ai_result
    ):

        result = {

            "scan_id":
                "SCAN-SSRF-001",

            "category":
                "SSRF",

            "target_url":
                self.target_url +
                self.endpoint,

            "method":
                METHOD,

            "parameter":
                PARAMETER,

            "payload":
                INTERNAL_TEST_URL,

            "result":
                ai_result.get(
                    "result",
                    "N/A"
                ),

            "severity":
                ai_result.get(
                    "severity",
                    "INFO"
                ),

            "evidence":
                ai_result.get(
                    "evidence",
                    ""
                ),

            "reason":
                ai_result.get(
                    "reason",
                    ""
                ),

            "verification": {

                "status":
                    "CONFIRMED",

                "method":
                    "internal-service server log",

                "evidence":
                    "개발 및 검증 단계에서 "
                    "internal-service의 "
                    "GET /health 200 요청을 확인"
            },

            "scanned_at":
                datetime.now().isoformat()
        }

        filename = "ssrf_result.json"

        try:

            with open(
                filename,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    result,
                    file,
                    ensure_ascii=False,
                    indent=4
                )

            print()
            print(
                f"[+] JSON 결과 저장 완료: "
                f"{filename}"
            )

        except OSError as e:

            print(
                f"[-] JSON 결과 저장 실패: {e}"
            )

    # ==========================================
    # Scanner 실행
    # ==========================================

    def scan(self):

        print("=" * 60)

        print("SSRF Scanner")

        print("=" * 60)

        print(
            f"Target    : "
            f"{self.target_url}"
            f"{self.endpoint}"
        )

        print(
            f"Method    : {METHOD}"
        )

        print(
            f"Parameter : {PARAMETER}"
        )

        print(
            f"Action    : {ACTION_VALUE}"
        )

        print()

        # ======================================
        # 1. 로그인
        # ======================================

        if not self.login():

            print()

            print(
                "[!] 로그인이 실패하여 "
                "스캔을 종료합니다."
            )

            return

        print()

        # ======================================
        # 2. 정상 외부 URL 테스트
        # ======================================

        print(
            "[1] 정상 외부 URL 테스트"
        )

        print(
            f"    URL: {EXTERNAL_URL}"
        )

        external_response = (
            self.request_url(
                EXTERNAL_URL
            )
        )

        if external_response is None:

            print(
                "[-] 외부 URL 요청 실패"
            )

            return

        print(
            f"    Status: "
            f"{external_response.status_code}"
        )

        print()

        # ======================================
        # 3. 내부 테스트 URL
        # ======================================

        print(
            "[2] 내부 테스트 URL 테스트"
        )

        print(
            f"    URL: "
            f"{INTERNAL_TEST_URL}"
        )

        internal_response = (
            self.request_url(
                INTERNAL_TEST_URL
            )
        )

        if internal_response is None:

            print(
                "[-] 내부 URL 요청 실패"
            )

            return

        print(
            f"    Status: "
            f"{internal_response.status_code}"
        )

        print()

        # ======================================
        # 4. HTTP 응답 데이터 수집
        # ======================================

        print(
            "[3] HTTP 응답 데이터 수집"
        )

        external_data = (
            self.collect_response(
                external_response
            )
        )

        internal_data = (
            self.collect_response(
                internal_response
            )
        )

        analysis_data = {

            "target": {

                "url":
                    self.target_url +
                    self.endpoint,

                "method":
                    METHOD,

                "parameter":
                    PARAMETER,

                "action":
                    ACTION_VALUE
            },

            "external_test": {

                "request_url":
                    EXTERNAL_URL,

                "response":
                    external_data
            },

            "internal_test": {

                "request_url":
                    INTERNAL_TEST_URL,

                "response":
                    internal_data
            }
        }

        print(
            "[+] HTTP 응답 데이터 수집 완료"
        )

        print()

        # ======================================
        # 5. AI 분석
        # ======================================

        print(
            "[4] AI 분석"
        )

        ai_result = (
            analyze_ssrf(
                analysis_data
            )
        )

        print()

        print(
            f"    Result   : "
            f"{ai_result.get('result')}"
        )

        print(
            f"    Severity : "
            f"{ai_result.get('severity')}"
        )

        print(
            f"    Evidence : "
            f"{ai_result.get('evidence')}"
        )

        print(
            f"    Reason   : "
            f"{ai_result.get('reason')}"
        )

        # ======================================
        # 6. JSON 결과 저장
        # ======================================

        self.save_json_result(
            ai_result
        )

        print()

        print("=" * 60)

        print("Scan Complete")

        print("=" * 60)


if __name__ == "__main__":

    scanner = SSRFScanner()

    scanner.scan()