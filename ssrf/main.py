import json
import os
import re

import requests

from scanner import SSRFScanner


INPUT_FILE = "ssrf_input.json"
OUTPUT_FILE = "ssrf_result.json"

TIMEOUT = 10


def extract_csrf_token(html):

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


def login(target_url):

    username = (
        os.getenv("SSRF_USERNAME")
        or os.getenv("SSrf_USERNAME")
    )

    password = (
        os.getenv("SSRF_PASSWORD")
        or os.getenv("SSrf_PASSWORD")
    )

    if not username or not password:

        print("[-] SSRF_USERNAME / SSRF_PASSWORD 환경변수가 없습니다.")

        return None

    # target_url에서 서버 주소 추출
    base_url = target_url.split(
        "/pre-course/",
        1
    )[0]

    login_url = f"{base_url}/login"

    session = requests.Session()

    print("[0] 로그인")

    try:

        # 로그인 페이지 요청
        response = session.get(
            login_url,
            timeout=TIMEOUT
        )

        if response.status_code != 200:

            print(
                f"[-] 로그인 페이지 요청 실패: "
                f"{response.status_code}"
            )

            return None

        csrf_token = extract_csrf_token(
            response.text
        )

        if not csrf_token:

            print("[-] 로그인 페이지에서 CSRF 토큰을 찾지 못했습니다.")

            return None

        # 로그인 요청
        login_data = {
            "csrf_token": csrf_token,
            "userId": username,
            "password": password
        }

        login_response = session.post(
            login_url,
            data=login_data,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        print(
            f"    Login Status: "
            f"{login_response.status_code}"
        )

        if login_response.status_code not in (
            200,
            302
        ):

            print("[-] 로그인 요청 실패")

            return None

        # 세션 쿠키 확인
        if not session.cookies:

            print("[-] 로그인 후 세션 쿠키가 없습니다.")

            return None

        print(
            f"    Login User: {username}"
        )

        print(
            f"    Session Cookies: "
            f"{dict(session.cookies)}"
        )

        # scanner.py에서 사용할 쿠키 문자열 생성
        session_cookie = "; ".join(
            f"{name}={value}"
            for name, value
            in session.cookies.items()
        )

        print("[+] 로그인 세션 확보")

        return session_cookie

    except requests.RequestException as e:

        print(
            f"[-] 로그인 요청 오류: {e}"
        )

        return None


def main():

    # ==========================================
    # 입력 JSON 읽기
    # ==========================================

    try:

        with open(
            INPUT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            input_data = json.load(file)

    except FileNotFoundError:

        print(
            f"[-] 입력 파일이 없습니다: "
            f"{INPUT_FILE}"
        )

        return

    except json.JSONDecodeError as e:

        print(
            f"[-] JSON 형식 오류: {e}"
        )

        return

    # ==========================================
    # 자동 로그인
    # ==========================================

    session_cookie = login(
        input_data["url"]
    )

    if not session_cookie:

        print("[-] 로그인 실패로 스캐너를 실행하지 않습니다.")

        return

    # Scanner에 로그인 세션 전달
    input_data["session_cookie"] = session_cookie

    # ==========================================
    # Scanner 실행
    # ==========================================

    scanner = SSRFScanner(
        input_data
    )

    result = scanner.scan()

    # ==========================================
    # 결과 JSON 저장
    # ==========================================

    try:

        with open(
            OUTPUT_FILE,
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
            f"[+] 결과 JSON 생성: "
            f"{OUTPUT_FILE}"
        )

    except OSError as e:

        print(
            f"[-] 결과 JSON 저장 실패: {e}"
        )


if __name__ == "__main__":

    main()