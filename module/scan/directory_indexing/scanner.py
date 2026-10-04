import re
from urllib.parse import urlsplit

import requests


INDEX_TITLE = re.compile(r"<title[^>]*>\s*index\s+of(?:\s+[^<]*)?</title>", re.IGNORECASE)


def run(url, method, parameters, cookie):
    """
    Directory Indexing 검사

    반환값:
        url
        method
        parameters
        vuln
        result
        status_code
        details
    """

    method = method.upper()

    if method != "GET":
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "severity": "INFO",
            "result": "Directory Indexing 검사는 GET 요청만 지원합니다.",
            "status_code": None,
            "details": {
                "reason": "unsupported_method"
            }
        }

    if not urlsplit(url).path.endswith("/"):
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "severity": "INFO",
            "result": "파일 URL은 디렉터리 인덱싱 검사 대상이 아닙니다.",
            "status_code": None,
            "details": {"reason": "not_a_directory_url"},
        }

    # 디렉터리 목록은 인증 없이 노출되는지가 핵심이므로 로그인 쿠키를 사용하지 않는다.
    session = requests.Session()

    try:
        response = session.get(
            url,
            allow_redirects=False,
            timeout=5
        )

    except requests.RequestException as e:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "ERROR",
            "severity": "INFO",
            "result": f"HTTP 요청 실패: {type(e).__name__}",
            "status_code": None,
            "details": {
                "reason": "request_failed",
                "error_type": type(e).__name__
            }
        }

    finally:
        session.close()

    title = INDEX_TITLE.search(response.text)
    matched_indicators = [title.group(0)] if title else []
    detected = response.status_code == 200 and bool(title)

    if detected:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "VULNERABLE",
            "severity": "HIGH",
            "result": (
                "HTTP 200 응답에서 디렉터리 목록을 나타내는 "
                "'Index of'가 확인되어 디렉터리 인덱싱이 노출된 것으로 판단됩니다."
            ),
            "status_code": response.status_code,
            "details": {
                "matched_indicators": matched_indicators,
                "authentication": "anonymous",
            },
            "remediation": "웹 서버의 디렉터리 목록 기능을 비활성화하고 업로드 경로에 접근 제어를 적용하세요.",
        }

    return {
        "url": url,
        "method": method,
        "parameters": parameters,
        "vuln": "SAFE",
        "severity": "NONE",
        "result": (
            "응답에서 디렉터리 목록을 나타내는 "
            "'Index of'가 확인되지 않았습니다."
        ),
        "status_code": response.status_code,
        "details": {
            "matched_indicators": matched_indicators,
            "authentication": "anonymous",
        }
    }
