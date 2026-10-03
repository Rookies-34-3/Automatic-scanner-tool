import requests


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
            "result": "Directory Indexing 검사는 GET 요청만 지원합니다.",
            "status_code": None,
            "details": {
                "reason": "unsupported_method"
            }
        }

    session = requests.Session()

    if isinstance(cookie, dict):
        session.cookies.update(cookie)

    elif isinstance(cookie, str) and cookie.strip():
        for item in cookie.split(";"):
            item = item.strip()

            if "=" not in item:
                continue

            name, value = item.split("=", 1)
            session.cookies.set(name.strip(), value.strip())

    try:
        response = session.get(
            url,
            timeout=5
        )

    except requests.RequestException as e:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": f"HTTP 요청 실패: {type(e).__name__}",
            "status_code": None,
            "details": {
                "reason": "request_failed",
                "error_type": type(e).__name__
            }
        }

    finally:
        session.close()

    body = response.text.lower()

    matched_indicators = []

    if "index of /" in body:
        matched_indicators.append("Index of /")

    if "<title>index of" in body:
        matched_indicators.append("<title>Index of")

    detected = (
        response.status_code == 200
        and bool(matched_indicators)
    )

    if detected:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "VULNERABLE",
            "result": (
                "HTTP 200 응답에서 디렉터리 목록을 나타내는 "
                "'Index of'가 확인되어 디렉터리 인덱싱이 노출된 것으로 판단됩니다."
            ),
            "status_code": response.status_code,
            "details": {
                "matched_indicators": matched_indicators
            }
        }

    return {
        "url": url,
        "method": method,
        "parameters": parameters,
        "vuln": "SAFE",
        "result": (
            "응답에서 디렉터리 목록을 나타내는 "
            "'Index of'가 확인되지 않았습니다."
        ),
        "status_code": response.status_code,
        "details": {
            "matched_indicators": matched_indicators
        }
    }