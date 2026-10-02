import requests


def run(url, method, parameters, cookie):
    """
    Directory Indexing 검사

    입력:
        url        : 검사 대상 전체 URL
        method     : HTTP Method
        parameters : 요청 파라미터
        cookie     : 세션 쿠키 (dict 또는 문자열)

    출력:
        url
        method
        parameters
        vuln
        result
    """

    method = method.upper()

    # 현재 Directory Indexing 검사는 GET만 지원
    if method != "GET":
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "Directory Indexing 검사는 GET 요청만 지원합니다."
        }

    session = requests.Session()

    # cookie가 dict 형태인 경우
    if isinstance(cookie, dict):
        session.cookies.update(cookie)

    # cookie가 "session=abc; token=xyz" 형태인 경우
    elif isinstance(cookie, str) and cookie.strip():
        for item in cookie.split(";"):
            item = item.strip()

            if "=" not in item:
                continue

            name, value = item.split("=", 1)

            session.cookies.set(
                name.strip(),
                value.strip()
            )

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
            "result": f"HTTP 요청 실패: {type(e).__name__}"
        }

    finally:
        session.close()

    body = response.text.lower()

    detected = (
        response.status_code == 200
        and (
            "index of /" in body
            or "<title>index of" in body
        )
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
            )
        }

    return {
        "url": url,
        "method": method,
        "parameters": parameters,
        "vuln": "SAFE",
        "result": (
            "응답에서 디렉터리 목록을 나타내는 "
            "'Index of'가 확인되지 않았습니다."
        )
    }