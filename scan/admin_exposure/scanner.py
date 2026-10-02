import requests


def run(url, method, parameters, cookie):
    """
    관리자 페이지 노출 검사

    입력:
        url        : 검사 대상 URL
        method     : HTTP Method
        parameters : 요청 파라미터
        cookie     : 세션 쿠키

    출력:
        url
        method
        parameters
        vuln
        result
    """

    method = method.upper()

    if method != "GET":
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "관리자 페이지 노출 검사는 GET 요청만 지원합니다."
        }

    # 관리자 페이지 노출 여부는 비로그인 상태에서 검사한다.
    # 따라서 전달받은 cookie는 현재 검사에서는 사용하지 않는다.
    session = requests.Session()

    try:
        response = session.get(
            url,
            timeout=5,
            allow_redirects=False
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

    # 인증/인가에 의해 차단된 경우
    if response.status_code in (401, 403):
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "SAFE",
            "result": (
                f"HTTP {response.status_code} 응답으로 접근이 거부되어 "
                "관리자 페이지가 노출되지 않았습니다."
            )
        }

    location = response.headers.get("Location", "").lower()

    # 로그인 페이지로 리다이렉트되는 경우
    if response.status_code in (301, 302, 303, 307, 308):
        if "login" in location or "signin" in location:
            return {
                "url": url,
                "method": method,
                "parameters": parameters,
                "vuln": "SAFE",
                "result": (
                    "인증 페이지로 리다이렉트되어 "
                    "비로그인 상태에서 관리자 페이지에 접근할 수 없습니다."
                )
            }

        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": (
                f"HTTP {response.status_code} 리다이렉트가 발생하여 "
                "관리자 페이지 노출 여부를 확정할 수 없습니다."
            )
        }

    body = response.text.lower()

    indicators = [
        'data-active="admin"',
        "관리자 페이지",
        "관리자 대시보드",
        "lab-admin-section",
    ]

    matched = [
        indicator
        for indicator in indicators
        if indicator.lower() in body
    ]

    # 4개 지표 중 2개 이상이면 관리자 페이지로 판정
    if response.status_code == 200 and len(matched) >= 2:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "VULNERABLE",
            "result": (
                "비로그인 상태에서 HTTP 200 응답이 반환되었으며, "
                f"관리자 페이지 식별 지표 {len(matched)}개가 확인되었습니다: "
                + ", ".join(matched)
            )
        }

    if response.status_code == 200:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "SAFE",
            "result": (
                "HTTP 200 응답은 확인되었지만 관리자 페이지를 나타내는 "
                "충분한 식별 지표가 확인되지 않았습니다."
            )
        }

    return {
        "url": url,
        "method": method,
        "parameters": parameters,
        "vuln": "N/A",
        "result": (
            f"HTTP {response.status_code} 응답으로 인해 "
            "관리자 페이지 노출 여부를 명확하게 판단할 수 없습니다."
        )
    }