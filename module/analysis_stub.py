"""Function call 연결을 확인하는 임시 분석 tool."""


TOOL_LABELS = {
    "sqli": "SQL Injection", "xss": "XSS", "ssrf": "SSRF",
    "fileio": "파일 처리", "authn": "인증", "authz": "접근 권한",
}


def analyze_endpoint_stub(url: str, method: str, parameters: list[dict], vulnerability_type: str) -> dict:
    """받은 입력 정보를 반환한다. 네트워크 요청이나 취약점 검증은 수행하지 않는다."""
    return {
        "tool": "analyze_endpoint_stub", "url": url, "method": method,
        "parameters": parameters, "vulnerability_type": vulnerability_type,
        "status": "stub", "verified": False,
        "message": "임시 모듈 호출 완료. 실제 취약점 검증은 수행하지 않았습니다.",
    }


# 파이썬 함수의 이름과 입력 형식을 AI에 알려주는 정의다.
TOOL_SCHEMA = {
    "type": "function",
    "name": "analyze_endpoint_stub",
    "description": "수집한 대표 엔드포인트 하나의 입력 정보를 받아 임시 처리 결과를 반환한다. 실제 검증은 하지 않는다.",
    "parameters": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "수집 결과에 있는 대표 URL"},
            "method": {"type": "string", "description": "해당 요청의 HTTP 메서드"},
            "vulnerability_type": {
                "type": "string", "enum": list(TOOL_LABELS),
                "description": "현재 대표 요청에 지정된 후보 도구 종류. 실제 검증은 수행하지 않는다.",
            },
            "parameters": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "location": {"type": "string"},
                    },
                    "required": ["name", "location"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["url", "method", "parameters", "vulnerability_type"],
        "additionalProperties": False,
    },
    "strict": True,
}
