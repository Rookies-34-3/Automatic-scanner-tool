"""초기 stub 계약을 실제 스캐너 실행기로 연결하는 호환 계층.

main 브랜치에서 먼저 정의한 ``analyze_endpoint_stub`` 함수명과 입력 형식을
유지한다. 세션 쿠키와 스캐너별 추가 설정은 공개 Function 인자에 포함하지
않고 애플리케이션이 로컬 실행 시점에만 전달한다.
"""

from __future__ import annotations

from typing import Any

from .tool_registry import CANDIDATE_TOOL_NAMES, execute_tool


TOOL_LABELS = {
    "sqli": "SQL Injection", "xss": "XSS", "ssrf": "SSRF",
    "fileio": "파일 처리", "authn": "인증", "authz": "접근 권한",
    "admin_exposure": "관리자 페이지 노출",
    "directory_indexing": "디렉터리 인덱싱",
    "portscan": "불필요한 포트 노출",
}


def analyze_endpoint_stub(
    url: str,
    method: str,
    parameters: list[dict],
    vulnerability_type: str,
    *,
    session_cookie: Any = "",
    scanner_options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """stub 입력 계약을 보존하면서 해당 실제 스캐너를 실행한다."""
    names = CANDIDATE_TOOL_NAMES.get(vulnerability_type, set())
    if len(names) != 1:
        raise ValueError(f"등록되지 않은 취약점 후보입니다: {vulnerability_type}")
    return execute_tool(
        next(iter(names)),
        {"url": url, "method": method, "parameters": parameters},
        session_cookie=session_cookie,
        options=scanner_options,
    )


# 파이썬 함수의 이름과 입력 형식을 AI에 알려주는 정의다.
TOOL_SCHEMA = {
    "type": "function",
    "name": "analyze_endpoint_stub",
    "description": "수집한 대표 엔드포인트와 후보 유형을 받아 실제 취약점 스캐너를 실행합니다.",
    "parameters": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "수집 결과에 있는 대표 URL"},
            "method": {"type": "string", "description": "해당 요청의 HTTP 메서드"},
            "vulnerability_type": {
                "type": "string", "enum": list(TOOL_LABELS),
                "description": "현재 대표 요청에 지정된 취약점 검사 유형",
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
