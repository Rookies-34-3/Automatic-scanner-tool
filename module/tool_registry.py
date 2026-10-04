"""OpenAI function-tool schemas and the trusted local dispatcher."""

from __future__ import annotations

from typing import Any

from .contracts import normalize_parameters, review_finding
from .scanner_tools import SCANNERS


DESCRIPTIONS = {
    "scan_sqli": "SQL 오류 및 Boolean 응답 차이로 SQL Injection을 점검합니다.",
    "scan_reflected_xss": "입력값의 반사 위치와 인코딩 여부로 Reflected XSS를 점검합니다.",
    "scan_ssrf": "정상 폼으로 내부 URL을 요청하고 응답 증거로 SSRF를 점검합니다.",
    "scan_authn": "인증 및 비로그인 응답을 비교해 인증 절차 누락을 점검합니다.",
    "scan_authz": "서로 다른 계정의 객체 접근 결과를 비교해 IDOR/BOLA를 점검합니다.",
    "scan_fileio": "파일 업로드·다운로드의 확장자, 경로 및 접근 제어를 점검합니다.",
    "scan_admin_exposure": "비로그인 상태의 관리자 페이지 노출 여부를 점검합니다.",
    "scan_directory_indexing": "웹 서버의 디렉터리 목록 노출 여부를 점검합니다.",
    "scan_portscan": "허용 목록 밖의 접근 가능한 TCP 포트를 점검합니다.",
}


def _schema(name: str) -> dict[str, Any]:
    return {
        "type": "function",
        "name": name,
        "description": DESCRIPTIONS[name],
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Sink 탐색 결과에 포함된 HTTP(S) URL"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]},
                "parameters": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "location": {"type": "string", "enum": ["path", "query", "body", "form", "header"]},
                        },
                        "required": ["name", "location"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["url", "method", "parameters"],
            "additionalProperties": False,
        },
        "strict": True,
    }


TOOL_SCHEMAS = [_schema(name) for name in SCANNERS]
TOOL_SCHEMA_BY_NAME = {schema["name"]: schema for schema in TOOL_SCHEMAS}

CANDIDATE_TOOL_NAMES = {
    "sqli": {"scan_sqli"},
    "xss": {"scan_reflected_xss"},
    "ssrf": {"scan_ssrf"},
    "authn": {"scan_authn"},
    "authz": {"scan_authz"},
    "fileio": {"scan_fileio"},
    "admin_exposure": {"scan_admin_exposure"},
    "directory_indexing": {"scan_directory_indexing"},
    "portscan": {"scan_portscan"},
}


def candidate_function_names(candidate_tools: list[str]) -> set[str]:
    return {
        function_name
        for candidate in candidate_tools
        for function_name in CANDIDATE_TOOL_NAMES.get(candidate, set())
    }


def validate_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(arguments, dict) or set(arguments) != {"url", "method", "parameters"}:
        raise ValueError("함수 입력은 url, method, parameters만 포함해야 합니다.")
    if not isinstance(arguments["url"], str) or not arguments["url"].strip():
        raise ValueError("함수 입력 url이 올바르지 않습니다.")
    if not isinstance(arguments["method"], str):
        raise ValueError("함수 입력 method가 올바르지 않습니다.")
    method = arguments["method"].upper()
    if method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}:
        raise ValueError("지원하지 않는 HTTP 메서드입니다.")
    parameters = normalize_parameters(arguments["parameters"])
    if any(set(item) - {"name", "location", "value"} for item in parameters):
        raise ValueError("함수 입력 parameters가 올바르지 않습니다.")
    return {"url": arguments["url"], "method": method, "parameters": parameters}


def execute_tool(
    name: str,
    arguments: dict[str, Any],
    *,
    session_cookie: Any = "",
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Execute a registered scanner while keeping credentials outside AI arguments."""
    if name not in SCANNERS:
        raise ValueError(f"등록되지 않은 스캐너 함수입니다: {name}")
    clean = validate_arguments(arguments)
    try:
        findings = SCANNERS[name](
            **clean,
            session_cookie=session_cookie,
            options=options or {},
        )
    except Exception as exc:  # 스캐너 하나의 오류가 전체 파이프라인을 중단시키지 않는다.
        return [review_finding(
            name.removeprefix("scan_"),
            DESCRIPTIONS[name].split("을 점검합니다.")[0],
            clean["url"],
            clean["method"],
            clean["parameters"],
            f"스캐너 실행 오류({type(exc).__name__})로 판정하지 못했습니다.",
        ) | {"vuln": "ERROR", "severity": "INFO"}]
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise ValueError(f"{name}이 결과 목록을 반환하지 않았습니다.")
    return findings
