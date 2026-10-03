from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, build_opener

from .http_auth import (
    AuthContext,
    NoRedirectHandler,
    ScanConfigError,
    authentication_type,
    build_auth_context,
    perform_logout,
    resolve_value,
    validate_authentication,
    validate_credential,
)


ALLOWED_METHODS = {"GET", "HEAD"}
REJECTED_STATUSES = {401, 403, 404}


@dataclass
class HTTPObservation:
    status: int | None
    content_type: str
    body_size: int
    body_hash: str
    json_keys: list[str]
    location: str | None = None
    json_body: Any = None
    text_body: str = ""
    error: str | None = None

    def public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("json_body", None)
        data.pop("text_body", None)
        return data


@dataclass
class AuthenticationCase:
    name: str
    context: AuthContext | None = None
    cookie_override: str | None = None


def common_parameters(test: dict[str, Any]) -> list[dict[str, str]]:
    parameters: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in test.get("parameters", []):
        if not isinstance(item, dict) or not item.get("name"):
            continue
        key = (str(item["name"]), str(item.get("location", "query")))
        if key not in seen:
            seen.add(key)
            parameters.append({"name": key[0], "location": key[1]})
    for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", str(test["path"])):
        if (name, "path") not in seen:
            seen.add((name, "path"))
            parameters.append({"name": name, "location": "path"})
    for name in test.get("query_params", {}):
        key = (str(name), "query")
        if key not in seen:
            seen.add(key)
            parameters.append({"name": key[0], "location": key[1]})
    return parameters


def common_url(config: dict[str, Any], test: dict[str, Any]) -> str:
    return config["base_url"].rstrip("/") + str(test["path"])


def load_config(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
    except OSError as exc:
        raise ScanConfigError(f"설정 파일을 열 수 없습니다: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ScanConfigError(f"설정 파일이 올바른 JSON이 아닙니다: {exc}") from exc
    validate_config(config)
    return config


def validate_config(config: dict[str, Any]) -> None:
    base_url = config.get("base_url", "")
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ScanConfigError("base_url은 http:// 또는 https:// 형식이어야 합니다.")
    if parsed.username or parsed.password:
        raise ScanConfigError("base_url에 사용자 정보나 비밀번호를 포함할 수 없습니다.")

    authentication = config.get("authentication", {"type": "bearer"})
    if not isinstance(authentication, dict):
        raise ScanConfigError("authentication은 객체여야 합니다.")
    validate_authentication(authentication)

    credential = config.get("valid_credential")
    if not isinstance(credential, dict):
        raise ScanConfigError("정상 기준 요청을 위한 valid_credential이 필요합니다.")
    validate_credential(authentication, credential, "valid_credential")

    tests = config.get("tests")
    if not isinstance(tests, list) or not tests:
        raise ScanConfigError("tests에 한 개 이상의 보호 경로가 필요합니다.")
    for index, test in enumerate(tests, start=1):
        if not isinstance(test, dict) or not test.get("name") or not test.get("path"):
            raise ScanConfigError(f"tests[{index}]에 name과 path가 필요합니다.")
        if not str(test["path"]).startswith("/") or str(test["path"]).startswith("//"):
            raise ScanConfigError(f"tests[{index}].path는 /로 시작해야 합니다.")
        method = str(test.get("method", "GET")).upper()
        if method not in ALLOWED_METHODS:
            raise ScanConfigError(
                f"tests[{index}]의 {method} 메서드는 허용되지 않습니다. "
                "안전한 기본 버전은 GET과 HEAD만 지원합니다."
            )


def substitute_variables(template: str, variables: dict[str, Any], encode: bool) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in variables:
            raise ScanConfigError(f"템플릿 변수 {{{key}}}의 값이 없습니다.")
        value = str(variables[key])
        return quote(value, safe="") if encode else value

    return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", replace, template)


def build_url(base_url: str, test: dict[str, Any]) -> str:
    variables = test.get("variables", {})
    rendered_path = substitute_variables(str(test["path"]), variables, encode=True)
    query_params: dict[str, Any] = {}
    for key, value in test.get("query_params", {}).items():
        query_params[key] = (
            substitute_variables(value, variables, encode=False)
            if isinstance(value, str)
            else value
        )
    url = base_url.rstrip("/") + rendered_path
    if query_params:
        url += "?" + urlencode(query_params, doseq=True)
    return url


def observe_request(
    url: str,
    method: str,
    context: AuthContext | None,
    timeout: float,
    extra_headers: dict[str, str] | None = None,
    cookie_override: str | None = None,
) -> HTTPObservation:
    headers = {
        "Accept": "*/*",
        "User-Agent": "AuthNScanner/2.0 (authorized-security-test)",
    }
    if extra_headers:
        headers.update({str(key): str(value) for key, value in extra_headers.items()})
    if context and context.bearer_token is not None:
        headers["Authorization"] = f"Bearer {context.bearer_token}"
    if cookie_override is not None:
        headers["Cookie"] = cookie_override

    request = Request(url, headers=headers, method=method)
    opener = (
        context.opener(follow_redirects=False)
        if context is not None
        else build_opener(NoRedirectHandler())
    )
    status: int | None = None
    response_headers: Any = {}
    raw_body = b""
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            response_headers = response.headers
            raw_body = response.read(1_048_577)
    except HTTPError as exc:
        status = exc.code
        response_headers = exc.headers
        raw_body = exc.read(1_048_577)
    except (URLError, TimeoutError, OSError) as exc:
        return HTTPObservation(None, "", 0, "", [], error=str(exc))

    truncated = len(raw_body) > 1_048_576
    raw_body = raw_body[:1_048_576]
    text_body = raw_body.decode("utf-8", errors="replace")
    content_type = response_headers.get("Content-Type", "") if response_headers else ""
    location = response_headers.get("Location") if response_headers else None
    try:
        parsed_json = json.loads(text_body) if text_body else None
    except json.JSONDecodeError:
        parsed_json = None
    json_keys = sorted(parsed_json.keys()) if isinstance(parsed_json, dict) else []
    return HTTPObservation(
        status=status,
        content_type=content_type,
        body_size=len(raw_body),
        body_hash=hashlib.sha256(raw_body).hexdigest()[:16],
        json_keys=json_keys,
        location=location,
        json_body=parsed_json,
        text_body=text_body,
        error="응답 본문이 1MB를 초과하여 잘렸습니다." if truncated else None,
    )


def remove_ignored_fields(value: Any, ignored_fields: list[str]) -> Any:
    normalized = copy.deepcopy(value)
    if not isinstance(normalized, dict):
        return normalized
    for field_path in ignored_fields:
        parts = field_path.split(".")
        cursor: Any = normalized
        for part in parts[:-1]:
            if not isinstance(cursor, dict) or part not in cursor:
                cursor = None
                break
            cursor = cursor[part]
        if isinstance(cursor, dict):
            cursor.pop(parts[-1], None)
    return normalized


def get_field(value: Any, field_path: str) -> Any:
    cursor = value
    for part in field_path.split("."):
        if not isinstance(cursor, dict) or part not in cursor:
            return None
        cursor = cursor[part]
    return cursor


def response_similarity(
    valid: HTTPObservation, candidate: HTTPObservation, ignored_fields: list[str]
) -> float:
    if valid.json_body is not None and candidate.json_body is not None:
        valid_value = remove_ignored_fields(valid.json_body, ignored_fields)
        candidate_value = remove_ignored_fields(candidate.json_body, ignored_fields)
        valid_text = json.dumps(valid_value, ensure_ascii=False, sort_keys=True)
        candidate_text = json.dumps(candidate_value, ensure_ascii=False, sort_keys=True)
    else:
        valid_text = valid.text_body
        candidate_text = candidate.text_body
    if not valid_text and not candidate_text:
        return 1.0
    return round(SequenceMatcher(None, valid_text, candidate_text).ratio(), 4)


def matching_sensitive_fields(
    valid: HTTPObservation, candidate: HTTPObservation, fields: list[str]
) -> list[str]:
    return [
        field
        for field in fields
        if get_field(valid.json_body, field) is not None
        and get_field(valid.json_body, field) == get_field(candidate.json_body, field)
    ]


def matching_markers(
    valid: HTTPObservation, candidate: HTTPObservation, markers: list[str]
) -> list[str]:
    return [
        marker
        for marker in markers
        if marker in valid.text_body and marker in candidate.text_body
    ]


def base64url_json(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def jwt_test_cases(valid_token: str) -> list[tuple[str, str]]:
    parts = valid_token.split(".")
    if len(parts) != 3 or not all(parts[:2]):
        return []
    signature = parts[2]
    replacement = "A" if not signature.endswith("A") else "B"
    tampered_signature = signature[:-1] + replacement if signature else "A"
    return [
        ("JWT 서명 변조", f"{parts[0]}.{parts[1]}.{tampered_signature}"),
        ("JWT alg=none", f"{base64url_json({'alg': 'none', 'typ': 'JWT'})}.{parts[1]}."),
    ]


def authentication_cases(
    config: dict[str, Any], timeout: float
) -> tuple[AuthContext, list[AuthenticationCase]]:
    authentication = config.get("authentication", {"type": "bearer"})
    credential = config["valid_credential"]
    valid_context = build_auth_context(
        config["base_url"], authentication, credential, "valid_credential", timeout
    )
    if authentication_type(authentication) == "bearer":
        valid_token = valid_context.bearer_token or ""
        cases = [
            AuthenticationCase("인증정보 없음"),
            AuthenticationCase("빈 Bearer 토큰", AuthContext("bearer", "")),
            AuthenticationCase(
                "임의의 잘못된 토큰", AuthContext("bearer", "authn-scanner-invalid-token")
            ),
        ]
        cases.extend(
            AuthenticationCase(name, AuthContext("bearer", token))
            for name, token in jwt_test_cases(valid_token)
        )
        expired = config.get("expired_credential")
        if isinstance(expired, dict) and (expired.get("token") or expired.get("token_env")):
            cases.append(
                AuthenticationCase(
                    "만료된 토큰",
                    AuthContext(
                        "bearer",
                        resolve_value(expired, "token", "token_env", "expired_credential"),
                    ),
                )
            )
        return valid_context, cases

    cookie_name = str(authentication["session_cookie_name"])
    cases = [
        AuthenticationCase("세션 쿠키 없음"),
        AuthenticationCase("빈 세션 쿠키", cookie_override=f"{cookie_name}="),
        AuthenticationCase(
            "임의의 잘못된 세션 쿠키",
            cookie_override=f"{cookie_name}=authn-scanner-invalid-session",
        ),
    ]
    expired = config.get("expired_credential")
    if isinstance(expired, dict) and (
        expired.get("cookie") or expired.get("cookie_env")
    ):
        expired_cookie = resolve_value(
            expired, "cookie", "cookie_env", "expired_credential 세션 쿠키"
        )
        cases.append(
            AuthenticationCase(
                "만료된 세션 쿠키", cookie_override=f"{cookie_name}={expired_cookie}"
            )
        )
    if isinstance(authentication.get("logout"), dict):
        logged_out = build_auth_context(
            config["base_url"], authentication, credential, "로그아웃 검사 계정", timeout
        )
        perform_logout(logged_out, config["base_url"], authentication, timeout)
        cases.append(AuthenticationCase("로그아웃 처리된 세션", logged_out))
    return valid_context, cases


def evaluate_case(
    name: str,
    valid: HTTPObservation,
    candidate: HTTPObservation,
    sensitive_fields: list[str],
    required_markers: list[str],
    ignored_fields: list[str],
    similarity_threshold: float,
) -> dict[str, Any]:
    similarity = response_similarity(valid, candidate, ignored_fields)
    fields = matching_sensitive_fields(valid, candidate, sensitive_fields)
    markers = matching_markers(valid, candidate, required_markers)
    if candidate.status is None:
        outcome, severity, reason = "ERROR", "INFO", "요청을 완료하지 못했습니다."
    elif candidate.status in REJECTED_STATUSES:
        outcome, severity = "PASS", "NONE"
        reason = f"HTTP {candidate.status}로 인증이 거부되었습니다."
    elif 300 <= candidate.status < 400:
        location = (candidate.location or "").lower()
        if "login" in location or "signin" in location:
            outcome, severity = "PASS", "NONE"
            reason = "로그인 페이지로 이동되어 인증이 요구되었습니다."
        else:
            outcome, severity, reason = (
                "REVIEW",
                "LOW",
                "인증 실패 요청이 다른 위치로 이동되어 확인이 필요합니다.",
            )
    elif 200 <= candidate.status < 300:
        if fields or markers or similarity >= similarity_threshold:
            outcome, severity = "VULNERABLE", "HIGH"
            reason = "유효하지 않은 인증 상태에서 정상 응답과 동일한 보호 내용이 반환되었습니다."
        else:
            outcome, severity = "REVIEW", "MEDIUM"
            reason = "유효하지 않은 인증 상태에서 성공 응답이 반환됐지만 보호 내용 일치는 확인되지 않았습니다."
    else:
        outcome, severity = "REVIEW", "LOW"
        reason = f"HTTP {candidate.status} 응답이 발생해 인증 처리를 확인해야 합니다."
    return {
        "case": name,
        "outcome": outcome,
        "severity": severity,
        "reason": reason,
        "similarity": similarity,
        "matched_sensitive_fields": fields,
        "matched_markers": markers,
        "observation": candidate.public_dict(),
    }


def scan_test(
    config: dict[str, Any],
    test: dict[str, Any],
    valid_context: AuthContext,
    cases: list[AuthenticationCase],
    timeout: float,
) -> dict[str, Any]:
    url = build_url(config["base_url"], test)
    method = str(test.get("method", "GET")).upper()
    headers = test.get("headers", {})
    valid = observe_request(url, method, valid_context, timeout, headers)
    required_markers = [str(item) for item in test.get("required_markers", [])]
    missing_markers = [item for item in required_markers if item not in valid.text_body]
    if valid.status is None or not (200 <= valid.status < 300) or missing_markers:
        reason = "정상 세션을 사용한 기준 요청이 성공하지 않아 검사를 중단했습니다."
        if missing_markers:
            reason = "정상 기준 응답에서 required_markers를 찾지 못했습니다."
        return {
            "scanner_id": "authn",
            "name": test["name"],
            "url": common_url(config, test),
            "method": method,
            "parameters": common_parameters(test),
            "vuln": "ERROR",
            "result": reason,
            "severity": "INFO",
            "details": {
                "valid_observation": valid.public_dict(),
                "checks": [],
            },
        }

    sensitive_fields = [str(item) for item in test.get("sensitive_fields", [])]
    ignored_fields = [str(item) for item in test.get("ignore_fields", [])]
    threshold = float(test.get("similarity_threshold", 0.75))
    checks = []
    for case in cases:
        candidate = observe_request(
            url,
            method,
            case.context,
            timeout,
            headers,
            cookie_override=case.cookie_override,
        )
        checks.append(
            evaluate_case(
                case.name,
                valid,
                candidate,
                sensitive_fields,
                required_markers,
                ignored_fields,
                threshold,
            )
        )

    severity_order = {"NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4}
    highest = max(checks, key=lambda item: severity_order[item["severity"]])
    if any(item["outcome"] == "VULNERABLE" for item in checks):
        result = "VULNERABLE"
    elif any(item["outcome"] in {"REVIEW", "ERROR"} for item in checks):
        result = "REVIEW"
    else:
        result = "PASS"
    return {
        "scanner_id": "authn",
        "name": test["name"],
        "url": common_url(config, test),
        "method": method,
        "parameters": common_parameters(test),
        "vuln": result,
        "result": highest["reason"],
        "severity": highest["severity"],
        "details": {
            "valid_observation": valid.public_dict(),
            "checks": checks,
        },
    }


def run_scan(config: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    """설정 객체를 검사하고 직렬화 가능한 결과를 반환한다."""
    validate_config(config)
    valid_context, cases = authentication_cases(config, timeout)
    findings = [
        scan_test(config, test, valid_context, cases, timeout)
        for test in config["tests"]
    ]
    summary = {
        "total": len(findings),
        "vulnerable": sum(item["vuln"] == "VULNERABLE" for item in findings),
        "pass": sum(item["vuln"] == "PASS" for item in findings),
        "review": sum(item["vuln"] == "REVIEW" for item in findings),
        "error": sum(item["vuln"] == "ERROR" for item in findings),
    }
    return {
        "tool": "AuthNScanner",
        "version": "3.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": config["base_url"],
        "authentication_type": authentication_type(
            config.get("authentication", {"type": "bearer"})
        ),
        "summary": summary,
        "findings": findings,
    }
