from __future__ import annotations

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
    validate_authentication,
    validate_credential,
)


ALLOWED_METHODS = {"GET", "HEAD"}
DENIED_STATUSES = {401, 403, 404}
MAX_COMPARE_CHARS = 65_536


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

    accounts = config.get("accounts")
    if not isinstance(accounts, dict) or len(accounts) < 2:
        raise ScanConfigError("교차 검사를 위해 accounts에 두 개 이상의 계정이 필요합니다.")
    for name, account in accounts.items():
        if not isinstance(account, dict):
            raise ScanConfigError(f"계정 {name} 설정이 올바르지 않습니다.")
        validate_credential(authentication, account, f"계정 {name}")

    tests = config.get("tests")
    if not isinstance(tests, list) or not tests:
        raise ScanConfigError("tests에 한 개 이상의 검사 항목이 필요합니다.")
    for index, test in enumerate(tests, start=1):
        if not isinstance(test, dict):
            raise ScanConfigError(f"tests[{index}]는 객체여야 합니다.")
        for field in ("name", "path", "owner_account", "attacker_account"):
            if not test.get(field):
                raise ScanConfigError(f"tests[{index}]에 {field}가 필요합니다.")
        if not str(test["path"]).startswith("/") or str(test["path"]).startswith("//"):
            raise ScanConfigError(f"tests[{index}].path는 /로 시작해야 합니다.")
        method = str(test.get("method", "GET")).upper()
        if method not in ALLOWED_METHODS:
            raise ScanConfigError(
                f"tests[{index}]의 {method} 메서드는 허용되지 않습니다. "
                "안전한 기본 버전은 GET과 HEAD만 지원합니다."
            )
        if test["owner_account"] not in accounts:
            raise ScanConfigError(f"tests[{index}]의 owner_account가 존재하지 않습니다.")
        if test["attacker_account"] not in accounts:
            raise ScanConfigError(f"tests[{index}]의 attacker_account가 존재하지 않습니다.")
        discovery = test.get("discovery")
        if discovery is not None:
            if not isinstance(discovery, dict):
                raise ScanConfigError(f"tests[{index}].discovery는 객체여야 합니다.")
            if not discovery.get("path") or not discovery.get("regex"):
                raise ScanConfigError(
                    f"tests[{index}].discovery에 path와 regex가 필요합니다."
                )
            if not str(discovery["path"]).startswith("/"):
                raise ScanConfigError(
                    f"tests[{index}].discovery.path는 /로 시작해야 합니다."
                )
            try:
                re.compile(str(discovery["regex"]))
            except re.error as exc:
                raise ScanConfigError(
                    f"tests[{index}].discovery.regex가 올바르지 않습니다: {exc}"
                ) from exc


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
    target_url = base_url.rstrip("/") + rendered_path
    if query_params:
        target_url += "?" + urlencode(query_params, doseq=True)
    return target_url


def observe_request(
    url: str,
    method: str,
    context: AuthContext | None,
    timeout: float,
    extra_headers: dict[str, str] | None = None,
) -> HTTPObservation:
    headers = {
        "Accept": "*/*",
        "User-Agent": "AuthZScanner/2.0 (authorized-security-test)",
    }
    if extra_headers:
        headers.update({str(key): str(value) for key, value in extra_headers.items()})
    if context and context.bearer_token is not None:
        headers["Authorization"] = f"Bearer {context.bearer_token}"

    request = Request(url, headers=headers, method=method)
    opener = (
        context.opener(follow_redirects=False)
        if context is not None
        else build_opener(NoRedirectHandler())
    )
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
        parsed_json: Any = json.loads(text_body) if text_body else None
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
    owner: HTTPObservation, other: HTTPObservation, ignored_fields: list[str]
) -> float:
    if owner.json_body is not None and other.json_body is not None:
        owner_value = remove_ignored_fields(owner.json_body, ignored_fields)
        other_value = remove_ignored_fields(other.json_body, ignored_fields)
        owner_text = json.dumps(owner_value, ensure_ascii=False, sort_keys=True)
        other_text = json.dumps(other_value, ensure_ascii=False, sort_keys=True)
    else:
        owner_text = owner.text_body
        other_text = other.text_body
    if not owner_text and not other_text:
        return 1.0
    return round(SequenceMatcher(
        None,
        owner_text[:MAX_COMPARE_CHARS],
        other_text[:MAX_COMPARE_CHARS],
    ).ratio(), 4)


def matching_sensitive_fields(
    owner: HTTPObservation, other: HTTPObservation, fields: list[str]
) -> list[str]:
    return [
        field
        for field in fields
        if get_field(owner.json_body, field) is not None
        and get_field(owner.json_body, field) == get_field(other.json_body, field)
    ]


def evaluate_pair(
    label: str,
    owner: HTTPObservation,
    other: HTTPObservation,
    sensitive_fields: list[str],
    ignored_fields: list[str],
    similarity_threshold: float,
) -> dict[str, Any]:
    similarity = response_similarity(owner, other, ignored_fields)
    matched_fields = matching_sensitive_fields(owner, other, sensitive_fields)
    if other.status is None:
        outcome, severity = "ERROR", "INFO"
        reason = f"{label} 요청을 완료하지 못했습니다."
    elif other.status in DENIED_STATUSES:
        outcome, severity = "PASS", "NONE"
        reason = f"{label} 요청이 HTTP {other.status}로 차단되었습니다."
    elif 300 <= other.status < 400:
        location = (other.location or "").lower()
        if "login" in location or "signin" in location:
            outcome, severity = "PASS", "NONE"
            reason = f"{label} 요청이 로그인 페이지로 이동되어 차단되었습니다."
        else:
            outcome, severity = "REVIEW", "LOW"
            reason = f"{label} 요청이 다른 위치로 이동되어 확인이 필요합니다."
    elif 200 <= other.status < 300:
        outcome = "VULNERABLE"
        if matched_fields or similarity >= similarity_threshold:
            severity = "HIGH"
            reason = f"{label} 요청이 성공했고 소유자 응답과 동일한 보호 내용이 확인되었습니다."
        else:
            severity = "MEDIUM"
            reason = f"{label} 요청이 HTTP {other.status}로 성공하여 수동 검토가 필요합니다."
    else:
        outcome, severity = "REVIEW", "LOW"
        reason = f"{label} 요청에서 HTTP {other.status} 응답이 발생했습니다."
    return {
        "actor": label,
        "outcome": outcome,
        "severity": severity,
        "reason": reason,
        "similarity": similarity,
        "matched_sensitive_fields": matched_fields,
        "observation": other.public_dict(),
    }


def discover_variables(
    config: dict[str, Any],
    test: dict[str, Any],
    owner_context: AuthContext,
    timeout: float,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    variables = dict(test.get("variables", {}))
    discovery = test.get("discovery")
    if not isinstance(discovery, dict):
        return variables, None
    discovery_test = {
        "path": discovery["path"],
        "variables": variables,
        "query_params": discovery.get("query_params", {}),
    }
    url = build_url(config["base_url"], discovery_test)
    observation = observe_request(url, "GET", owner_context, timeout)
    if observation.status is None or not 200 <= observation.status < 300:
        raise ScanConfigError(
            f"{test['name']} 객체 ID 탐색 경로가 HTTP {observation.status}를 반환했습니다."
        )
    match = re.search(str(discovery["regex"]), observation.text_body)
    if not match:
        raise ScanConfigError(
            f"{test['name']} 객체 ID를 탐색하지 못했습니다. 소유자 테스트 데이터가 있는지 확인하세요."
        )
    variable = str(discovery.get("variable", "object_id"))
    if variable in match.groupdict():
        value = match.group(variable)
    elif match.lastindex:
        value = match.group(1)
    else:
        value = match.group(0)
    variables[variable] = value
    return variables, {
        "path": discovery["path"],
        "variable": variable,
        "found": True,
        "observation": observation.public_dict(),
    }


def scan_test(
    config: dict[str, Any],
    test: dict[str, Any],
    contexts: dict[str, AuthContext],
    timeout: float,
) -> dict[str, Any]:
    owner_name = str(test["owner_account"])
    attacker_name = str(test["attacker_account"])
    owner_context = contexts[owner_name]
    attacker_context = contexts[attacker_name]
    variables, discovery_result = discover_variables(
        config, test, owner_context, timeout
    )
    runtime_test = dict(test)
    runtime_test["variables"] = variables
    url = build_url(config["base_url"], runtime_test)
    method = str(test.get("method", "GET")).upper()
    headers = test.get("headers", {})
    sensitive_fields = [str(item) for item in test.get("sensitive_fields", [])]
    ignored_fields = [str(item) for item in test.get("ignore_fields", [])]
    threshold = float(test.get("similarity_threshold", 0.75))

    owner = observe_request(url, method, owner_context, timeout, headers)
    if owner.status is None or not 200 <= owner.status < 300:
        return {
            "scanner_id": "authz",
            "name": test["name"],
            "url": common_url(config, test),
            "method": method,
            "parameters": common_parameters(test),
            "vuln": "ERROR",
            "result": "소유자의 정상 기준 요청이 성공하지 않아 권한 비교를 중단했습니다.",
            "severity": "INFO",
            "details": {
                "owner_account": owner_name,
                "attacker_account": attacker_name,
                "discovery": discovery_result,
                "owner_observation": owner.public_dict(),
                "checks": [],
            },
        }

    attacker = observe_request(url, method, attacker_context, timeout, headers)
    checks = [
        evaluate_pair(
            f"다른 사용자({attacker_name})",
            owner,
            attacker,
            sensitive_fields,
            ignored_fields,
            threshold,
        )
    ]
    if test.get("check_anonymous", True):
        anonymous = observe_request(url, method, None, timeout, headers)
        checks.append(
            evaluate_pair(
                "비로그인 사용자",
                owner,
                anonymous,
                sensitive_fields,
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
        "scanner_id": "authz",
        "name": test["name"],
        "url": common_url(config, test),
        "method": method,
        "parameters": common_parameters(test),
        "vuln": result,
        "result": highest["reason"],
        "severity": highest["severity"],
        "details": {
            "owner_account": owner_name,
            "attacker_account": attacker_name,
            "discovery": discovery_result,
            "owner_observation": owner.public_dict(),
            "checks": checks,
        },
    }


def run_scan(config: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    """설정 객체를 검사하고 직렬화 가능한 결과를 반환한다."""
    validate_config(config)
    authentication = config.get("authentication", {"type": "bearer"})
    contexts = {
        str(name): build_auth_context(
            config["base_url"], authentication, account, f"계정 {name}", timeout
        )
        for name, account in config["accounts"].items()
    }
    findings = [
        scan_test(config, test, contexts, timeout) for test in config["tests"]
    ]
    summary = {
        "total": len(findings),
        "vulnerable": sum(item["vuln"] == "VULNERABLE" for item in findings),
        "pass": sum(item["vuln"] == "PASS" for item in findings),
        "review": sum(item["vuln"] == "REVIEW" for item in findings),
        "error": sum(item["vuln"] == "ERROR" for item in findings),
    }
    return {
        "tool": "AuthZScanner",
        "version": "3.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": config["base_url"],
        "authentication_type": authentication_type(authentication),
        "summary": summary,
        "findings": findings,
    }
