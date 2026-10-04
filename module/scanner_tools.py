"""Thin adapters around the scanners delivered by each project member."""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import requests

from .authn_scanner import run_scan as run_authn_config
from .authz_scanner import run_scan as run_authz_config
from .contracts import (
    cookie_dict,
    cookie_header,
    normalize_finding,
    normalize_parameters,
    parameter_values,
    public_parameters,
    review_finding,
)
from .fileio_scanner.pipeline import run as run_fileio_native
from .scan.admin_exposure.scanner import run as run_admin_exposure_native
from .scan.directory_indexing.scanner import run as run_directory_indexing_native
from .scan.portscan.scanner import run as run_portscan_native
from .sqli.scanner import run as run_sqli_native
from .ssrf.scanner import SSRFScanner
from .xss.reflected_xss import ReflectedXSSScanner


Options = dict[str, Any] | None
DEFAULT_AUTH_TIMEOUT = 3.0
MAX_AUTH_COMPARE_CHARS = 65_536
SQLI_CONTROL_PARAMETER_NAMES = {
    "csrf", "csrf_token", "_csrf", "token",
    "action", "submit",
    "file", "files", "upload", "attachment", "taskresult",
    "is_secret",
}
SQLI_LOOKUP_PARAMETER = re.compile(
    r"(?i)^(?:q|query|search|keyword|content|term|filter|lookup|id|[a-z0-9]+_id)$"
)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc or parts.username or parts.password:
        raise ValueError("url은 사용자 정보가 없는 HTTP(S) 절대 URL이어야 합니다.")
    return f"{parts.scheme}://{parts.netloc}"


def _load_config(options: Options, key: str, env_name: str) -> dict[str, Any] | None:
    options = options or {}
    supplied = options.get(key)
    if isinstance(supplied, dict):
        return deepcopy(supplied)
    path = supplied if isinstance(supplied, str) else os.getenv(env_name, "").strip()
    if not path:
        return None
    with Path(path).open(encoding="utf-8-sig") as source:
        loaded = json.load(source)
    if not isinstance(loaded, dict):
        raise ValueError(f"{env_name} 설정은 JSON 객체여야 합니다.")
    return loaded


def _load_example_config(filename: str) -> dict[str, Any]:
    path = Path(__file__).resolve().parents[1] / "examples" / filename
    with path.open(encoding="utf-8-sig") as source:
        loaded = json.load(source)
    if not isinstance(loaded, dict):
        raise ValueError(f"{filename} 설정은 JSON 객체여야 합니다.")
    return loaded


def _inject_runtime_password(config: dict[str, Any], password: str) -> dict[str, Any]:
    """Put a UI-supplied lab password into an in-memory config only."""
    copied = deepcopy(config)
    for key in ("valid_credential",):
        credential = copied.get(key)
        if isinstance(credential, dict):
            credential.pop("password_env", None)
            credential["password"] = password
    accounts = copied.get("accounts")
    if isinstance(accounts, dict):
        for account in accounts.values():
            if isinstance(account, dict):
                account.pop("password_env", None)
                account["password"] = password
    return copied


def _normalize_many(
    raws: list[dict[str, Any]], scanner_id: str, name: str,
    url: str, method: str, parameters: Any,
) -> list[dict[str, Any]]:
    return [
        normalize_finding(
            raw,
            scanner_id=scanner_id,
            name=name,
            fallback_url=url,
            fallback_method=method,
            fallback_parameters=parameters,
        )
        for raw in raws
    ]


def _sqli_parameters(parameters: Any) -> list[dict[str, str]]:
    """SQL 문자열을 실제로 넣을 수 있는 쿼리·본문 필드만 반환한다."""
    usable = []
    seen = set()
    for parameter in normalize_parameters(parameters):
        name = parameter["name"]
        location = parameter["location"]
        key = (name, location)
        if (
            location not in {"query", "form", "body", "json"}
            or name.lower() in SQLI_CONTROL_PARAMETER_NAMES
            or SQLI_LOOKUP_PARAMETER.fullmatch(name) is None
            or key in seen
        ):
            continue
        seen.add(key)
        usable.append(parameter)
    return usable


def scan_sqli(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    method = method.upper()
    usable_parameters = _sqli_parameters(parameters)
    if method not in {"GET", "POST"}:
        return [review_finding(
            "sqli", "SQL Injection", url, method, usable_parameters or parameters,
            f"현재 SQLi 스캐너가 {method} 요청 본문을 구성하지 못해 검사를 보류했습니다.",
        )]
    findings = []
    for parameter in usable_parameters:
        raw = run_sqli_native(
            url, method, parameter["name"], cookie_dict(session_cookie),
        )
        raw["parameters"] = [parameter]
        findings.append(normalize_finding(
            raw,
            scanner_id="sqli",
            name="SQL Injection",
            fallback_url=url,
            fallback_method=method,
            fallback_parameters=[parameter],
        ))
    # Sink 분류와 별도로 한 번 더 거른다. 검사할 검색·조회 필드가 없으면
    # 판정 보류 결과를 추가하지 않고 이 도구 호출만 건너뛴다.
    return findings


def scan_reflected_xss(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    target = {
        "url": url,
        "method": method,
        "parameters": parameter_values(parameters),
        "session_cookie": cookie_header(session_cookie),
    }
    timeout = float((options or {}).get("timeout", 5))
    scanner = ReflectedXSSScanner(timeout=timeout)
    try:
        raw = scanner.scan(target)
    finally:
        scanner.session.close()
    raw["parameters"] = public_parameters(parameters)
    if any(
        "request error" in str(item.get("reason", "")).lower()
        for item in raw.get("result", []) if isinstance(item, dict)
    ):
        raw["vuln"] = "ERROR"
        raw["severity"] = "INFO"
    return [normalize_finding(
        raw,
        scanner_id="xss",
        name="Reflected XSS",
        fallback_url=url,
        fallback_method=method,
        fallback_parameters=parameters,
    )]


def scan_directory_indexing(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    raw = run_directory_indexing_native(url, method, public_parameters(parameters), cookie_dict(session_cookie))
    return _normalize_many([raw], "directory_indexing", "Directory Indexing", url, method, parameters)


def scan_admin_exposure(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    raw = run_admin_exposure_native(url, method, public_parameters(parameters), {})
    return _normalize_many([raw], "admin_exposure", "Administrator Page Exposure", url, method, parameters)


def scan_portscan(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    port_options = deepcopy((options or {}).get("portscan") or {})
    raw = run_portscan_native(url, method, port_options, {})
    raw["parameters"] = public_parameters(parameters)
    return _normalize_many([raw], "portscan", "Unexpected Open Port", url, method, parameters)


def scan_fileio(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    options = options if options is not None else {}
    native = _load_config(options, "fileio_config", "ROOKIESCAN_FILEIO_CONFIG")
    victim_cookies = cookie_dict(session_cookie)
    attacker_cookies = cookie_dict(options.get("authz_attacker_cookie", ""))
    if not native and victim_cookies:
        native = _load_example_config("fileio-config.example.json")
    if not native:
        return [review_finding(
            "fileio", "File Upload/Download", url, method, parameters,
            "파일 검사를 위한 사용자 A 세션 쿠키가 없습니다.",
        )]
    sessions = deepcopy(native.get("sessions") or {})
    if victim_cookies:
        sessions["victim"] = {"cookies": victim_cookies}
    if attacker_cookies:
        sessions["attacker"] = {"cookies": attacker_cookies}
    if not sessions.get("victim"):
        return [review_finding(
            "fileio", "File Upload/Download", url, method, parameters,
            "파일 검사를 위한 사용자 A 세션 쿠키가 없습니다.",
        )]
    native["sessions"] = sessions
    native.pop("accounts", None)
    native["base_url"] = _origin(url)

    # fileio is a scenario scanner: one run needs the upload form and the
    # download template together.  Replacing its configured endpoints with
    # every discovered URL made directory pages and stored files look like
    # upload forms, and repeated the same account scan for every sink.
    # Keep the complete configured scenario and run it once per target.
    if not native.get("endpoints") and not native.get("upload_path") and not native.get("download"):
        native["endpoints"] = [{
            "url": url,
            "method": method,
            "parameters": public_parameters(parameters),
        }]

    scan_key = native["base_url"]
    completed = options.setdefault("_fileio_completed_targets", set())
    if scan_key in completed:
        return []

    # Missing optional admin/private-resource scenarios are not findings.
    # The integrated report should contain only checks that actually ran.
    raws = run_fileio_native(native, include_skipped=False)
    completed.add(scan_key)
    adapted = []
    for raw in raws:
        item = dict(raw)
        item["vuln"] = raw.get("result", "REVIEW")
        item["result"] = raw.get("reason", "판정 근거가 없습니다.")
        adapted.append(item)
    return _normalize_many(adapted, "fileio", "File Upload/Download", url, method, parameters)


def _configured_auth_scan(
    runner: Callable[[dict[str, Any], float], dict[str, Any]],
    scanner_id: str,
    name: str,
    config: dict[str, Any],
    url: str,
    method: str,
    parameters: Any,
    timeout: float,
) -> list[dict]:
    config["base_url"] = _origin(url)
    result = runner(config, timeout=timeout)
    return _normalize_many(result.get("findings", []), scanner_id, name, url, method, parameters)


def _request(session: requests.Session, method: str, url: str, parameters: Any, timeout: float):
    values = parameter_values(parameters)
    kwargs = {"params": values} if method.upper() in {"GET", "HEAD"} else {"data": values}
    return session.request(method.upper(), url, timeout=timeout, allow_redirects=False, **kwargs)


def _blocked_response(response: requests.Response) -> str | None:
    if response.status_code in {401, 403, 404}:
        return f"HTTP {response.status_code}"
    if response.status_code in {301, 302, 303, 307, 308}:
        location = response.headers.get("Location", "").lower()
        if "login" in location or "signin" in location:
            return f"로그인 페이지 이동(HTTP {response.status_code})"
    return None


def _response_fingerprint(response: requests.Response) -> dict[str, Any]:
    import hashlib

    body = response.content[:1_048_576]
    return {
        "status": response.status_code,
        "body_size": len(response.content),
        "body_hash": hashlib.sha256(body).hexdigest()[:16],
    }


def scan_authn(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    options = options or {}
    timeout = float(options.get("auth_timeout", options.get("timeout", DEFAULT_AUTH_TIMEOUT)))
    config = _load_config(options, "authn_config", "ROOKIESCAN_AUTHN_CONFIG")
    if config:
        return _configured_auth_scan(
            run_authn_config, "authn", "Insufficient Authentication", config,
            url, method, parameters, timeout,
        )
    if not cookie_dict(session_cookie):
        return [review_finding(
            "authn", "Insufficient Authentication", url, method, parameters,
            "인증 요청과 비교할 세션 쿠키 또는 ROOKIESCAN_AUTHN_CONFIG가 없습니다.",
        )]
    if method.upper() not in {"GET", "HEAD"}:
        return [review_finding(
            "authn", "Insufficient Authentication", url, method, parameters,
            "상태를 변경할 수 있는 요청은 설정 기반 인증 검사에서만 실행합니다.",
        )]

    authenticated = requests.Session()
    anonymous = requests.Session()
    authenticated.cookies.update(cookie_dict(session_cookie))
    try:
        auth_response = _request(authenticated, method, url, parameters, timeout)
        anon_response = _request(anonymous, method, url, parameters, timeout)
    except requests.Timeout:
        return [review_finding(
            "authn", "Insufficient Authentication", url, method, parameters,
            f"응답 제한 시간 {timeout:g}초를 초과해 이 인증 검사를 건너뛰었습니다.",
        )]
    except requests.RequestException:
        return [review_finding(
            "authn", "Insufficient Authentication", url, method, parameters,
            "HTTP 요청 오류로 이 인증 검사를 건너뛰었습니다.",
        )]
    finally:
        authenticated.close()
        anonymous.close()

    location = anon_response.headers.get("Location", "").lower()
    if anon_response.status_code in {401, 403} or (
        anon_response.status_code in {301, 302, 303, 307, 308}
        and any(marker in location for marker in ("login", "signin"))
    ):
        vuln = "PASS"
        reason = f"비로그인 요청이 HTTP {anon_response.status_code}로 차단되었습니다."
    elif auth_response.status_code == anon_response.status_code == 200:
        similarity = SequenceMatcher(
            None,
            auth_response.text[:MAX_AUTH_COMPARE_CHARS],
            anon_response.text[:MAX_AUTH_COMPARE_CHARS],
        ).ratio()
        if len(auth_response.content) >= 80 and similarity >= 0.95:
            vuln = "VULNERABLE"
            reason = f"비로그인 응답이 인증 응답과 {similarity:.1%} 유사하여 보호 누락이 의심됩니다."
        else:
            vuln = "REVIEW"
            reason = f"비로그인 요청도 HTTP 200이지만 응답 유사도는 {similarity:.1%}로 수동 확인이 필요합니다."
    else:
        vuln = "REVIEW"
        reason = (
            f"인증 응답 HTTP {auth_response.status_code}, 비로그인 응답 HTTP "
            f"{anon_response.status_code}로 자동 판정이 어렵습니다."
        )
    raw = {
        "vuln": vuln,
        "result": reason,
        "details": {
            "authenticated_status": auth_response.status_code,
            "anonymous_status": anon_response.status_code,
        },
    }
    return _normalize_many([raw], "authn", "Insufficient Authentication", url, method, parameters)


def scan_authz(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    options = options or {}
    timeout = float(options.get("auth_timeout", options.get("timeout", DEFAULT_AUTH_TIMEOUT)))
    config = _load_config(options, "authz_config", "ROOKIESCAN_AUTHZ_CONFIG")
    if config:
        runtime_password = str(options.get("lab_password") or "")
        if runtime_password:
            config = _inject_runtime_password(config, runtime_password)
        return _configured_auth_scan(
            run_authz_config, "authz", "IDOR/BOLA", config,
            url, method, parameters, timeout,
        )

    attacker_cookie = options.get("authz_attacker_cookie", "")
    owner_cookies = cookie_dict(session_cookie)
    attacker_cookies = cookie_dict(attacker_cookie)
    if not owner_cookies or not attacker_cookies:
        return [review_finding(
            "authz", "IDOR/BOLA", url, method, parameters,
            "교차 계정 검사를 위한 다른 사용자 세션 쿠키 또는 ROOKIESCAN_AUTHZ_CONFIG가 없습니다.",
        )]
    if method.upper() not in {"GET", "HEAD"}:
        return [review_finding(
            "authz", "IDOR/BOLA", url, method, parameters,
            "상태 변경 요청은 설정 기반 교차 계정 검사에서만 실행합니다.",
        )]

    owner = requests.Session()
    attacker = requests.Session()
    anonymous = requests.Session()
    owner.cookies.update(owner_cookies)
    attacker.cookies.update(attacker_cookies)
    try:
        owner_response = _request(owner, method, url, parameters, timeout)
        attacker_response = _request(attacker, method, url, parameters, timeout)
        anonymous_response = _request(anonymous, method, url, parameters, timeout)
    except requests.Timeout:
        return [review_finding(
            "authz", "IDOR/BOLA", url, method, parameters,
            f"응답 제한 시간 {timeout:g}초를 초과해 이 권한 검사를 건너뛰었습니다.",
        )]
    except requests.RequestException:
        return [review_finding(
            "authz", "IDOR/BOLA", url, method, parameters,
            "HTTP 요청 오류로 이 권한 검사를 건너뛰었습니다.",
        )]
    finally:
        owner.close()
        attacker.close()
        anonymous.close()

    owner_blocked = _blocked_response(owner_response)
    attacker_blocked = _blocked_response(attacker_response)
    if owner_blocked or not 200 <= owner_response.status_code < 300:
        vuln = "REVIEW"
        severity = "INFO"
        reason = (
            f"소유자 기준 요청이 HTTP {owner_response.status_code}로 정상 응답하지 않아 "
            "교차 계정 비교를 완료하지 못했습니다."
        )
        similarity = 0.0
    elif attacker_blocked:
        vuln = "PASS"
        severity = "NONE"
        reason = f"다른 사용자 요청이 {attacker_blocked}로 차단되었습니다."
        similarity = 0.0
    elif 200 <= attacker_response.status_code < 300:
        similarity = SequenceMatcher(
            None,
            owner_response.text[:MAX_AUTH_COMPARE_CHARS],
            attacker_response.text[:MAX_AUTH_COMPARE_CHARS],
        ).ratio()
        if len(owner_response.content) >= 80 and similarity >= 0.90:
            vuln = "VULNERABLE"
            severity = "HIGH"
            reason = (
                f"다른 사용자 요청이 성공했고 소유자 응답과 {similarity:.1%} 유사하여 "
                "IDOR/BOLA가 확인되었습니다."
            )
        else:
            vuln = "REVIEW"
            severity = "MEDIUM"
            reason = (
                f"다른 사용자 요청이 HTTP {attacker_response.status_code}로 성공했지만 "
                f"응답 유사도는 {similarity:.1%}여서 수동 확인이 필요합니다."
            )
    else:
        vuln = "REVIEW"
        severity = "LOW"
        similarity = 0.0
        reason = f"다른 사용자 요청이 HTTP {attacker_response.status_code}를 반환했습니다."

    raw = {
        "vuln": vuln,
        "result": reason,
        "severity": severity,
        "details": {
            "comparison": "owner_vs_other_user",
            "similarity": round(similarity, 4),
            "owner": _response_fingerprint(owner_response),
            "attacker": _response_fingerprint(attacker_response),
            "anonymous": _response_fingerprint(anonymous_response),
            "anonymous_blocked": _blocked_response(anonymous_response),
        },
    }
    return _normalize_many([raw], "authz", "IDOR/BOLA", url, method, parameters)


def scan_ssrf(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    options = options or {}
    normalized = normalize_parameters(parameters)
    names = [item["name"] for item in normalized]
    parameter_name = next(
        (name for name in names if name.lower() in {"url", "uri", "link", "callback", "webhook"}),
        names[0] if names else "url",
    )
    scanner_input = {
        "url": url,
        "method": method,
        "parameters": parameter_values(normalized),
        "ssrf_parameter": parameter_name,
        "session_cookie": cookie_dict(session_cookie),
    }
    if options.get("ssrf_probe_url"):
        scanner_input["probe_url"] = options["ssrf_probe_url"]
    if options.get("ssrf_expected_markers"):
        markers = options["ssrf_expected_markers"]
        scanner_input["expected_markers"] = (
            [item.strip() for item in markers.split("|") if item.strip()]
            if isinstance(markers, str) else markers
        )
    scanner = SSRFScanner(scanner_input)
    try:
        raw = scanner.scan()
    finally:
        scanner.session.close()
    raw["parameters"] = public_parameters(normalized)
    return _normalize_many([raw], "ssrf", "Server-Side Request Forgery", url, method, parameters)


SCANNERS: dict[str, Callable[..., list[dict]]] = {
    "scan_sqli": scan_sqli,
    "scan_reflected_xss": scan_reflected_xss,
    "scan_ssrf": scan_ssrf,
    "scan_authn": scan_authn,
    "scan_authz": scan_authz,
    "scan_fileio": scan_fileio,
    "scan_admin_exposure": scan_admin_exposure,
    "scan_directory_indexing": scan_directory_indexing,
    "scan_portscan": scan_portscan,
}
