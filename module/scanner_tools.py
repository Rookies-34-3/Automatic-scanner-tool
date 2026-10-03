"""Thin adapters around the scanners delivered by each project member."""

from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout
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


def scan_sqli(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    findings = []
    for parameter in normalize_parameters(parameters):
        if parameter["location"] == "header":
            continue
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
    return findings or [review_finding(
        "sqli", "SQL Injection", url, method, parameters,
        "점검할 쿼리 또는 본문 파라미터가 없습니다.",
    )]


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
    native = _load_config(options, "fileio_config", "ROOKIESCAN_FILEIO_CONFIG")
    if not native:
        return [review_finding(
            "fileio", "File Upload/Download", url, method, parameters,
            "ROOKIESCAN_FILEIO_CONFIG가 없어 계정 기반 파일 검사를 수행하지 않았습니다.",
        )]
    native["base_url"] = _origin(url)
    native["endpoints"] = [{
        "url": url,
        "method": method,
        "parameters": public_parameters(parameters),
    }]
    raws = run_fileio_native(native)
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


def scan_authn(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    options = options or {}
    timeout = float(options.get("timeout", 5))
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
        similarity = SequenceMatcher(None, auth_response.text, anon_response.text).ratio()
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
    config = _load_config(options, "authz_config", "ROOKIESCAN_AUTHZ_CONFIG")
    if not config:
        return [review_finding(
            "authz", "IDOR/BOLA", url, method, parameters,
            "교차 계정 검사를 위한 ROOKIESCAN_AUTHZ_CONFIG가 없습니다.",
        )]
    return _configured_auth_scan(
        run_authz_config, "authz", "IDOR/BOLA", config,
        url, method, parameters, float(options.get("timeout", 5)),
    )


def scan_ssrf(url: str, method: str, parameters: Any, session_cookie: Any = "", options: Options = None) -> list[dict]:
    options = options or {}
    normalized = normalize_parameters(parameters)
    names = [item["name"] for item in normalized]
    parameter_name = next(
        (name for name in names if name.lower() in {"url", "uri", "link", "callback", "webhook"}),
        names[0] if names else "url",
    )
    values = parameter_values(normalized)
    values[parameter_name] = options.get("ssrf_probe_url", "http://internal-service:9000/health")
    scanner = SSRFScanner({
        "url": url,
        "method": method,
        "parameters": values,
        "ssrf_parameter": parameter_name,
        "session_cookie": cookie_dict(session_cookie),
    })
    try:
        # 팀원 코드의 진행 메시지는 통합 UI/JSON에 섞이지 않게 숨긴다.
        with redirect_stdout(io.StringIO()):
            raw = scanner.scan()
    finally:
        scanner.session.close()
    raw["parameters"] = public_parameters(parameters)
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
