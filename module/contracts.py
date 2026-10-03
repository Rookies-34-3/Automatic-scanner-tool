"""Shared input/output contract for every ROOKIESCAN module."""

from __future__ import annotations

import json
import os
from typing import Any


VALID_VULN = {"VULNERABLE", "PASS", "REVIEW", "ERROR"}
VULN_ALIASES = {
    "SAFE": "PASS",
    "FALSE": "PASS",
    "TRUE": "VULNERABLE",
    "N/A": "REVIEW",
    "NA": "REVIEW",
    "POTENTIAL": "REVIEW",
    "SKIPPED": "REVIEW",
    "INFO": "REVIEW",
}


def normalize_parameters(parameters: Any) -> list[dict[str, Any]]:
    """Return parameters as [{name, location, optional value}, ...]."""
    if parameters is None:
        return []
    if isinstance(parameters, str):
        return [{"name": parameters, "location": "query"}]
    if isinstance(parameters, dict):
        return [
            {"name": str(name), "location": "query", "value": value}
            for name, value in parameters.items()
        ]
    if not isinstance(parameters, list):
        raise ValueError("parameters는 문자열, 객체 또는 목록이어야 합니다.")

    normalized = []
    for parameter in parameters:
        if isinstance(parameter, str):
            normalized.append({"name": parameter, "location": "query"})
            continue
        if not isinstance(parameter, dict) or not str(parameter.get("name", "")).strip():
            raise ValueError("각 parameter에는 name이 필요합니다.")
        item = {
            "name": str(parameter["name"]),
            "location": str(parameter.get("location", "query")),
        }
        if "value" in parameter:
            item["value"] = parameter["value"]
        normalized.append(item)
    return normalized


def public_parameters(parameters: Any) -> list[dict[str, str]]:
    """Drop runtime values before saving or sending findings to AI."""
    return [
        {"name": item["name"], "location": item["location"]}
        for item in normalize_parameters(parameters)
    ]


def parameter_values(parameters: Any) -> dict[str, Any]:
    """Build the request mapping expected by scanners that send form/query data."""
    return {
        item["name"]: item.get("value", "")
        for item in normalize_parameters(parameters)
    }


def cookie_dict(session_cookie: Any) -> dict[str, str]:
    """Convert a Cookie header or mapping without ever serializing it to output."""
    if session_cookie in (None, ""):
        return {}
    if isinstance(session_cookie, dict):
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in session_cookie.items()):
            raise ValueError("session_cookie의 이름과 값은 문자열이어야 합니다.")
        return dict(session_cookie)
    if not isinstance(session_cookie, str):
        raise ValueError("session_cookie는 문자열 또는 객체여야 합니다.")
    raw_cookie = session_cookie.strip()
    if not raw_cookie:
        return {}
    # The Streamlit UI intentionally accepts either a complete Cookie header or
    # only the session value.  Sink discovery already supported the value-only
    # form, so the scanner adapters must normalize it in the same way.
    if "=" not in raw_cookie:
        cookie_name = os.getenv(
            "ROOKIESCAN_SESSION_COOKIE_NAME", "sslc_lab_session"
        ).strip() or "sslc_lab_session"
        return {cookie_name: raw_cookie}
    parsed = {}
    for part in raw_cookie.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        if name.strip():
            parsed[name.strip()] = value.strip()
    return parsed


def cookie_header(session_cookie: Any) -> str:
    if isinstance(session_cookie, str):
        raw_cookie = session_cookie.strip()
        if "=" in raw_cookie:
            return raw_cookie
    return "; ".join(f"{name}={value}" for name, value in cookie_dict(session_cookie).items())


def normalize_vuln(value: Any) -> str:
    if isinstance(value, bool):
        return "VULNERABLE" if value else "PASS"
    normalized = str(value or "REVIEW").upper()
    normalized = VULN_ALIASES.get(normalized, normalized)
    return normalized if normalized in VALID_VULN else "REVIEW"


def _reason(raw: dict[str, Any]) -> str:
    value = raw.get("result", raw.get("reason", raw.get("evidence", "판정 근거가 없습니다.")))
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("evidence", "reason", "message"):
            if isinstance(value.get(key), str) and value[key]:
                return value[key]
    if isinstance(value, list):
        messages = [
            item.get("evidence") or item.get("reason")
            for item in value if isinstance(item, dict)
        ]
        messages = [message for message in messages if message]
        if messages:
            return " / ".join(messages)
    return json.dumps(value, ensure_ascii=False, default=str)


def normalize_finding(
    raw: dict[str, Any],
    *,
    scanner_id: str,
    name: str,
    fallback_url: str,
    fallback_method: str,
    fallback_parameters: Any,
) -> dict[str, Any]:
    """Normalize one team scanner result to the final shared schema."""
    if not isinstance(raw, dict):
        raise ValueError("스캐너 결과는 객체여야 합니다.")
    raw_vuln = raw.get("vuln", raw.get("result", "REVIEW"))
    details = dict(raw.get("details") or {})
    raw_result = raw.get("result")
    if isinstance(raw_result, (dict, list)):
        details.setdefault("raw_result", raw_result)
    for key in ("status_code", "scan_id", "category", "remediation"):
        if raw.get(key) is not None:
            details.setdefault(key, raw[key])
    return {
        "scanner_id": scanner_id,
        "name": str(raw.get("name") or raw.get("category") or name),
        "url": str(raw.get("url") or raw.get("target_url") or fallback_url),
        "method": str(raw.get("method") or fallback_method).upper(),
        "parameters": public_parameters(raw.get("parameters", fallback_parameters)),
        "vuln": normalize_vuln(raw_vuln),
        "result": _reason(raw),
        "severity": str(raw.get("severity") or ("HIGH" if normalize_vuln(raw_vuln) == "VULNERABLE" else "NONE")),
        "details": details,
    }


def review_finding(
    scanner_id: str,
    name: str,
    url: str,
    method: str,
    parameters: Any,
    result: str,
) -> dict[str, Any]:
    return normalize_finding(
        {"vuln": "REVIEW", "result": result, "severity": "INFO"},
        scanner_id=scanner_id,
        name=name,
        fallback_url=url,
        fallback_method=method,
        fallback_parameters=parameters,
    )
