"""각 취약점 모듈의 결과를 모아 최종 보고서를 작성할 모듈.

공통 finding과 대시보드 호환 results를 함께 가진 JSON을 기준 결과로 사용한다.
"""

import json
import re
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4


def save_sink_summary(summary: dict, target_url: str) -> Path:
    """Sink 집계 결과를 호스트별 고유 JSON 파일로 저장한다."""
    parts = urlsplit(target_url)
    host = re.sub(r"[^A-Za-z0-9.-]", "-", (parts.hostname or "target").encode("idna").decode("ascii"))
    if parts.port:
        host += f"-{parts.port}"
    output_dir = Path(__file__).resolve().parent / "output"
    output_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = output_dir / f"openai-sinks-{host}-{stamp}-{uuid4().hex[:8]}.json"
    with path.open("x", encoding="utf-8") as output:
        json.dump(summary, output, ensure_ascii=False, separators=(",", ":"))
    return path


SENSITIVE_KEY = re.compile(r"(?i)(?:password|passwd|secret|token|cookie|authorization|api[_-]?key)")


def redact_sensitive(value):
    """Remove credentials from any data written to the final report."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if SENSITIVE_KEY.search(str(key)) else redact_sensitive(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    return value


def build_scan_report(target_url: str, analysis: dict) -> dict:
    """Build the canonical finding list plus the dashboard-compatible grouped view."""
    findings = redact_sensitive(analysis.get("tool_results", []))
    grouped = OrderedDict()
    for finding in findings:
        key = (finding["url"], finding["method"], finding["scanner_id"])
        result = grouped.setdefault(key, {
            "url": finding["url"],
            "method": finding["method"],
            "scanner": finding["scanner_id"],
            "status": "completed",
            "vulnerable": False,
            "findings": [],
        })
        result["vulnerable"] = result["vulnerable"] or finding["vuln"] == "VULNERABLE"
        if finding["vuln"] == "ERROR":
            result["status"] = "error"
        if finding["vuln"] == "PASS":
            continue
        details = finding.get("details") or {}
        raw = details.get("raw_result")
        payload = details.get("payload")
        if payload is None and isinstance(raw, dict):
            payload = raw.get("payload")
        if payload is None and isinstance(raw, list):
            payload = next(
                (item.get("payload") for item in raw
                 if isinstance(item, dict) and item.get("payload")),
                None,
            )
        result["findings"].append({
            "type": finding["name"],
            "severity": finding["severity"],
            "parameter": ", ".join(item["name"] for item in finding["parameters"]),
            "payload": payload,
            "evidence": finding["result"],
            "description": finding["result"],
            "recommendation": details.get("remediation", "해당 기능의 입력 검증과 접근 제어를 적용하세요."),
            "vuln": finding["vuln"],
        })

    results = list(grouped.values())
    counts = {status: sum(item["vuln"] == status for item in findings)
              for status in ("VULNERABLE", "PASS", "REVIEW", "ERROR")}
    endpoint_count = len({(item["url"], item["method"]) for item in findings})
    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target_url,
        "summary": {
            "total_endpoints": endpoint_count,
            "total_scans": len(results),
            "total_findings": len(findings),
            "vulnerable_scans": sum(item["vulnerable"] for item in results),
            "vulnerable": counts["VULNERABLE"],
            "pass": counts["PASS"],
            "review": counts["REVIEW"],
            "error": counts["ERROR"],
        },
        "results": results,
        "findings": findings,
        "ai": {
            "model": analysis.get("model"),
            "summary": analysis.get("summary", ""),
            "summary_scope": analysis.get("summary_scope"),
            "summary_status": analysis.get("summary_status", "completed"),
            "summary_error": analysis.get("summary_error"),
            "tool_call_count": analysis.get("tool_call_count", 0),
        },
    }


def save_scan_report(report: dict, target_url: str) -> Path:
    """최신 최종 보고서를 output/scan-results.json에 저장하고 절대 경로를 반환한다."""
    output_dir = Path(__file__).resolve().parent / "output"
    output_dir.mkdir(exist_ok=True)
    path = output_dir / "scan-results.json"
    # 고정 파일명은 재검사 때 갱신한다. 직렬화 실패 시 기존 파일은 유지한다.
    serialized = json.dumps(redact_sensitive(report), ensure_ascii=False, indent=2)
    with path.open("w", encoding="utf-8") as output:
        output.write(serialized + "\n")
    return path
