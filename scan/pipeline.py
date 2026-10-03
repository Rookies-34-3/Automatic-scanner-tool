"""ROOKIESCAN 공통 파이프라인 어댑터 (scan 모듈).

scan 전용 설정을 읽어
Port Scan / Directory Indexing / Admin Page Exposure
모듈을 실행하고, 최신 FileIO pipeline과 같은 공통 출력 형식으로 변환한다.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from scan.admin_exposure.scanner import run as run_admin_exposure
from scan.directory_indexing.scanner import run as run_directory_indexing
from scan.portscan.scanner import run as run_portscan


SCANNER_ID = "scan"

RESULT_MAP = {
    "VULNERABLE": "VULNERABLE",
    "SAFE": "PASS",
    "POTENTIAL": "REVIEW",
    "N/A": "REVIEW",
    "INFO": "REVIEW",
    "ERROR": "ERROR",
}


def _target_parameters(target):
    """공통 parameters 형식을 유지한다."""
    parameters = target.get("parameters", [])

    if isinstance(parameters, list):
        return parameters

    return []


def _common_finding(
    name,
    target,
    raw_finding,
    severity,
    scan_id,
    scanned_at,
):
    """개별 scanner 결과를 최신 공통 출력 형식으로 변환한다."""

    internal_result = raw_finding.get("vuln", "N/A")

    details = dict(raw_finding.get("details") or {})

    # 현재 scanner가 사용하는 내부 판정값 보존
    details.setdefault("internal_result", internal_result)

    # 공통 추적 정보
    details.setdefault("scan_id", scan_id)
    details.setdefault("scanned_at", scanned_at)

    # HTTP 응답 상태 코드 보존
    if raw_finding.get("status_code") is not None:
        details.setdefault(
            "status_code",
            raw_finding.get("status_code"),
        )

    # 사용한 payload가 있는 경우 보존
    if raw_finding.get("payload") is not None:
        details.setdefault(
            "payload",
            raw_finding.get("payload"),
        )

    return {
        "scanner_id": SCANNER_ID,
        "name": name,
        "url": raw_finding.get(
            "url",
            target.get("url", ""),
        ),
        "method": str(
            raw_finding.get(
                "method",
                target.get("method", "GET"),
            )
        ).upper(),
        "parameters": _target_parameters(target),
        "result": RESULT_MAP.get(
            internal_result,
            "REVIEW",
        ),
        "severity": severity,
        "reason": raw_finding.get(
            "result",
            "판정 근거 없음",
        ),
        "details": details,
    }


def _run_directory_indexing(config):
    findings = []

    module_config = config.get("directory_indexing", {})
    targets = module_config.get("targets", [])

    severity = (
        config.get("severity", {})
        .get("directory_indexing", "INFO")
    )

    for target in targets:
        raw = run_directory_indexing(
            target.get("url", ""),
            target.get("method", "GET"),
            target.get("parameters", []),
            {},
        )

        findings.append(
            ("Directory Indexing", target, raw, severity)
        )

    return findings


def _run_admin_exposure(config):
    findings = []

    module_config = config.get("admin_exposure", {})
    targets = module_config.get("targets", [])

    severity = (
        config.get("severity", {})
        .get("admin_exposure", "INFO")
    )

    for target in targets:
        raw = run_admin_exposure(
            target.get("url", ""),
            target.get("method", "GET"),
            target.get("parameters", []),
            {},
        )

        findings.append(
            ("Admin Page Exposure", target, raw, severity)
        )

    return findings


def _run_portscan(config):
    findings = []

    module_config = config.get("portscan", {})

    url = module_config.get(
        "url",
        config.get("base_url", ""),
    )

    parameters = {
        "ports": module_config.get("ports", [80]),
        "allowed_ports": module_config.get(
            "allowed_ports",
            [80],
        ),
        "timeout": module_config.get(
            "timeout",
            1,
        ),
    }

    severity = (
        config.get("severity", {})
        .get("portscan", "INFO")
    )

    target = {
        "url": url,
        "method": "SCAN",
        "parameters": [],
    }

    raw = run_portscan(
        url,
        "SCAN",
        parameters,
        {},
    )

    findings.append(
        ("Port Scan", target, raw, severity)
    )

    return findings


def run(config):
    """모든 scan 모듈을 실행하고 공통 결과 리스트를 반환한다."""

    scanned_at = datetime.now(timezone.utc).isoformat()

    raw_findings = []

    raw_findings.extend(
        _run_directory_indexing(config)
    )

    raw_findings.extend(
        _run_admin_exposure(config)
    )

    raw_findings.extend(
        _run_portscan(config)
    )

    findings = []

    for index, (
        name,
        target,
        raw,
        severity,
    ) in enumerate(raw_findings, 1):

        scan_id = f"SCAN-{index:03d}"

        findings.append(
            _common_finding(
                name=name,
                target=target,
                raw_finding=raw,
                severity=severity,
                scan_id=scan_id,
                scanned_at=scanned_at,
            )
        )

    return findings


def _replace_target_origin(url, base_url):
    """기존 endpoint의 경로는 유지하고 origin만 base_url로 교체한다."""

    target_parts = urlsplit(url)
    base_parts = urlsplit(base_url)

    return urlunsplit(
        (
            base_parts.scheme,
            base_parts.netloc,
            target_parts.path,
            target_parts.query,
            target_parts.fragment,
        )
    )


def override_base_url(config, base_url):
    """실행 시 입력한 base_url로 검사 대상 URL을 교체한다."""

    base_url = base_url.rstrip("/")
    parts = urlsplit(base_url)

    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(
            "base-url은 http:// 또는 https://로 시작하는 "
            "올바른 URL이어야 합니다."
        )

    if parts.query or parts.fragment:
        raise ValueError(
            "base-url에는 query string이나 fragment를 포함할 수 없습니다."
        )

    config["base_url"] = base_url

    # Directory Indexing 대상 URL 변경
    directory_config = config.get("directory_indexing", {})
    for target in directory_config.get("targets", []):
        if target.get("url"):
            target["url"] = _replace_target_origin(
                target["url"],
                base_url,
            )

    # Admin Exposure 대상 URL 변경
    admin_config = config.get("admin_exposure", {})
    for target in admin_config.get("targets", []):
        if target.get("url"):
            target["url"] = _replace_target_origin(
                target["url"],
                base_url,
            )

    # Port Scan 대상 host 변경
    portscan_config = config.get("portscan", {})
    portscan_config["url"] = base_url

    return config


def print_summary(findings, base_url):
    """PowerShell에서 사람이 읽기 쉬운 결과를 출력한다."""

    print()
    print("=" * 72)
    print(" ROOKIESCAN Scan Result")
    print(f" Target: {base_url}")
    print("=" * 72)

    for finding in findings:
        print()
        print(f"[{finding['name']}]")
        print(f"Result : {finding['result']}")
        print(f"URL    : {finding['url']}")
        print(f"Reason : {finding['reason']}")

        details = finding.get("details", {})

        if "status_code" in details:
            print(f"Status : {details['status_code']}")

        if finding["name"] == "Directory Indexing":
            indicators = details.get(
                "matched_indicators",
                [],
            )
            print(f"Found  : {indicators}")

        elif finding["name"] == "Admin Page Exposure":
            indicators = details.get(
                "matched_indicators",
                [],
            )
            print(f"Found  : {indicators}")

        elif finding["name"] == "Port Scan":
            print(
                f"Open   : "
                f"{details.get('open_ports', [])}"
            )
            print(
                f"Allowed: "
                f"{details.get('allowed_ports', [])}"
            )
            print(
                f"Unexpected: "
                f"{details.get('unexpected_ports', [])}"
            )

    vulnerable = sum(
        finding["result"] == "VULNERABLE"
        for finding in findings
    )

    passed = sum(
        finding["result"] == "PASS"
        for finding in findings
    )

    review = sum(
        finding["result"] == "REVIEW"
        for finding in findings
    )

    error = sum(
        finding["result"] == "ERROR"
        for finding in findings
    )

    print()
    print("=" * 72)
    print(" Summary")
    print(f" VULNERABLE : {vulnerable}")
    print(f" PASS       : {passed}")
    print(f" REVIEW     : {review}")
    print(f" ERROR      : {error}")
    print("=" * 72)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="ROOKIESCAN Scan vulnerability pipeline"
    )

    parser.add_argument(
        "--config",
        default=str(
            Path(__file__).with_name("config.json")
        ),
        help="scan 설정 JSON 경로",
    )

    parser.add_argument(
        "--output",
        default=str(
            Path(__file__).with_name("output") / "scan_findings.json"
        ),
        help="공통 결과 JSON 경로",
    )

    parser.add_argument(
        "--base-url",
        help=(
            "실행 시 검사 대상 서버의 기본 URL. "
            "config.json의 base_url을 덮어씁니다."
        ),
    )

    args = parser.parse_args()

    with open(
        args.config,
        encoding="utf-8-sig",
    ) as fp:
        config = json.load(fp)

    if args.base_url:
        config = override_base_url(
            config,
            args.base_url,
        )

    findings = run(config)

    output_path = Path(args.output)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            findings,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print_summary(
        findings,
        config.get("base_url", ""),
    )

    print(
        f"[scan] 공통 출력 "
        f"{len(findings)}건 저장: {output_path}"
    )

    has_vulnerable = any(
        finding["result"] == "VULNERABLE"
        for finding in findings
    )

    return 2 if has_vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())