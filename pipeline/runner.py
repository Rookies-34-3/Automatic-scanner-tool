from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


PIPELINE_VERSION = "1.1.0"
RESULT_VALUES = {"VULNERABLE", "PASS", "REVIEW", "ERROR"}
ADAPTERS = {
    "authn": {
        "directory": "authn-scanner",
        "endpoint_key": "tests",
        "output_argument": "--output-json",
        "module": "authn_scanner",
        "accepted_exit_codes": {0},
    },
    "authz": {
        "directory": "authz-scanner",
        "endpoint_key": "tests",
        "output_argument": "--output-json",
        "module": "authz_scanner",
        "accepted_exit_codes": {0},
    },
    "sqli": {
        "directory": "sqli",
        "endpoint_key": "targets",
        "output_argument": "--output",
        "script": "scanner.py",
        "accepted_exit_codes": {0, 2},
    },
}


class PipelineConfigError(ValueError):
    """Raised when the common configuration cannot be executed safely."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineConfigError(f"JSON 파일을 읽을 수 없습니다: {path}") from exc


def safe_repo_path(repo_root: Path, value: str) -> Path:
    candidate = (repo_root / value).resolve()
    if candidate != repo_root and repo_root not in candidate.parents:
        raise PipelineConfigError(f"저장소 밖의 경로는 사용할 수 없습니다: {value}")
    return candidate


def required_secret_names(scanner_id: str, scanner_config: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    if scanner_id == "authn":
        name = scanner_config.get("valid_credential", {}).get("password_env")
        if name:
            names.add(str(name))
    elif scanner_id == "authz":
        for account in scanner_config.get("accounts", {}).values():
            name = account.get("password_env") if isinstance(account, dict) else None
            if name:
                names.add(str(name))
    elif scanner_id == "sqli":
        name = scanner_config.get("password_env")
        if name:
            names.add(str(name))
    return names


def common_parameter_names(parameters: list[Any], location: str | None = None) -> list[str]:
    names: list[str] = []
    for parameter in parameters:
        if isinstance(parameter, str):
            name = parameter
            parameter_location = "query"
        elif isinstance(parameter, dict):
            name = str(parameter.get("name", ""))
            parameter_location = str(parameter.get("location", "query"))
        else:
            continue
        if name and (location is None or parameter_location == location):
            names.append(name)
    return names


def adapt_endpoints(
    scanner_id: str,
    endpoints: list[dict[str, Any]],
    target_base_url: str,
    existing_endpoints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Translate the common endpoint shape into an existing scanner's native config."""
    target_origin = urlsplit(target_base_url)
    existing_by_path = {
        str(item.get("path")): copy.deepcopy(item)
        for item in existing_endpoints
        if isinstance(item, dict) and item.get("path")
    }
    adapted: list[dict[str, Any]] = []
    for index, endpoint in enumerate(endpoints, start=1):
        if not isinstance(endpoint, dict):
            raise PipelineConfigError(f"{scanner_id}: endpoints[{index}]는 객체여야 합니다.")
        allowed_fields = {"url", "method", "parameters"}
        unexpected = sorted(set(endpoint) - allowed_fields)
        if unexpected:
            raise PipelineConfigError(
                f"{scanner_id}: endpoints[{index}] 공통 입력에는 url, method, parameters만 허용됩니다: "
                + ", ".join(unexpected)
            )
        url = str(endpoint.get("url", ""))
        parsed_url = urlsplit(url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise PipelineConfigError(f"{scanner_id}: endpoints[{index}].url은 전체 http(s) URL이어야 합니다.")
        if (parsed_url.scheme, parsed_url.netloc) != (target_origin.scheme, target_origin.netloc):
            raise PipelineConfigError(f"{scanner_id}: endpoints[{index}].url은 target과 같은 origin이어야 합니다.")
        path = parsed_url.path or "/"
        if not path.startswith("/"):
            raise PipelineConfigError(f"{scanner_id}: endpoints[{index}].url 경로가 올바르지 않습니다.")
        method = str(endpoint.get("method", "GET")).upper()
        parameters = endpoint.get("parameters", [])
        if not isinstance(parameters, list):
            raise PipelineConfigError(f"{scanner_id}: endpoints[{index}].parameters는 배열이어야 합니다.")

        native = existing_by_path.get(path, {"name": f"{scanner_id} {path}", "path": path})
        native["method"] = method
        native["path"] = path

        if scanner_id == "sqli":
            query_parameters = common_parameter_names(parameters, "query")
            if len(query_parameters) != 1:
                raise PipelineConfigError(
                    f"sqli: endpoints[{index}]에는 query parameters가 정확히 한 개 필요합니다."
                )
            adapted.append({"path": path, "parameter": query_parameters[0]})
            continue

        if scanner_id == "authz" and not {"owner_account", "attacker_account"}.issubset(native):
            raise PipelineConfigError(
                f"authz: {path}의 계정·객체 탐색 규칙은 기존 스캐너 config에 정의되어야 합니다."
            )
        adapted.append(native)
    return adapted


def prepare_runtime_config(
    repo_root: Path,
    runtime_dir: Path,
    target_base_url: str,
    entry: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    scanner_id = str(entry.get("id", ""))
    adapter = ADAPTERS.get(scanner_id)
    if adapter is None:
        raise PipelineConfigError(f"지원하지 않는 스캐너입니다: {scanner_id}")

    config_value = entry.get("config")
    if not config_value:
        raise PipelineConfigError(f"{scanner_id}: config 경로가 필요합니다.")
    source = safe_repo_path(repo_root, str(config_value))
    scanner_config = read_json(source)
    if not isinstance(scanner_config, dict):
        raise PipelineConfigError(f"{scanner_id}: 설정 최상위 값은 객체여야 합니다.")

    scanner_config["base_url"] = target_base_url.rstrip("/")
    if "endpoints" in entry:
        endpoints = entry["endpoints"]
        if not isinstance(endpoints, list) or not endpoints:
            raise PipelineConfigError(f"{scanner_id}: endpoints는 비어 있지 않은 배열이어야 합니다.")
        endpoint_key = str(adapter["endpoint_key"])
        existing_endpoints = scanner_config.get(endpoint_key, [])
        if not isinstance(existing_endpoints, list):
            raise PipelineConfigError(f"{scanner_id}: 기존 {endpoint_key} 설정이 배열이 아닙니다.")
        scanner_config[endpoint_key] = adapt_endpoints(
            scanner_id, endpoints, target_base_url, existing_endpoints
        )

    missing = sorted(name for name in required_secret_names(scanner_id, scanner_config) if not os.environ.get(name))
    if missing:
        raise PipelineConfigError(
            f"{scanner_id}: 필요한 환경변수가 없습니다: {', '.join(missing)}"
        )

    runtime_dir.mkdir(parents=True, exist_ok=True)
    destination = runtime_dir / f"{scanner_id}.json"
    destination.write_text(
        json.dumps(scanner_config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return destination, scanner_config


def normalize_status(value: Any) -> str:
    status = str(value or "REVIEW").upper()
    aliases = {
        "SAFE": "PASS",
        "N/A": "REVIEW",
        "NA": "REVIEW",
        "UNKNOWN": "REVIEW",
        "FAILED": "ERROR",
    }
    status = aliases.get(status, status)
    return status if status in RESULT_VALUES else "REVIEW"


def summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"total": len(findings), "vulnerable": 0, "pass": 0, "review": 0, "error": 0}
    for finding in findings:
        key = normalize_status(finding.get("result")).lower()
        summary[key] += 1
    return summary


def finding_parameters(finding: dict[str, Any], path: str) -> list[dict[str, str]]:
    parameters: list[dict[str, str]] = []
    supplied = finding.get("parameters")
    if isinstance(supplied, list):
        for parameter in supplied:
            if isinstance(parameter, str):
                parameters.append({"name": parameter, "location": "query"})
            elif isinstance(parameter, dict) and parameter.get("name"):
                parameters.append({
                    "name": str(parameter["name"]),
                    "location": str(parameter.get("location", "query")),
                })
    elif finding.get("parameter"):
        parameters.append({"name": str(finding["parameter"]), "location": "query"})

    existing = {(item["name"], item["location"]) for item in parameters}
    for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", path):
        if (name, "path") not in existing:
            parameters.append({"name": name, "location": "path"})
    return parameters


def normalize_finding(
    scanner_id: str,
    finding: dict[str, Any],
    target: str,
) -> dict[str, Any]:
    source = copy.deepcopy(finding)
    original_result = source.get("result")
    result = normalize_status(original_result)
    path = str(source.get("path") or source.get("target_url") or "/")
    url = path if path.startswith(("http://", "https://")) else target.rstrip("/") + "/" + path.lstrip("/")
    reason = str(source.get("reason") or source.get("evidence") or "판정 근거가 제공되지 않았습니다.")
    name = str(source.get("name") or f"{source.get('category', scanner_id)} {path}".strip())

    common_keys = {
        "name", "url", "path", "target_url", "method", "parameters", "parameter",
        "result", "severity", "reason", "evidence",
    }
    details = {key: value for key, value in source.items() if key not in common_keys}
    if original_result is not None and str(original_result).upper() != result:
        details["source_result"] = original_result
    return {
        "scanner_id": scanner_id,
        "name": name,
        "url": url,
        "method": str(source.get("method", "GET")).upper(),
        "parameters": finding_parameters(source, path),
        "result": result,
        "severity": str(source.get("severity", "NONE")),
        "reason": reason,
        "details": details,
    }


def normalize_result(scanner_id: str, raw: Any, target: str) -> dict[str, Any]:
    if isinstance(raw, list):
        source_findings = raw
        tool = "SQLiScanner" if scanner_id == "sqli" else f"{scanner_id}-scanner"
        version = "1.0.0"
        generated_at = utc_now()
    elif isinstance(raw, dict):
        source_findings = raw.get("findings", [])
        tool = raw.get("tool", f"{scanner_id}-scanner")
        version = raw.get("version", "unknown")
        generated_at = raw.get("generated_at", utc_now())
    else:
        raise PipelineConfigError(f"{scanner_id}: 결과는 JSON 객체 또는 배열이어야 합니다.")

    if not isinstance(source_findings, list):
        raise PipelineConfigError(f"{scanner_id}: findings는 배열이어야 합니다.")
    findings = [
        normalize_finding(scanner_id, item, target)
        for item in source_findings
        if isinstance(item, dict)
    ]
    return {
        "scanner_id": scanner_id,
        "tool": tool,
        "version": version,
        "generated_at": generated_at,
        "target": target,
        "summary": summarize(findings),
        "findings": findings,
    }


def error_result(scanner_id: str, target: str, reason: str) -> dict[str, Any]:
    finding = {
        "scanner_id": scanner_id,
        "name": f"{scanner_id} 실행 오류",
        "url": target,
        "method": "GET",
        "parameters": [],
        "result": "ERROR",
        "severity": "NONE",
        "reason": reason,
        "details": {},
    }
    return {
        "scanner_id": scanner_id,
        "tool": f"{scanner_id}-scanner",
        "version": "unknown",
        "generated_at": utc_now(),
        "target": target,
        "summary": summarize([finding]),
        "findings": [finding],
    }


def scanner_command(scanner_id: str, runtime_config: Path, output_path: Path) -> list[str]:
    adapter = ADAPTERS[scanner_id]
    if "module" in adapter:
        return [
            sys.executable,
            "-m",
            str(adapter["module"]),
            "--config",
            str(runtime_config),
            str(adapter["output_argument"]),
            str(output_path),
            "--authorized",
            "--no-fail-on-findings",
        ]
    return [
        sys.executable,
        str(adapter["script"]),
        "--config",
        str(runtime_config),
        str(adapter["output_argument"]),
        str(output_path),
    ]


def run_scanner(
    repo_root: Path,
    target: str,
    output_dir: Path,
    entry: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    scanner_id = str(entry.get("id", ""))
    started = time.monotonic()
    try:
        adapter = ADAPTERS.get(scanner_id)
        if adapter is None:
            raise PipelineConfigError(f"지원하지 않는 스캐너입니다: {scanner_id}")
        runtime_config, _ = prepare_runtime_config(
            repo_root, output_dir / "runtime-configs", target, entry
        )
        scanner_output = output_dir / f"{scanner_id}.json"
        scanner_output.unlink(missing_ok=True)
        working_directory = safe_repo_path(repo_root, str(adapter["directory"]))
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "utf-8"
        process = subprocess.run(
            scanner_command(scanner_id, runtime_config, scanner_output),
            cwd=working_directory,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
        if process.returncode not in adapter["accepted_exit_codes"]:
            message = (process.stderr or process.stdout or "출력 없음").strip()
            raise PipelineConfigError(
                f"프로세스 종료 코드 {process.returncode}: {message[-500:]}"
            )
        if not scanner_output.exists():
            raise PipelineConfigError("결과 JSON 파일이 생성되지 않았습니다.")
        result = normalize_result(scanner_id, read_json(scanner_output), target)
        result["execution"] = {
            "exit_code": process.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
        }
        scanner_output.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return result
    except subprocess.TimeoutExpired:
        return error_result(scanner_id, target, f"{timeout_seconds}초 실행 제한 시간을 초과했습니다.")
    except (OSError, PipelineConfigError) as exc:
        return error_result(scanner_id or "unknown", target, str(exc))


def aggregate_results(
    scan_id: str,
    target: str,
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for result in results:
        findings.extend(result.get("findings", []))
    summary = summarize(findings)
    if summary["vulnerable"]:
        overall_result = "VULNERABLE"
    elif summary["error"]:
        overall_result = "ERROR"
    elif summary["review"]:
        overall_result = "REVIEW"
    else:
        overall_result = "PASS"
    return {
        "pipeline": "ROOKIESCAN",
        "pipeline_version": PIPELINE_VERSION,
        "schema_version": "1.1",
        "scan_id": scan_id,
        "generated_at": utc_now(),
        "target": target,
        "result": overall_result,
        "summary": summary,
        "scanners": [
            {
                "scanner_id": result.get("scanner_id"),
                "tool": result.get("tool"),
                "summary": result.get("summary"),
                "execution": result.get("execution"),
            }
            for result in results
        ],
        "findings": findings,
        "ai_analysis": {
            "status": "NOT_CONFIGURED",
            "reason": "공통 AI 재판정·종합 분석 모듈 연결 전 단계입니다.",
        },
    }


def load_pipeline_config(path: Path) -> dict[str, Any]:
    config = read_json(path)
    if not isinstance(config, dict):
        raise PipelineConfigError("공통 설정 최상위 값은 객체여야 합니다.")
    target = config.get("target", {})
    if not isinstance(target, dict) or not str(target.get("base_url", "")).startswith(("http://", "https://")):
        raise PipelineConfigError("target.base_url에 http 또는 https URL이 필요합니다.")
    scanners = config.get("scanners")
    if not isinstance(scanners, list) or not scanners:
        raise PipelineConfigError("scanners는 비어 있지 않은 배열이어야 합니다.")
    scanner_ids: list[str] = []
    for entry in scanners:
        if not isinstance(entry, dict) or not entry.get("id"):
            raise PipelineConfigError("각 scanner 항목에는 id가 필요합니다.")
        scanner_id = str(entry["id"])
        if scanner_id not in ADAPTERS:
            raise PipelineConfigError(f"어댑터가 없는 스캐너입니다: {scanner_id}")
        endpoints = entry.get("endpoints")
        if not isinstance(endpoints, list) or not endpoints:
            raise PipelineConfigError(f"{scanner_id}: 공통 endpoints 입력이 필요합니다.")
        scanner_ids.append(scanner_id)
    if len(scanner_ids) != len(set(scanner_ids)):
        raise PipelineConfigError("scanner id는 중복될 수 없습니다.")
    return config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ROOKIESCAN 공통 스캐너 파이프라인")
    parser.add_argument("--config", required=True, help="공통 파이프라인 설정 JSON")
    parser.add_argument("--authorized", action="store_true", help="허가된 대상임을 확인")
    parser.add_argument("--only", help="실행할 스캐너 ID(쉼표 구분)")
    parser.add_argument("--sequential", action="store_true", help="병렬 실행 대신 순차 실행")
    parser.add_argument("--no-fail-on-findings", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not args.authorized:
        raise SystemExit("허가된 대상만 검사할 수 있습니다. --authorized 옵션이 필요합니다.")

    try:
        config_path = Path(args.config).resolve()
        repo_root = Path(__file__).resolve().parents[1]
        config = load_pipeline_config(config_path)
        target = str(config["target"]["base_url"]).rstrip("/")
        if not target.startswith(("http://", "https://")):
            raise PipelineConfigError("base URL은 http 또는 https로 시작해야 합니다.")
        execution = config.get("execution", {})
        output_value = str(execution.get("output_dir", "pipeline/results"))
        output_dir = safe_repo_path(repo_root, output_value)
        output_dir.mkdir(parents=True, exist_ok=True)
        timeout_seconds = float(execution.get("scanner_timeout_seconds", 180))
        if timeout_seconds <= 0 or timeout_seconds > 1800:
            raise PipelineConfigError("scanner_timeout_seconds는 0초 초과 1800초 이하여야 합니다.")

        selected = {item.strip() for item in args.only.split(",")} if args.only else None
        entries = [
            entry for entry in config["scanners"]
            if isinstance(entry, dict)
            and entry.get("enabled", True)
            and (selected is None or entry.get("id") in selected)
        ]
        if not entries:
            raise PipelineConfigError("실행할 스캐너가 없습니다.")

        parallel = bool(execution.get("parallel", True)) and not args.sequential
        if parallel and len(entries) > 1:
            results_by_id: dict[str, dict[str, Any]] = {}
            with ThreadPoolExecutor(max_workers=min(len(entries), 6)) as executor:
                futures = {
                    executor.submit(
                        run_scanner, repo_root, target, output_dir, entry, timeout_seconds
                    ): str(entry["id"])
                    for entry in entries
                }
                for future in as_completed(futures):
                    results_by_id[futures[future]] = future.result()
            results = [results_by_id[str(entry["id"])] for entry in entries]
        else:
            results = [
                run_scanner(repo_root, target, output_dir, entry, timeout_seconds)
                for entry in entries
            ]

        aggregate = aggregate_results("SCAN-" + uuid.uuid4().hex[:12], target, results)
        aggregate_path = (output_dir / str(execution.get("aggregate_file", "aggregate.json"))).resolve()
        if aggregate_path != output_dir and output_dir not in aggregate_path.parents:
            raise PipelineConfigError("aggregate_file은 결과 폴더 안에 있어야 합니다.")
        aggregate_path.write_text(
            json.dumps(aggregate, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(aggregate, ensure_ascii=False, indent=2))
    except (OSError, ValueError, PipelineConfigError) as exc:
        raise SystemExit(f"파이프라인 설정 오류: {exc}") from exc

    if aggregate["summary"]["error"]:
        raise SystemExit(1)
    if aggregate["summary"]["vulnerable"] and not args.no_fail_on_findings:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
