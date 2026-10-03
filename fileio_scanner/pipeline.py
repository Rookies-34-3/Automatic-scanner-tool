"""ROOKIESCAN 공통 파이프라인 어댑터 (fileio 스캐너).

공통 입력(url/method/parameters) + 자기 config(계정 등)를 받아 스캔하고,
공통 출력 스키마(finding-output.schema.json)로 결과를 쓴다.

실행 계약 (runner.py 가 서브프로세스로 호출):
  python -m fileio_scanner.pipeline --config <config.json> --output <result.json> \
         --authorized --no-fail-on-findings

config(native, 자기 설정) 예:
{
  "base_url": "http://127.0.0.1:8080",      # runner 가 target.base_url 로 덮어씀
  "login_path": "/login",
  "accounts": {                              # 비밀번호는 환경변수로
    "victim":   { "userId": "student1", "password_env": "ROOKIESCAN_PASSWORD" },
    "attacker": { "userId": "student2", "password_env": "ROOKIESCAN_PASSWORD" },
    "admin":    { "userId": "admin",    "password_env": "ROOKIESCAN_PASSWORD" }
  },
  "endpoints": [                             # runner 가 공통 입력으로 채움(선택)
    { "url": ".../my-class/board/write/qna", "method": "POST",
      "parameters": [ { "name": "file", "location": "body" } ] },
    { "url": ".../download/{id}", "method": "GET",
      "parameters": [ { "name": "id", "location": "path" } ] }
  ],
  "upload_path": "/my-class/board/write/qna",   # endpoints 없을 때 직접 지정(선택)
  "download": { "url_template": "/download/{id}", "id_range": [1, 200] },
  "ai": { "enabled": false }
}
"""
import argparse
import json
import os
import sys
from urllib.parse import urlsplit
from .engine import run_scan

SCANNER_ID = "fileio"

# 내부 판정값 → 공통 4값
RESULT_MAP = {
    "VULNERABLE": "VULNERABLE",
    "SAFE": "PASS",
    "POTENTIAL": "REVIEW",
    "SKIPPED": "REVIEW",
    "INFO": "REVIEW",
    "ERROR": "ERROR",
}
# 공통 parameters.location 추정
UPLOAD_HINT = ("Upload", "Extension", "MIME", "Magic", "Stored XSS", "SVG",
               "Path Traversal in Filename", "Filename", "Special File",
               "Broken Access Control")


def _password(account: dict) -> str:
    """account 에서 비밀번호 획득: password_env(환경변수) 우선, 없으면 password."""
    env = account.get("password_env")
    if env:
        return os.environ.get(env, "")
    return account.get("password", "")


def _path_of(url: str) -> str:
    try:
        p = urlsplit(url).path
        return p or "/"
    except Exception:
        return url


def resolve_config(native: dict) -> dict:
    """native(파이프라인) config → 내부 engine cfg 로 변환."""
    cfg = {
        "base_url": native.get("base_url", "").rstrip("/"),
        "login_path": native.get("login_path", "/login"),
        "verify_tls": native.get("verify_tls", True),
    }
    # 계정 → credentials (비밀번호는 env 에서)
    accounts = native.get("accounts") or {}
    creds = {}
    for role in ("victim", "attacker", "admin"):
        a = accounts.get(role)
        if isinstance(a, dict) and a.get("userId"):
            creds[role] = {"userId": a["userId"], "password": _password(a)}
    if creds:
        cfg["credentials"] = creds

    # 엔드포인트 → 업로드/다운로드 경로 유도 (공통 입력 우선, 없으면 직접 지정)
    upload_path = native.get("upload_path")
    download = native.get("download")
    for ep in native.get("endpoints") or []:
        url = ep.get("url", "")
        method = str(ep.get("method", "GET")).upper()
        path = _path_of(url)
        params = ep.get("parameters") or []
        has_path_param = any(p.get("location") == "path" for p in params if isinstance(p, dict))
        if method in ("POST", "PUT", "PATCH") and not upload_path:
            upload_path = path
        elif (method == "GET" and (has_path_param or "{" in path)) and not download:
            # /download/{id} 형태 → 템플릿화
            tpl = path if "{" in path else path.rstrip("/") + "/{id}"
            download = {"url_template": tpl, "id_range": native.get("id_range", [1, 200])}
    if upload_path:
        cfg["upload_path"] = upload_path
    if download:
        cfg["download"] = download

    # 선택: 관리자 전용 경로/접근제어 자원도 native 에서 그대로 전달
    for k in ("notice_path", "access_control", "access_controlled"):
        if native.get(k):
            cfg[k] = native[k]
    return cfg


def _location_for(finding: dict) -> str:
    cat = finding.get("category", "")
    if cat.startswith(("IDOR", "Path Traversal / LFI", "Missing Authentication (Download)",
                       "Content-Disposition", "MIME Sniffing")):
        return "path"  # 다운로드 id/경로
    if any(cat.startswith(h) for h in UPLOAD_HINT):
        return "body"  # 업로드 파일/폼
    return "query"


def to_common(finding: dict) -> dict:
    """내부 finding → 공통 finding-output 스키마."""
    param = finding.get("parameter") or ""
    parameters = [{"name": param, "location": _location_for(finding)}] if param else []
    details = dict(finding.get("details") or {})
    # 추적용 부가정보 보존
    for k in ("scan_id", "payload", "status_code"):
        if finding.get(k) is not None:
            details.setdefault(k, finding.get(k))
    return {
        "scanner_id": SCANNER_ID,
        "name": finding.get("category", "fileio finding"),
        "url": finding.get("target_url", ""),
        "method": str(finding.get("method", "GET")).upper(),
        "parameters": parameters,
        "result": RESULT_MAP.get(finding.get("result", ""), "REVIEW"),
        "severity": str(finding.get("severity", "NONE")),
        "reason": finding.get("evidence", "판정 근거 없음"),
        "details": details,
    }


def to_common_skip(skip: dict) -> dict:
    """건너뜀 항목 → 공통 스키마(REVIEW)."""
    return {
        "scanner_id": SCANNER_ID,
        "name": skip.get("category", "skipped"),
        "url": "",
        "method": "GET",
        "parameters": [],
        "result": "REVIEW",
        "severity": "INFO",
        "reason": "미수행: " + skip.get("reason", ""),
        "details": {"skip_id": skip.get("skip_id"), "skipped": True},
    }


def run(native: dict, include_skipped: bool = True) -> list:
    cfg = resolve_config(native)
    result = run_scan(cfg)
    out = [to_common(f) for f in result.get("findings", [])]
    if include_skipped:
        out += [to_common_skip(s) for s in result.get("skipped", [])]
    return out


def main():
    ap = argparse.ArgumentParser(description="fileio 스캐너 (ROOKIESCAN 파이프라인 어댑터)")
    ap.add_argument("--config", required=True, help="native config JSON")
    ap.add_argument("--output", required=True, help="공통 출력 JSON 경로")
    ap.add_argument("--authorized", action="store_true", help="허가된 대상 확인")
    ap.add_argument("--no-fail-on-findings", action="store_true")
    args = ap.parse_args()
    if not args.authorized:
        print("허가된 대상만 검사할 수 있습니다(--authorized 필요).", file=sys.stderr)
        return 1

    with open(args.config, encoding="utf-8-sig") as fp:
        native = json.load(fp)
    findings = run(native)
    with open(args.output, "w", encoding="utf-8") as fp:
        json.dump(findings, fp, ensure_ascii=False, indent=2)
    print(f"[fileio] 공통 출력 {len(findings)}건 저장: {args.output}")

    has_vuln = any(f["result"] == "VULNERABLE" for f in findings)
    if has_vuln and not args.no_fail_on_findings:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
