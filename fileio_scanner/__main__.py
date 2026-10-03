"""CLI 진입점 (JSON 전용 버전).

사용:
  python -m fileio_scanner --config targets/sslc_lab_minimal.json
  python -m fileio_scanner --config targets/sslc_lab_minimal.json --out output/result.json
"""
import argparse
import json
import os
import sys
from .engine import run_scan, write_json, print_summary


def _resolve_secrets(cfg):
    """비밀번호는 JSON 에 두지 않고 password_env(환경변수 이름)로만 둔다.
    설정에 password_env 가 있으면 해당 환경변수에서 실제 비번을 읽어 채운다."""
    # credentials 스타일: { role: {userId, password_env} }
    for acct in (cfg.get("credentials") or {}).values():
        if isinstance(acct, dict) and acct.get("password_env") and not acct.get("password"):
            acct["password"] = os.environ.get(acct["password_env"], "")
    # auth 스타일: { auth/attacker_auth/admin_auth: {password_env, fields:{userId}} }
    for key in ("auth", "attacker_auth", "admin_auth"):
        a = cfg.get(key)
        if isinstance(a, dict) and a.get("password_env"):
            fields = a.setdefault("fields", {})
            if not fields.get("password"):
                fields["password"] = os.environ.get(a["password_env"], "")
    return cfg


def main():
    ap = argparse.ArgumentParser(description="파일 업로드/다운로드 취약점 스캐너 (JSON 출력)")
    ap.add_argument("--config", "-c", required=True, help="타깃 설정 JSON 경로")
    ap.add_argument("--out", "-o", default=None, help="결과 JSON 출력 경로")
    args = ap.parse_args()

    # utf-8-sig: Windows 에서 저장 시 붙는 BOM 도 허용
    with open(args.config, encoding="utf-8-sig") as fp:
        cfg = json.load(fp)
    cfg = _resolve_secrets(cfg)

    result = run_scan(cfg)
    print_summary(result)

    name = cfg.get("target_name", "scan")
    out = args.out or f"output/{name}_result.json"
    write_json(result, out)
    print(f"\n[+] JSON 저장: {out}  (findings {result['meta']['total']}건)")


if __name__ == "__main__":
    sys.exit(main())
