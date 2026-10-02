"""CLI 진입점 (JSON 전용 버전).

사용:
  python -m fileio_scanner --config targets/sslc_lab_minimal.json
  python -m fileio_scanner --config targets/sslc_lab_minimal.json --out output/result.json
"""
import argparse
import json
import sys
from .engine import run_scan, write_json, print_summary


def main():
    ap = argparse.ArgumentParser(description="파일 업로드/다운로드 취약점 스캐너 (JSON 출력)")
    ap.add_argument("--config", "-c", required=True, help="타깃 설정 JSON 경로")
    ap.add_argument("--out", "-o", default=None, help="결과 JSON 출력 경로")
    args = ap.parse_args()

    # utf-8-sig: Windows 에서 저장 시 붙는 BOM 도 허용
    with open(args.config, encoding="utf-8-sig") as fp:
        cfg = json.load(fp)

    result = run_scan(cfg)
    print_summary(result)

    name = cfg.get("target_name", "scan")
    out = args.out or f"output/{name}_result.json"
    write_json(result, out)
    print(f"\n[+] JSON 저장: {out}  (findings {result['meta']['total']}건)")


if __name__ == "__main__":
    sys.exit(main())
