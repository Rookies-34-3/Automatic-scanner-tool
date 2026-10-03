from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import ScanConfigError, load_config, run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authn-scanner",
        description="보호 API의 불충분한 인증 절차 자동 점검기",
    )
    parser.add_argument("--config", required=True, help="검사 설정 JSON 파일")
    parser.add_argument(
        "--output-json",
        help="선택 사항: JSON 결과를 저장할 파일 경로",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="요청 제한 시간(초)")
    parser.add_argument("--authorized", action="store_true", help="검사 권한 확인")
    parser.add_argument("--no-fail-on-findings", action="store_true")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not args.authorized:
        parser.error("허가된 대상만 검사할 수 있습니다. --authorized 옵션이 필요합니다.")
    if args.timeout <= 0 or args.timeout > 60:
        parser.error("timeout은 0초보다 크고 60초 이하여야 합니다.")
    try:
        result = run_scan(load_config(args.config), timeout=args.timeout)
    except ScanConfigError as exc:
        print(f"설정 오류: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    output = json.dumps(result, ensure_ascii=False, indent=2)
    print(output)
    if args.output_json:
        output_path = Path(args.output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")

    summary = result["summary"]
    if summary["vulnerable"] and not args.no_fail_on_findings:
        raise SystemExit(2)
