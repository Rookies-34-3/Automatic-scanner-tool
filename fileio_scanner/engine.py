"""스캔 오케스트레이터.

타깃 설정을 받아 로그인 → 업로드 체크 → 다운로드 체크를 수행하고
scan_id 를 채번한 finding 리스트와 요약을 생성한다.
"""
import json
from datetime import datetime, timezone
from .client import Client
from . import checks_upload, checks_download, recon
from .finding import SEVERITY_ORDER, RESULT_ORDER, VULNERABLE, POTENTIAL


def run_scan(cfg, autodetect=True) -> dict:
    # 0) 자동 정찰: 빠진 값(필드명/확장자/다운로드패턴 등)을 코드가 채움
    if autodetect:
        try:
            cfg = recon.normalize(cfg)
            r = cfg.get("_recon", {})
            print(f"[recon] 로그인필드 {r.get('login_detected')}")
            print(f"[recon] 파일필드={r.get('upload_field')}  다운로드={r.get('download')}")
        except Exception as e:
            print(f"[recon] 자동 탐지 일부 실패(수동값 사용): {e}")

    findings = []

    # 1) 업로드 체크 (인증 세션)
    if cfg.get("upload"):
        c = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True),
                   proxy=cfg.get("proxy"))
        if c.login(cfg.get("auth")):
            findings += checks_upload.run(c, cfg)
        else:
            print("[!] 로그인 실패 - 업로드 체크 건너뜀")

    # 2) 다운로드 체크 (내부에서 다중 계정 세션 생성)
    if cfg.get("download"):
        findings += checks_download.run(cfg)

    # 3) scan_id 채번
    for i, f in enumerate(findings, 1):
        f.scan_id = f"SCAN-{i:03d}"

    # 4) 정렬 (취약 > 심각도 순)
    findings.sort(key=lambda f: (RESULT_ORDER.get(f.result, 9),
                                 SEVERITY_ORDER.get(f.severity, 9)))

    vuln = [f for f in findings if f.result == VULNERABLE]
    pot = [f for f in findings if f.result == POTENTIAL]

    return {
        "meta": {
            "target_name": cfg.get("target_name", ""),
            "base_url": cfg["base_url"],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "total": len(findings),
            "vulnerable": len(vuln),
            "potential": len(pot),
        },
        "findings": [f.to_dict() for f in findings],
    }


def write_json(result, path):
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)


def print_summary(result):
    m = result["meta"]
    print("\n" + "=" * 68)
    print(f"  스캔 요약  {m['target_name']}  ({m['base_url']})")
    print("=" * 68)
    print(f"  총 {m['total']}건  |  VULNERABLE {m['vulnerable']}  |  POTENTIAL {m['potential']}")
    print("-" * 68)
    for f in result["findings"]:
        if f["result"] in (VULNERABLE, POTENTIAL):
            print(f"  {f['scan_id']}  [{f['result']:<10}] [{f['severity']:<8}] "
                  f"{f['category']}")
            print(f"          {f['evidence']}")
