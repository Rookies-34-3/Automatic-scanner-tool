"""허가받은 ROOKIESCAN 실습 사이트의 검색 기능만 진단한다."""

import argparse
import getpass
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

# 일반적인 'error' 문구 대신 MySQL에 특화된 오류 흔적을 찾는다.
MYSQL_ERROR = re.compile(
    r"You have an error in your SQL syntax|"
    r"check the manual that corresponds to your MySQL server version|"
    r"(?:pymysql|MySQLdb)\.err\.\w+|"
    r"SQLSTATE\[42000\].{0,100}1064",
    re.IGNORECASE,
)
REMEDIATION = "사용자 입력을 SQL에 직접 연결하지 말고 파라미터 바인딩(Prepared Statement)을 적용하며, DB 오류 상세는 서버 로그에만 기록합니다."


class ScanError(Exception):
    """접근 실패와 판정 불가를 양호와 구분하기 위한 예외."""


def soup(response):
    # HTML의 input, 게시판 결과 영역 등을 선택할 수 있게 파싱한다.
    return BeautifulSoup(response.text, "html.parser")


def login_form(response):
    # 로그인 페이지가 200으로 반환되어도 로그인 실패로 인식한다.
    return soup(response).select_one('input[type="password"]') is not None


class Scanner:
    def __init__(self, config):
        self.config = config
        self.base = config["base_url"].rstrip("/") + "/"
        self.session = requests.Session()  # 로그인 쿠키를 이후 요청에도 유지한다.
        self.session.headers["User-Agent"] = "ROOKIESCAN-SQLi/1.0"

    def request(self, method, path, **kwargs):
        url = urljoin(self.base, path)
        # 설정 실수나 리다이렉트로 다른 서버에 로그인 정보가 전송되지 않게 한다.
        if urlsplit(url)[:2] != urlsplit(self.base)[:2]:
            raise ScanError("설정한 base_url과 다른 서버의 경로입니다.")
        time.sleep(self.config.get("delay", 0.2))
        try:
            return self.session.request(
                method, url, timeout=self.config.get("timeout", 10),
                allow_redirects=False, **kwargs,
            )
        except requests.RequestException as exc:
            # 예외 원문에는 URL 등이 포함되므로 오류 종류만 결과에 남긴다.
            raise ScanError(f"네트워크 요청 실패: {type(exc).__name__}") from exc

    def login(self, password):
        page = self.request("GET", self.config["login_path"])
        token = soup(page).select_one('input[name="csrf_token"]')
        if page.status_code != 200 or token is None or not token.get("value"):
            raise ScanError("로그인 페이지 또는 CSRF 토큰을 확인할 수 없습니다.")
        response = self.request("POST", self.config["login_path"], data={
            "userId": self.config["username"], "password": password,
            "csrf_token": token["value"],
        })
        if response.status_code not in (200, 302, 303) or login_form(response):
            raise ScanError("로그인 실패: 계정과 CSRF 설정을 확인하세요.")
        # 리다이렉트 자체를 성공으로 보지 않고 보호된 게시판 접근으로 검증한다.
        probe = self.request("GET", self.config["targets"][0]["path"])
        self.check_page(probe)

    @staticmethod
    def check_page(response):
        if response.status_code != 200 or login_form(response):
            raise ScanError(f"게시판 접근 실패 또는 세션 만료 (HTTP {response.status_code})")

    def result_text(self, response, payload):
        document = soup(response)
        selector = self.config.get("result_selector", "tbody")
        regions = document.select(selector)
        if not regions:
            raise ScanError(f"검색 결과 영역을 찾지 못했습니다. result_selector 확인: {selector}")
        # 검색창, 스크립트 및 반사된 페이로드를 비교에서 제외한다.
        for region in regions:
            for node in region.select("script, style, input, textarea"):
                node.decompose()
        text = " ".join(region.get_text(" ", strip=True) for region in regions)
        return " ".join(text.replace(payload, "").split()) if payload else " ".join(text.split())

    def scan(self, target, scan_id):
        finding = {
            "scan_id": scan_id, "category": "SQL Injection",
            "target_url": target["path"], "method": "GET",
            "parameter": target["parameter"], "payload": None,
            "status_code": None, "result": "N/A", "severity": "INFO",
            "evidence": "", "remediation": REMEDIATION,
            "details": {"base_url": self.base, "checks": []},
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

        def fetch(payload):
            response = self.request("GET", target["path"], params={target["parameter"]: payload})
            finding["status_code"] = response.status_code
            if 300 <= response.status_code < 500 or login_form(response):
                raise ScanError(f"인증·접근·리다이렉트 문제 (HTTP {response.status_code})")
            return response

        try:
            baseline = fetch("")
            self.check_page(baseline)
            if MYSQL_ERROR.search(baseline.text):
                raise ScanError("일반 요청에도 MySQL 오류가 있어 주입 효과를 구분할 수 없습니다.")
            # 오류 응답은 500일 수도 있으므로 오류 흔적을 HTTP 성공 여부보다 먼저 검사한다.
            for payload in ("'", "\""):
                responses = [fetch(payload), fetch(payload)]
                matches = [MYSQL_ERROR.search(r.text) for r in responses]
                if all(matches):
                    finding.update(result="VULNERABLE", severity="HIGH", payload=payload,
                                   evidence=f"반복 주입에서 MySQL 오류 노출: {matches[0].group(0)}")
                    finding["details"]["checks"].append({"type": "error", "confirmed": True})
                    return finding
                if any(matches):
                    raise ScanError("MySQL 오류가 한 번만 나타나 재현 여부를 확인하지 못했습니다.")
                for response in responses:
                    self.check_page(response)
            finding["details"]["checks"].append({"type": "error", "confirmed": False})
            base_text = self.result_text(baseline, "")
            if base_text != self.result_text(fetch(""), ""):
                raise ScanError("일반 검색 결과가 반복 요청에서 변합니다.")
            # LIKE '%입력%' 및 괄호로 감싼 LIKE 조건을 각각 지원한다.
            for prefix in ("%'", "%')"):
                true_payload = prefix + " AND 1=1 -- "
                false_payload = prefix + " AND 1=2 -- "
                values = []
                for payload in (true_payload, false_payload, true_payload, false_payload):
                    response = fetch(payload)
                    self.check_page(response)
                    if MYSQL_ERROR.search(response.text):
                        values = []  # 문법이 맞지 않는 변형은 Boolean 증거로 사용하지 않는다.
                        break
                    values.append(self.result_text(response, payload))
                if not values:
                    continue
                t1, f1, t2, f2 = values
                stable = t1 == t2 and f1 == f2
                confirmed = stable and t1 == base_text and t1 != f1
                finding["details"]["checks"].append({
                    "type": "boolean", "true_payload": true_payload,
                    "false_payload": false_payload, "true_length": len(t1),
                    "false_length": len(f1), "stable": stable, "confirmed": confirmed,
                })
                if confirmed:
                    finding.update(result="VULNERABLE", severity="HIGH", payload=true_payload,
                                   evidence="참 조건은 일반 검색 결과와 같고 거짓 조건과 다름. 두 차례 재현됨.")
                    return finding
                if not stable or t1 != f1:
                    raise ScanError("응답 차이가 불안정하거나 기준 결과와 맞지 않아 판정 보류")
            boolean_checks = [c for c in finding["details"]["checks"] if c["type"] == "boolean"]
            if not boolean_checks:
                raise ScanError("Boolean 페이로드에 대한 정상 응답을 확보하지 못했습니다.")
            finding.update(result="SAFE", evidence="실행한 Error/Boolean 검사 범위에서 SQL 인젝션 증거 미탐지")
        except ScanError as exc:
            finding["evidence"] = str(exc)
        return finding


def main():
    parser = argparse.ArgumentParser(description="ROOKIESCAN SQL 인젝션 진단")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--base-url", help="설정 파일의 base_url을 일시적으로 덮어씁니다.")
    parser.add_argument("--output", default="results/findings.json")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8-sig"))
    if args.base_url:
        config["base_url"] = args.base_url
    password = os.environ.get(config["password_env"]) or getpass.getpass("실습 계정 비밀번호: ")
    scanner = Scanner(config)
    scan_id = "SCAN-" + uuid.uuid4().hex[:12]
    try:
        scanner.login(password)
        findings = [scanner.scan(target, scan_id) for target in config["targets"]]
    except ScanError as exc:
        # 로그인 실패 시 실제 주입 요청은 보내지 않는다.
        findings = []
        for target in config["targets"]:
            findings.append({
                "scan_id": scan_id, "category": "SQL Injection", "target_url": target["path"],
                "method": "GET", "parameter": target["parameter"], "payload": None,
                "status_code": None, "result": "N/A", "severity": "INFO",
                "evidence": str(exc), "remediation": REMEDIATION,
                "details": {"phase": "login"}, "scanned_at": datetime.now(timezone.utc).isoformat(),
            })
    finally:
        scanner.session.close()
    output = json.dumps(findings, ensure_ascii=False, indent=2)
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 2 if any(f["result"] == "N/A" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
