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
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

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
SQLI_FORM_TYPES = {"text", "search", "textarea", "email", "tel", "url", "select"}


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

    def follow_post_redirect(self, response, limit=3):
        """정상 POST 뒤의 동일 출처 301/302/303을 GET으로 따라간다."""
        for _ in range(limit):
            if response.status_code not in {301, 302, 303}:
                return response
            location = response.headers.get("Location")
            if not location:
                raise ScanError(f"POST 리다이렉트 위치가 없습니다 (HTTP {response.status_code})")
            redirect_url = urljoin(response.url, location)
            if urlsplit(redirect_url)[:2] != urlsplit(self.base)[:2]:
                raise ScanError("POST 리다이렉트가 검사 대상 밖을 가리킵니다.")
            response = self.request("GET", redirect_url)
        if response.status_code in {301, 302, 303}:
            raise ScanError("POST 리다이렉트가 너무 많이 반복됩니다.")
        return response

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

    def form_request_data(self, target):
        """POST 폼의 정상값을 구성해 검사 대상 필드만 나중에 교체할 수 있게 한다."""
        page = self.request("GET", target["path"])
        self.check_page(page)
        target_url = urljoin(self.base, target["path"])
        target_parts = urlsplit(target_url)
        forms = []
        for form in soup(page).select("form"):
            if form.get("method", "GET").upper() != "POST":
                continue
            action = urlsplit(urljoin(target_url, form.get("action") or target_url))
            if (action.scheme, action.netloc, action.path) == (
                target_parts.scheme, target_parts.netloc, target_parts.path,
            ):
                forms.append(form)
        form = next((item for item in forms if any(
            field.get("name") == target["parameter"] for field in item.select("[name]")
        )), forms[0] if len(forms) == 1 else None)
        if form is None:
            raise ScanError("POST 대상과 일치하는 폼을 찾지 못했습니다.")

        fields = {}
        target_type = None
        safe_values = {
            "email": "rookiescan@example.com", "tel": "010-0000-0000",
            "url": "https://example.com/", "number": "1",
        }
        for field in form.select("[name]"):
            if field.has_attr("disabled"):
                continue
            name = field["name"]
            if field.name == "input":
                kind = field.get("type", "text").lower()
            else:
                kind = (field.get("type") or ("submit" if field.name == "button" else field.name)).lower()
            if name == target["parameter"]:
                target_type = kind
            if kind in {"file", "reset", "button", "image"}:
                if kind == "file" and field.has_attr("required") and name != target["parameter"]:
                    raise ScanError(f"필수 파일 입력값이 필요합니다: {name}")
                continue
            if kind in {"checkbox", "radio"}:
                if field.has_attr("checked") or field.has_attr("required"):
                    fields.setdefault(name, field.get("value", "on"))
                continue
            if kind == "submit":
                if field.get("value"):
                    fields.setdefault(name, field["value"])
                continue
            if field.name == "select":
                options = [option for option in field.select("option:not([disabled])")]
                selected = next((option for option in options if option.has_attr("selected")), None)
                if selected is None:
                    selected = next((option for option in options if option.get("value", option.text)), None)
                fields[name] = selected.get("value", selected.text) if selected else ""
                continue
            value = field.get_text() if field.name == "textarea" else field.get("value", "")
            if not value and (field.has_attr("required") or kind in SQLI_FORM_TYPES):
                value = safe_values.get(kind, "ROOKIESCAN")
            fields[name] = value

        if target_type not in SQLI_FORM_TYPES:
            raise ScanError(f"{target['parameter']} 필드는 SQL 인젝션 문자열 검사 대상이 아닙니다.")
        csrf = next((value for name, value in fields.items() if "csrf" in name.lower()), None)
        if csrf is not None and not csrf:
            raise ScanError("POST 폼의 CSRF 토큰 값이 비어 있습니다.")
        return fields

    def result_text(self, response, payload):
        document = soup(response)
        region = document.body or document
        # tbody 존재 여부에 의존하지 않고 응답 본문 전체를 비교한다. 동적 입력값과
        # 공통 메뉴는 결과 차이로 오인하기 쉬우므로 텍스트 추출에서 제외한다.
        for node in region.select(
            "script, style, input, textarea, select, button, nav, header, footer"
        ):
            node.decompose()
        text = region.get_text(" ", strip=True)
        return " ".join(text.replace(payload, "").split()) if payload else " ".join(text.split())

    def scan(self, target, scan_id):
        finding = {
            "scan_id": scan_id, "category": "SQL Injection",
            "target_url": target["path"], "method": target.get("method", "GET"),
            "parameter": target["parameter"], "payload": None,
            "status_code": None, "result": "N/A", "severity": "INFO",
            "evidence": "", "remediation": REMEDIATION,
            "details": {"base_url": self.base, "checks": []},
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

        def fetch(payload):
            # 입력 방식만 선택합니다. 페이로드와 아래의 판정 조건은 기존 그대로입니다.
            method = target.get("method", "GET")
            request_data = self.form_request_data(target) if method == "POST" else {}
            if payload is not None:
                request_data[target["parameter"]] = payload
            options = {"params": request_data} if method == "GET" else {"data": request_data}
            response = self.request(method, target["path"], **options)
            if method == "POST":
                response = self.follow_post_redirect(response)
            finding["status_code"] = response.status_code
            # 정상 요청은 통과하지만 SQLi 문자열만 400/403/422로 거부되는 경우에는
            # 입력 검증이 동작한 증거로 사용하기 위해 응답을 호출부에 돌려준다.
            if payload not in (None, "") and response.status_code in {400, 403, 422}:
                return response
            if 300 <= response.status_code < 500 or login_form(response):
                raise ScanError(f"인증·접근·리다이렉트 문제 (HTTP {response.status_code})")
            return response

        boolean_started = False  # 추가 증거 수집 중 발생한 실패를 구분합니다.
        try:
            if (target.get("method", "GET") == "POST"
                    and "csrf" in target["parameter"].lower()):
                raise ScanError("CSRF 토큰은 요청 제어값이므로 SQL 인젝션 검사에서 제외했습니다.")
            baseline_payload = None if target.get("method", "GET") == "POST" else ""
            baseline = fetch(baseline_payload)
            self.check_page(baseline)
            if MYSQL_ERROR.search(baseline.text):
                raise ScanError("일반 요청에도 MySQL 오류가 있어 주입 효과를 구분할 수 없습니다.")
            # 오류 응답은 500일 수도 있으므로 오류 흔적을 HTTP 성공 여부보다 먼저 검사한다.
            for payload in ("'", "\""):
                responses = [fetch(payload), fetch(payload)]
                rejected = [response.status_code in {400, 403, 422} for response in responses]
                if all(rejected):
                    finding["details"]["checks"].append({
                        "type": "input_validation", "payload": payload,
                        "status_codes": [response.status_code for response in responses],
                        "confirmed": True,
                    })
                    continue
                if any(rejected):
                    raise ScanError("SQLi 입력 거부 응답이 반복되지 않아 판정을 보류합니다.")
                matches = [MYSQL_ERROR.search(r.text) for r in responses]
                if all(matches):
                    finding.update(result="VULNERABLE", severity="HIGH", payload=payload,
                                   evidence=f"반복 주입에서 MySQL 오류 노출: {matches[0].group(0)}")
                    finding["details"]["checks"].append({"type": "error", "confirmed": True})
                    # 오류 검사만 끝내고 Boolean 검사로 이어갑니다.
                    break
                if any(matches):
                    raise ScanError("MySQL 오류가 한 번만 나타나 재현 여부를 확인하지 못했습니다.")
                for response in responses:
                    self.check_page(response)
            else:
                finding["details"]["checks"].append({"type": "error", "confirmed": False})
            rejected_checks = [
                check for check in finding["details"]["checks"]
                if check["type"] == "input_validation" and check["confirmed"]
            ]
            if len(rejected_checks) == 2:
                statuses = sorted({
                    status for check in rejected_checks for status in check["status_codes"]
                })
                finding.update(
                    result="SAFE",
                    evidence=f"따옴표 SQLi 입력이 반복해서 HTTP {statuses} 응답으로 거부됨",
                )
                return finding
            boolean_started = True
            base_text = self.result_text(baseline, "")
            if base_text != self.result_text(fetch(baseline_payload), ""):
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
                    boolean_evidence = "참 조건은 일반 검색 결과와 같고 거짓 조건과 다름. 두 차례 재현됨."
                    if finding["result"] == "VULNERABLE":
                        # 기존 오류 증거와 대표 페이로드를 보존하고 추가 증거를 덧붙입니다.
                        finding["evidence"] += " / " + boolean_evidence
                    else:
                        finding.update(result="VULNERABLE", severity="HIGH", payload=true_payload,
                                       evidence=boolean_evidence)
                    return finding
                if not stable or t1 != f1:
                    raise ScanError("응답 차이가 불안정하거나 기준 결과와 맞지 않아 판정 보류")
            boolean_checks = [c for c in finding["details"]["checks"] if c["type"] == "boolean"]
            if not boolean_checks:
                raise ScanError("Boolean 페이로드에 대한 정상 응답을 확보하지 못했습니다.")
            # Boolean 증거가 없어도 앞서 확정한 오류 기반 취약 판정을 낮추지 않습니다.
            if finding["result"] != "VULNERABLE":
                finding.update(result="SAFE", evidence="실행한 Error/Boolean 검사 범위에서 SQL 인젝션 증거 미탐지")
        except ScanError as exc:
            if boolean_started:
                # 실패는 양호 증거가 아닙니다. 추가 검사 중단 사유를 별도 기록합니다.
                finding["details"]["checks"].append({
                    "type": "boolean", "confirmed": False,
                    "completed": False, "reason": str(exc),
                })
            if finding["result"] != "VULNERABLE":
                finding["evidence"] = str(exc)
        return finding


def format_finding(finding, url):
    """내부 판정 결과를 팀 공통 출력으로 변환합니다. 판정 자체는 바꾸지 않습니다."""
    details = dict(finding.get("details", {}))
    return {
        "url": url,
        "method": finding["method"],
        "parameters": finding["parameter"],
        "vuln": finding["result"],  # 기존 result(판정 문자열)는 이제 vuln입니다.
        "result": {  # 팀 포맷의 result는 상세 정보를 담는 객체입니다.
            **details,
            "payload": finding["payload"],
            "status_code": finding["status_code"],
            "evidence": finding["evidence"],
            "checks": details.get("checks", []),
        },
        "scan_id": finding["scan_id"],
        "category": finding["category"],
        "severity": finding["severity"],
        "scanned_at": finding["scanned_at"],
        "remediation": finding["remediation"],
    }


def run(url, method, parameters, cookie):
    """통합용 진입점. 로그인·입력창·출력·파일 저장 없이 결과 객체 하나를 반환합니다.

    parameters는 한 번에 점검할 파라미터 이름 문자열(예: "content")입니다.
    cookie는 {"session": "로그인된 쿠키 값"} 형태의 딕셔너리입니다.
    공통 로그인에서 session.cookies.get_dict()로 만들 수 있습니다.
    POST는 application/x-www-form-urlencoded 폼 방식입니다.
    입력 형식 오류는 ValueError, 접근/진단 실패는 vuln="N/A"로 구분합니다.
    """
    if not isinstance(url, str):
        raise ValueError("url은 HTTP(S) 절대 URL 문자열이어야 합니다.")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("url은 사용자 정보와 fragment가 없는 HTTP(S) 절대 URL이어야 합니다.")
    if not isinstance(method, str) or method.upper() not in ("GET", "POST"):
        raise ValueError("method는 GET 또는 POST여야 합니다.")
    method = method.upper()
    if not isinstance(parameters, str) or not parameters.strip():
        raise ValueError("parameters는 점검할 파라미터 이름 하나여야 합니다.")
    if not isinstance(cookie, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in cookie.items()
    ):
        raise ValueError("cookie는 쿠키 이름과 값을 문자열로 담은 딕셔너리여야 합니다.")

    # GET URL에 같은 파라미터가 이미 있으면 제거해 중복 전달을 막습니다.
    # 다른 쿼리 파라미터는 유지하고, POST에서는 원래 URL을 그대로 사용합니다.
    target_url = url
    if method == "GET":
        query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True)
                 if key != parameters]
        target_url = urlunsplit(parts._replace(query=urlencode(query)))
    scanner = Scanner({
        "base_url": f"{parts.scheme}://{parts.netloc}",
        "timeout": 10,
        "delay": 0.2,
    })
    try:
        # 이 호출에서만 쓰는 세션입니다. 쿠키는 결과나 로그에 포함하지 않습니다.
        scanner.session.cookies.update(cookie)
        target = {"path": target_url, "parameter": parameters, "method": method}
        finding = scanner.scan(target, "SCAN-" + uuid.uuid4().hex[:12])
        return format_finding(finding, url)
    finally:
        scanner.session.close()


def main():
    parser = argparse.ArgumentParser(description="ROOKIESCAN SQL 인젝션 진단")
    parser.add_argument("--config", default=str(Path(__file__).with_name("config.json")))
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
                "method": target.get("method", "GET"), "parameter": target["parameter"], "payload": None,
                "status_code": None, "result": "N/A", "severity": "INFO",
                "evidence": str(exc), "remediation": REMEDIATION,
                "details": {"phase": "login"}, "scanned_at": datetime.now(timezone.utc).isoformat(),
            })
    finally:
        scanner.session.close()
    # 직접 로그인하는 테스트 모드도 통합 모드와 같은 JSON 형식으로 출력합니다.
    findings = [format_finding(finding, urljoin(scanner.base, finding["target_url"]))
                for finding in findings]
    output = json.dumps(findings, ensure_ascii=False, indent=2)
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 2 if any(f["vuln"] == "N/A" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
