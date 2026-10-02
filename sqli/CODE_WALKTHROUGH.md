# scanner.py 줄별 해설

## 검사 순서 보강

오류 취약 확정 시의 즉시 반환을 `break`로 바꿨습니다. 오류 검사 루프만 종료하고 Boolean 검사로 이어집니다. 루프의 `else`는 오류가 확정되지 않은 경우에만 error/confirmed=false를 추가합니다. 페이로드와 비교 기준은 변경하지 않았습니다.

`boolean_started`는 Boolean 준비·검사 단계에서 발생한 ScanError를 구분합니다. 이 단계가 중단되면 boolean/confirmed=false/completed=false와 reason을 남깁니다. SAFE 설정과 evidence 덮어쓰기는 이미 VULNERABLE인 경우 건너뜁니다. Boolean에서도 취약이 확인되면 기존 오류 증거에 설명을 덧붙이고 반환합니다. 아래 원래 줄별 설명에서 오류 확정 후 즉시 반환과 무조건 SAFE/evidence 갱신을 설명한 부분은 이 변경 사항으로 대체합니다.

## 통합 인터페이스 추가 사항

아래 기존 해설의 `finding["result"]`는 **내부 판정 자료 구조**입니다. 외부 run() 반환값과 CLI 출력에서는 `vuln`으로 변환합니다.

- `fetch()`의 `method`, `request_data`, `options`: GET은 params, POST는 data로 입력 위치만 선택합니다. 이후 탐지 로직은 유지합니다.
- `format_finding()`: 기존 판정 문자열을 vuln에, payload/status_code/evidence 및 details의 checks를 result 객체에 담습니다. 추가 메타데이터는 최상위에 유지합니다.
- `run(url, method, parameters, cookie)`: 입력 타입을 검사하고, GET의 중복 점검 파라미터를 제거하고, 독립적인 세션에 외부 쿠키를 넣습니다. 기존 scan() 호출 → 공통 출력 변환 → 세션 종료 순서입니다. 로그인·파일 저장·print는 하지 않습니다.
- `main()`: 기존 직접 로그인 흐름을 유지하고 저장 직전에 format_finding()을 적용합니다. 종료 코드도 result 대신 vuln을 확인합니다. config 기본 경로는 scanner.py 옆으로 고정했습니다.
- 사용 예제와 POST 제약은 README의 ‘통합용 함수’를 참고하세요. 아래 기존 main 설명 중 출력 전 변환 단계와 종료 코드 필드는 이 변경 사항을 우선합니다.

코드에 나오는 순서대로 설명합니다. 빈 줄은 가독성을 위한 것이고 `#`는 실행되지 않는 한국어 주석입니다. 여러 줄에 걸친 함수 호출·딕셔너리의 닫는 괄호는 해당 문장을 끝냅니다. 아래에서 이러한 괄호와 주석은 해당 문장에 묶어 설명합니다.

## 먼저 알아둘 문법

- `self`: 현재 Scanner 객체. 함수들 사이에서 설정과 세션을 공유할 때 사용합니다.
- `def`: 함수 정의. 들여쓴 부분이 함수의 내용입니다.
- `return`: 함수 실행을 끝내고 값을 돌려줍니다.
- `raise`: 정상 진행이 불가능하다는 예외를 발생시킵니다.
- `try / except`: 예외가 발생할 수 있는 실행과 그 예외 처리입니다.
- `dict[key]`: 딕셔너리에서 이름에 대응하는 값을 읽습니다.
- `None`: 값이 아직 없음을 뜻하며 JSON에서는 `null`이 됩니다.
- `f"...{값}..."`: 문자열 안에 값을 넣는 문법입니다.
- `[실행 for 항목 in 목록]`: 각 항목을 처리하여 새 목록을 만드는 리스트 컴프리헨션입니다.

## 모듈과 상수

- 첫 `"""..."""`: 파일의 용도를 설명하는 문서 문자열입니다.
- `import argparse`: 실행 옵션을 해석하는 표준 모듈입니다.
- `import getpass`: 비밀번호를 화면에 표시하지 않고 입력받습니다.
- `import json`: JSON 읽기와 쓰기를 제공합니다.
- `import os`: 비밀번호 환경 변수를 읽습니다.
- `import re`: 정규표현식으로 DB 오류 흔적을 찾습니다.
- `import time`: 요청 간 대기를 제공합니다.
- `import uuid`: 실행별 식별자를 생성합니다.
- `from datetime import datetime, timezone`: 시간과 UTC 시간대 기능을 가져옵니다.
- `from pathlib import Path`: 파일 경로, 읽기, 저장을 다룹니다.
- `from urllib.parse import urljoin, urlsplit`: URL 결합과 분해를 제공합니다.
- `import requests`: HTTP 요청과 쿠키 세션을 제공합니다.
- `from bs4 import BeautifulSoup`: HTML을 파싱하고 원하는 태그를 찾습니다.
- `MYSQL_ERROR = re.compile(`: 여러 번 사용할 오류 검색 규칙을 준비합니다.
- `r"You have an error ...|"`: MySQL SQL 문법 오류 문구를 찾습니다. 끝의 `|`는 '또는'입니다.
- `r"check the manual ...|"`: MySQL 설명서 참조 문구도 찾습니다.
- `r"(?:pymysql|MySQLdb)..."`: Python MySQL 드라이버의 예외 표시를 찾습니다. `\w+`는 이름에 쓰이는 문자가 하나 이상이라는 뜻입니다.
- `r"SQLSTATE...1064"`: SQLSTATE와 MySQL 문법 오류 코드의 조합을 찾습니다.
- `re.IGNORECASE`: 대문자와 소문자 차이를 무시합니다.
- `REMEDIATION = ...`: 모든 결과에 넣을 고정 대응 문구입니다. AI 호출은 없습니다.

## ScanError와 HTML 보조 함수

- `class ScanError(Exception)`: 이 도구의 진단 실패를 표현하는 예외 형식을 정의합니다.
- 내부 문서 문자열: 실패를 SAFE로 처리하지 않으려는 목적을 설명합니다.
- `def soup(response)`: HTTP 응답을 입력받는 HTML 파싱 함수를 정의합니다.
- `return BeautifulSoup(response.text, "html.parser")`: 응답 본문을 HTML 객체로 변환합니다.
- `def login_form(response)`: 응답이 로그인 화면처럼 보이는지 검사합니다.
- `return soup(...).select_one(...) is not None`: password 입력란이 있으면 True를 반환합니다. 이는 이 실습 사이트를 위한 휴리스틱이며 모든 사이트의 로그인 상태를 증명하는 검사는 아닙니다.

## Scanner 초기화

- `class Scanner`: 로그인과 진단 기능을 한 객체로 묶습니다.
- `def __init__(self, config)`: 객체를 만들 때 자동으로 호출됩니다.
- `self.config = config`: 설정을 저장합니다.
- `self.base = ...rstrip("/") + "/"`: 기본 URL 끝의 슬래시를 하나로 맞춥니다.
- `self.session = requests.Session()`: 요청들 사이에서 쿠키를 유지합니다.
- `self.session.headers["User-Agent"] = ...`: 서버 로그에서 도구의 요청을 식별할 이름입니다.

## request: 공통 HTTP 요청

- `def request(self, method, path, **kwargs)`: GET/POST, 대상 경로, 추가 옵션을 받습니다. `**kwargs`에는 검색 파라미터나 로그인 폼 데이터가 들어갑니다.
- `url = urljoin(self.base, path)`: 기본 URL과 경로를 결합합니다.
- `if urlsplit(url)[:2] != ...`: 프로토콜과 서버 주소가 설정한 대상과 같은지 확인합니다.
- `raise ScanError(...)`: 다른 서버를 가리키면 요청 전에 중단합니다.
- `time.sleep(self.config.get("delay", 0.2))`: 설정된 간격만큼 쉽니다. 설정이 없으면 0.2초입니다.
- `try`: 네트워크 오류 처리 범위를 시작합니다.
- `return self.session.request(`: 세션을 사용해 요청하고 응답을 돌려줍니다.
- `method, url, timeout=...`: HTTP 메서드, URL, 대기 제한을 지정합니다. timeout은 전체 실행의 시간 제한이 아니라 연결·읽기 대기 제한입니다.
- `allow_redirects=False, **kwargs`: 리다이렉트를 자동으로 따라가지 않고, 전달받은 폼·검색 옵션을 적용합니다.
- `except requests.RequestException as exc`: 연결 실패, 타임아웃 등의 Requests 예외를 받습니다.
- `raise ScanError(...) from exc`: 오류 종류만 담은 도구 예외로 변환합니다. 원래 예외와의 관계는 유지합니다.

## login: CSRF와 로그인

- `def login(self, password)`: 비밀번호를 받아 로그인합니다.
- `page = self.request("GET", ...)`: 로그인 페이지와 초기 쿠키를 받습니다.
- `token = soup(page).select_one(...)`: 이름이 csrf_token인 input을 찾습니다.
- `if page.status_code != 200 or ...`: HTTP 실패·토큰 누락·빈 토큰을 검사합니다.
- `raise ScanError(...)`: 토큰을 얻지 못하면 로그인 POST를 하지 않습니다.
- `response = self.request("POST", ..., data={...})`: 같은 세션에서 로그인 폼을 보냅니다.
- `"userId": ..., "password": ...`: 설정된 계정과 입력받은 비밀번호를 폼에 담습니다.
- `"csrf_token": token["value"]`: 방금 얻은 토큰 값을 폼에 담습니다.
- `if response.status_code not in (...) or login_form(response)`: 예상하지 않은 상태 코드이거나 로그인 폼이 다시 나오면 실패로 봅니다.
- `raise ScanError(...)`: 로그인 실패를 상위 호출에 알립니다.
- `probe = self.request("GET", ...)`: 첫 보호된 게시판에 접근합니다. 로그인 성공 리다이렉트 자체는 따라가지 않습니다.
- `self.check_page(probe)`: 실제 보호된 페이지 접근이 되는지 검사합니다.

## check_page: 정상 접근 검사

- `@staticmethod`: 객체의 설정을 사용하지 않는 메서드임을 표시합니다.
- `def check_page(response)`: 응답 하나를 검사합니다.
- `if response.status_code != 200 or login_form(response)`: 200이 아니거나 로그인 페이지이면 정상 결과로 쓰지 않습니다.
- `raise ScanError(...)`: 상태 코드와 실패 이유를 알립니다.

## result_text: 결과 영역만 추출

- `def result_text(self, response, payload)`: 응답에서 비교용 결과 문자열을 만듭니다.
- `document = soup(response)`: HTML 객체를 만듭니다.
- `selector = self.config.get(...)`: 결과 영역 선택자를 읽습니다. 기본값 tbody는 표의 본문입니다.
- `regions = document.select(selector)`: 해당 영역을 모두 선택합니다.
- `if not regions`: 선택된 영역이 없는지 검사합니다.
- `raise ScanError(...)`: 결과 영역이 없으면 전체 HTML 길이로 대체하지 않고 판정을 보류합니다.
- `for region in regions`: 결과 영역을 하나씩 순회합니다.
- `for node in region.select(...)`: 스크립트·스타일·입력란을 선택합니다.
- `node.decompose()`: 선택한 요소를 비교용 HTML에서 제거합니다. 서버의 페이지를 변경하는 것은 아닙니다.
- `text = " ".join(...)`: 각 영역의 텍스트를 추출해 공백으로 연결합니다.
- `return ...replace(payload, "").split()...`: 그대로 반사된 페이로드를 지우고 연속 공백을 정리합니다. 페이로드가 빈 문자열이면 공백만 정리합니다.

## scan: 한 엔드포인트의 결과 생성

- `def scan(self, target, scan_id)`: 대상 설정과 실행 ID를 받습니다.
- `finding = {`: 결과 딕셔너리를 초기화합니다.
- `"scan_id": ..., "category": ...`: 실행 식별자와 취약점 종류입니다.
- `"target_url": ..., "method": ...`: 점검 경로와 GET 메서드입니다.
- `"parameter": ..., "payload": None`: 점검 입력 이름과 아직 없는 대표 페이로드입니다.
- `"status_code": None, "result": "N/A", ...`: 검증 전에는 판정 불가로 시작합니다.
- `"evidence": "", "remediation": ...`: 증거 설명과 대응 문구입니다.
- `"details": ...`: 기본 URL과 세부 검사 기록 목록입니다.
- `"scanned_at": ...isoformat()`: UTC 시각을 기계가 읽기 쉬운 문자열로 기록합니다.

## fetch: 내부 검색 함수

- `def fetch(payload)`: 현재 대상에 페이로드를 보내는 내부 함수를 정의합니다.
- `response = self.request(...params={...})`: 검색 파라미터를 보냅니다. URL 인코딩은 requests가 처리합니다.
- `finding["status_code"] = ...`: 마지막 응답 코드를 저장합니다.
- `if 300 <= ... < 500 or login_form(response)`: 이동, 접근 실패, 로그인 화면을 걸러냅니다. 500은 DB 오류가 있을 수 있어 이 단계에서 일괄 차단하지 않습니다.
- `raise ScanError(...)`: 정상 진단을 진행할 수 없음을 알립니다.
- `return response`: 응답을 판정 코드에 돌려줍니다.

## Error-based 검사

- `try`: 진단 중 발생하는 ScanError를 결과에 기록할 범위입니다.
- `baseline = fetch("")`: 빈 검색어로 기준 응답을 받습니다.
- `self.check_page(baseline)`: 기준 응답이 정상인지 확인합니다.
- `if MYSQL_ERROR.search(baseline.text)`: 평소에도 오류 문구가 나타나는지 검사합니다.
- `raise ScanError(...)`: 원래 있던 오류를 주입 증거로 오인하지 않도록 중단합니다.
- `for payload in (...)`: 작은따옴표와 큰따옴표를 차례로 시도합니다.
- `responses = [fetch(payload), fetch(payload)]`: 같은 입력을 두 번 보냅니다.
- `matches = [...]`: 각 응답에서 MySQL 오류 패턴을 찾습니다.
- `if all(matches)`: 두 응답에서 모두 오류를 찾았는지 확인합니다.
- `finding.update(result=..., severity=..., payload=...)`: 취약·높음·대표 페이로드를 기록합니다.
- `evidence=f"..."`: 일치한 오류 패턴을 증거로 기록합니다. 전체 본문을 저장하지 않습니다.
- `finding["details"]["checks"].append(...)`: 오류 기반 검사 성공을 세부 기록에 추가합니다.
- `return finding`: 확정 증거를 얻었으므로 이 대상 진단을 끝냅니다.
- `if any(matches)`: 두 번 중 한 번만 오류가 있었는지 확인합니다.
- `raise ScanError(...)`: 재현되지 않는 오류를 양호로 처리하지 않고 판정을 보류합니다.
- `for response in responses`: 오류로 확정하지 못한 응답을 순회합니다.
- `self.check_page(response)`: 정상 응답인지 검사합니다. 이유 모를 500을 SAFE로 처리하지 않습니다.
- `...append({"type": "error", "confirmed": False})`: 오류 기반 증거가 없었다고 기록합니다.
- `base_text = self.result_text(baseline, "")`: 기준 응답의 게시판 결과 텍스트를 추출합니다.
- `if base_text != self.result_text(fetch(""), "")`: 같은 일반 요청의 결과가 재현되는지 확인합니다.
- `raise ScanError(...)`: 원래부터 변하는 결과라면 참/거짓 차이를 믿을 수 없어 보류합니다.

## Boolean-based 검사

- `for prefix in (...)`: 일반 LIKE 조건과 괄호로 감싼 LIKE 조건용 접두어를 순회합니다.
- `true_payload = prefix + " AND 1=1 -- "`: 항상 참 조건을 만듭니다.
- `false_payload = prefix + " AND 1=2 -- "`: 항상 거짓 조건을 만듭니다. 뒤 공백은 MySQL 주석 문법에 필요합니다.
- `values = []`: 네 번의 결과 텍스트를 저장할 목록입니다.
- `for payload in (true_payload, false_payload, ...)`: 참/거짓을 번갈아 두 번 검사합니다.
- `response = fetch(payload)`: 검색 요청을 보냅니다.
- `self.check_page(response)`: 정상 페이지인지 확인합니다.
- `if MYSQL_ERROR.search(response.text)`: Boolean 비교 중 SQL 오류가 있는지 확인합니다.
- `values = []`: 이 변형의 비교 결과를 폐기합니다.
- `break`: 현재 변형의 반복 요청을 끝냅니다.
- `values.append(self.result_text(...))`: 정상 결과 영역의 텍스트만 저장합니다.
- `if not values`: 해당 변형을 비교할 수 없었는지 확인합니다.
- `continue`: 다음 접두어 변형으로 넘어갑니다.
- `t1, f1, t2, f2 = values`: 첫 번째 참·거짓과 두 번째 참·거짓 값을 이름 붙입니다.
- `stable = t1 == t2 and f1 == f2`: 같은 조건의 결과가 반복해서 같은지 확인합니다.
- `confirmed = stable and t1 == base_text and t1 != f1`: 재현성, 일반 검색과 참 결과 일치, 참/거짓 차이를 모두 요구합니다. 단순한 길이 차이보다 보수적인 조건입니다.
- `...append({`: 비교 통계를 결과에 추가합니다.
- `"type": "boolean", "true_payload": ...`: 검사 종류와 참 페이로드입니다.
- `"false_payload": ..., "true_length": len(t1)`: 거짓 페이로드와 참 결과 텍스트 길이입니다.
- `"false_length": ..., "stable": ..., "confirmed": ...`: 거짓 결과 길이와 재현·확정 여부입니다.
- `if confirmed`: 확정 조건을 충족한 경우입니다.
- `finding.update(...)`: 취약 판정과 증거 문구를 기록합니다.
- `return finding`: 현재 대상 결과를 반환합니다.
- `if not stable or t1 != f1`: 차이는 있지만 확정 규칙을 충족하지 못한 경우를 찾습니다.
- `raise ScanError(...)`: 애매한 차이는 판정 불가로 처리합니다.
- `boolean_checks = [...]`: 세부 기록에서 Boolean 검사만 골라냅니다.
- `if not boolean_checks`: 정상적인 Boolean 비교를 한 번도 못 했는지 검사합니다.
- `raise ScanError(...)`: 비교를 못 했다면 양호로 처리하지 않습니다.
- `finding.update(result="SAFE", ...)`: 정상 검사를 했지만 증거가 없을 때 검사 범위 내 양호로 기록합니다.
- `except ScanError as exc`: 검사 실패를 받습니다.
- `finding["evidence"] = str(exc)`: 기본 N/A 판정을 유지하고 이유를 기록합니다.
- `return finding`: 확정 취약·양호·판정 불가 중 하나를 반환합니다.

## main: 설정, 실행, JSON 저장

- `def main()`: 명령행 실행 전체를 묶습니다.
- `parser = argparse.ArgumentParser(...)`: 명령행 옵션 파서를 만듭니다.
- `parser.add_argument("--config", ...)`: 설정 파일 경로 옵션을 등록합니다.
- `parser.add_argument("--base-url", ...)`: URL만 일시적으로 바꾸는 옵션입니다.
- `parser.add_argument("--output", ...)`: 출력 파일 옵션입니다.
- `args = parser.parse_args()`: 실제 실행 인수를 해석합니다.
- `config = json.loads(Path(...).read_text(...))`: 설정 파일을 읽어 딕셔너리로 변환합니다. utf-8-sig는 BOM이 있는 UTF-8 파일도 읽습니다.
- `if args.base_url`: URL 덮어쓰기 옵션을 사용했는지 확인합니다.
- `config["base_url"] = args.base_url`: 이번 실행에서만 URL을 변경합니다.
- `password = os.environ.get(...) or getpass.getpass(...)`: 환경 변수에 비밀번호가 없으면 입력받습니다.
- `scanner = Scanner(config)`: 세션과 설정을 준비합니다.
- `scan_id = "SCAN-" + uuid.uuid4().hex[:12]`: 임의 식별자 일부에 접두어를 붙입니다.
- `try`: 로그인 실패를 처리할 범위를 시작합니다.
- `scanner.login(password)`: 먼저 인증합니다.
- `findings = [scanner.scan(...) for ...]`: 지정된 두 게시판을 순서대로 검사합니다.
- `except ScanError as exc`: 로그인 단계에서 발생한 실패를 받습니다. 개별 진단 실패는 scan 내부에서 처리합니다.
- `findings = []`: 실패 결과 목록을 준비합니다.
- `for target in config["targets"]`: 각 대상의 결과를 만듭니다.
- `findings.append({`: 결과 객체를 추가합니다.
- `"scan_id": ..., "category": ..., "target_url": ...`: 실행과 대상 식별 정보입니다.
- `"method": ..., "parameter": ..., "payload": None`: 예정했던 검색 정보입니다. 주입은 하지 않았으므로 payload는 null입니다.
- `"status_code": None, "result": "N/A", ...`: 대상 진단 응답이 없고 실패했음을 나타냅니다.
- `"evidence": str(exc), "remediation": ...`: 실패 이유와 대응 문구입니다.
- `"details": {"phase": "login"}, "scanned_at": ...`: 로그인 단계 실패와 시간을 기록합니다.
- `finally`: 성공과 실패에 관계없이 실행합니다.
- `scanner.session.close()`: 네트워크 세션을 정리합니다.
- `output = json.dumps(...ensure_ascii=False, indent=2)`: 한글을 유지하고 들여쓰기가 있는 JSON 문자열로 바꿉니다.
- `destination = Path(args.output)`: 저장 경로 객체입니다.
- `destination.parent.mkdir(...)`: 상위 폴더가 없으면 만듭니다. 이미 있어도 괜찮습니다.
- `destination.write_text(...)`: UTF-8 파일로 저장합니다.
- `print(output)`: 같은 JSON을 표준 출력에도 씁니다.
- `return 2 if any(...) else 0`: 하나라도 N/A이면 종료 코드 2, 아니면 0입니다.
- `if __name__ == "__main__"`: 다른 파일에서 import할 때는 실행하지 않고 직접 실행할 때만 동작합니다.
- `raise SystemExit(main())`: main을 실행하고 반환값을 프로그램 종료 코드로 사용합니다.

## JSON 예시를 읽는 법

파일의 가장 바깥은 배열입니다. 배열 안에 qna 결과와 notice 결과가 각각 들어갑니다. `details.checks`는 수행한 검사 기록이며, Error-based로 바로 확정되면 Boolean 기록은 없습니다. `SAFE`는 파라미터 바인딩을 소스에서 확인했다는 뜻이 아니라, 제한된 블랙박스 검사에서 증거가 없었다는 뜻입니다. 이 차이를 발표에서 분명히 설명하세요.
