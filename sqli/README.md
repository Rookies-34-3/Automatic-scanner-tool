# ROOKIESCAN SQL 인젝션 진단 도구

지정된 GET/POST 검색 파라미터에 Error-based / Boolean-based 검사를 수행합니다. 통합용 run()은 결과 객체 하나를 반환하고, 직접 로그인하는 CLI는 결과 객체 배열을 출력·저장합니다. Python 3.10 이상을 사용합니다.

## 통합용 함수

프로젝트 루트에서 다음처럼 호출합니다. 로그인은 바깥에서 완료한 상태여야 합니다.

```python
from sqli.scanner import run

# common_session은 공통 로그인 모듈이 인증을 마친 requests.Session입니다.
finding = run(
    url="http://13.125.233.51/my-class/board/qna",
    method="GET",
    parameters="content",
    cookie=common_session.cookies.get_dict(),
)
print(finding["vuln"])
print(finding["result"]["evidence"])
```

`cookie`는 `{"session": "실제 로그인 쿠키 값"}` 형태의 문자열 딕셔너리입니다. 해당 대상 서버의 쿠키만 전달하세요. `parameters`는 목록이 아니라 **한 개의 파라미터 이름 문자열**입니다. 여러 파라미터는 각각 run()을 호출합니다. run()은 config.json을 읽거나 직접 로그인하지 않으며, 입력창·print·파일 저장 없이 반환합니다. 호출마다 세션을 새로 만들고 정리합니다. 입력 형식 오류는 ValueError, 네트워크·인증·진단 실패는 N/A 결과입니다.

GET은 query string, POST는 form data로 전송합니다. URL에 들어 있던 다른 쿼리는 유지하며 GET 점검 파라미터만 교체합니다. POST JSON 본문이나 추가 폼 필드/CSRF 토큰 전달은 현재 네 인수 인터페이스에 포함하지 않았습니다. 쿠키 외 별도 CSRF 토큰이 필수인 POST 경로는 차단 응답으로 N/A가 나올 수 있습니다. 기존 HTML 검색 판정 방식(tbody 결과 영역)을 유지하므로 임의의 JSON API 진단용은 아닙니다.

출력의 최상위 필드는 `url`, `method`, `parameters`, `vuln`, `result`, `scan_id`, `category`, `severity`, `scanned_at`, `remediation`입니다. `vuln`은 판정 문자열이며 `result`는 `payload`, `status_code`, `evidence`, `checks`, `base_url` 등의 상세 객체입니다. 기존 파일은 자동 변환하지 않으며 새 실행부터 이 포맷을 사용합니다. 내부 Scanner.scan()은 판정 로직 보존을 위해 기존 자료 구조를 유지하고 format_finding()이 외부 출력만 변환합니다.

## 실행 (PowerShell)

아래 명령은 `sqli` 폴더에서 실행합니다. 프로젝트 루트에서는 `python sqli/scanner.py --base-url http://13.125.233.51`로 실행해도 됩니다. 설정 파일 기본값은 scanner.py 옆 config.json이며 출력 상대 경로는 실행한 폴더 기준입니다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scanner.py
```

비밀번호는 실행 시 표시되지 않는 입력창에 입력합니다. 인수 문서의 실습 비밀번호를 사용하세요. 자동 실행에는 `ROOKIESCAN_PASSWORD` 환경 변수를 사용할 수 있습니다. 비밀번호·쿠키·CSRF 토큰은 결과 JSON에 저장하지 않습니다.

팀 AWS 실습 서버를 대상으로 실행:

```powershell
.\.venv\Scripts\python.exe scanner.py --base-url http://13.125.233.51 --output results/aws-findings.json
```

설정 파일의 `base_url`을 바꿔도 됩니다. 기본값은 `http://127.0.0.1:8080`입니다. `targets`에서 대상 경로와 파라미터를, `username`에서 계정을 변경합니다. 대상의 `method`는 기본 GET이며 POST로 지정할 수 있습니다. `result_selector`는 검색 결과만 포함하는 CSS 선택자이며 기본값은 `tbody`입니다. 실제 게시판이 테이블이 아니라면 개발자 도구에서 결과 목록의 선택자를 확인하여 변경해야 합니다. `timeout`은 네트워크 타임아웃(초), `delay`는 각 요청 전 대기(초)입니다. 이 설정 파일은 직접 로그인하는 CLI에서 사용합니다.

## 로그인과 판정

1. `/login` GET으로 숨겨진 `csrf_token`을 가져옵니다.
2. 같은 `requests.Session`에서 `userId`, `password`, `csrf_token`을 POST합니다.
3. 보호된 첫 번째 게시판을 GET하여 로그인 페이지나 리다이렉트가 아닌 200 응답인지 검증합니다.
4. 빈 검색어 응답을 기준으로 작은따옴표·큰따옴표 주입을 각각 두 번 검사합니다. 기준 응답에 없던 MySQL 오류가 두 번 나타나면 취약으로 기록하고 오류 검사 루프만 종료합니다.
5. 오류 기반 취약 확인 여부와 관계없이 Boolean 검사를 이어갑니다. 결과 영역을 추출하고 참/거짓/참/거짓 조건을 보냅니다. 참과 거짓 각각의 결과가 재현되고, 참 결과가 일반 빈 검색 결과와 같으며, 거짓과 다르면 취약입니다. Boolean 취약이 확인되면 기존처럼 반환합니다.

두 검사의 기록은 내부 `details.checks`, 공통 출력의 `result.checks`에 남습니다. 오류 기반 취약이 확인된 뒤 Boolean 증거가 없거나 검사가 중단되어도 VULNERABLE과 기존 오류 증거를 유지합니다. 중단된 Boolean 검사는 `confirmed: false`, `completed: false`, `reason`으로 기록하며, 이것은 양호 판정이 아닙니다. 아직 취약 증거가 없는 상태에서 ScanError가 발생하면 기존처럼 N/A입니다.

Boolean 페이로드는 `LIKE '%입력%'`를 예상하여 `%' AND 1=1 -- ` 및 `%' AND 1=2 -- `를 사용합니다. 괄호로 감싼 조건에 대해서도 한 가지 변형을 검사합니다. MySQL의 `-- ` 뒤 공백은 반드시 유지합니다. 사용자 예시의 OR 조건 대신 AND를 사용해 빈 검색어의 전체 결과를 기준으로 참/거짓 차이를 비교합니다. 다른 SQL 구조는 추가 조정이 필요합니다.

## 판정값 (vuln)

- `VULNERABLE`: 취약. 반복 확인된 증거가 있음. 심각도 `HIGH`.
- `SAFE`: 양호. **실행한 페이로드 범위에서 증거를 찾지 못했다는 뜻**이며 SQL 안전성을 증명하지는 않음. 심각도 `INFO`.
- `N/A`: 해당없음/판정 불가. 로그인·접근 실패, 타임아웃, 결과 선택자 불일치, 불안정한 응답 등. `evidence`에 이유 기록. 팀에서 '해당없음'과 '진단 실패'를 분리한다면 `ERROR` 등의 값으로 확장할 것.

`scan_id`는 CLI 한 실행의 모든 대상이 공유하며 run()은 호출마다 생성합니다. `url`은 절대 URL입니다. `result.payload`는 대표 증거이며 Boolean 쌍과 비교 결과는 `result.checks`에 있습니다. `result.status_code`는 마지막 수신 응답 코드이며 응답을 받지 못한 경우 null입니다. `scanned_at`은 UTC ISO 8601 시각입니다. API 전송은 구현하지 않았습니다. CLI 기본 출력 경로는 `results/findings.json`이며 같은 경로로 다시 실행하면 덮어씁니다. 대상 중 하나라도 vuln이 N/A이면 종료 코드 2, 나머지는 0입니다. 취약 발견 자체는 프로그램 오류가 아닙니다.

실제 qna가 VULNERABLE, notice가 SAFE로 나오는지는 실습 서버에서 확인해야 합니다. 현재 외부 AWS 서버에는 요청하지 않았습니다. 빈 DB, 입력 필터, 다른 SQL 구조는 미탐지의 원인이 될 수 있고, 결과 영역에 변화하는 시간이 포함되면 N/A가 나올 수 있습니다. 결과 전체나 사용자 게시물은 JSON에 보관하지 않고 오류 패턴과 길이·재현 여부만 기록합니다.

## 검증

```powershell
.\.venv\Scripts\python.exe -m unittest -v
```

외부 접속 없이 오류 노출(500 포함), Boolean 탐지, 안전 검색과 입력 반사, 인증 실패, 동적 응답, 결과 영역 누락, 타임아웃, CSRF 전달을 검증합니다. 가짜 HTTP 응답 기반 테스트이므로 실제 Flask/MySQL 연동 검증을 대체하지 않습니다.

## 발표용 설명

“저희 도구는 사전에 지정된 검색 파라미터를 점검합니다. 로그인 페이지에서 CSRF 토큰을 얻어 로그인하고 세션 쿠키를 유지합니다. 일반 응답과 오류 유발 입력의 응답을 비교하고, 오류가 없으면 참·거짓 조건에 따른 게시판 검색 결과를 반복 비교합니다. 로그인 실패를 양호로 오인하지 않도록 판정 불가를 구분하며, 결과는 공통 JSON으로 저장해 대시보드 통합에 사용합니다. AI는 필요하지 않아 사용하지 않았습니다.”

코드의 줄별 설명은 `CODE_WALKTHROUGH.md`를 참고하세요.

## 참고 문서

- [Requests Session 공식 문서](https://requests.readthedocs.io/en/stable/user/advanced/)
- [Requests timeout 공식 문서](https://requests.readthedocs.io/en/latest/user/quickstart/)
- [MySQL 주석 문법](https://dev.mysql.com/doc/refman/8.0/en/comments.html)
