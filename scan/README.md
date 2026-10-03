# ROOKIESCAN Scan 취약점 진단 도구

지정된 대상 URL을 기준으로 Directory Indexing, Admin Page Exposure, Port Scan 검사를 수행합니다. 각 검사는 독립적인 scanner로 구성되며 `pipeline.py`가 세 모듈을 실행하고 결과를 ROOKIESCAN 공통 Finding 형식으로 변환합니다. Python 3.10 이상을 사용합니다.

## 통합용 실행

프로젝트 루트에서 다음처럼 실행합니다.

```powershell
python -m scan.pipeline --config scan/config.json --output scan/output/scan_findings.json
```

`pipeline.py`는 `config.json`을 읽어 Directory Indexing, Admin Page Exposure, Port Scan을 순서대로 실행하고 결과 리스트 하나를 반환합니다. 실행 과정에서 로그인하거나 별도의 계정 정보를 요구하지 않습니다.

Python에서 직접 호출할 수도 있습니다.

```python
import json
from pathlib import Path

from scan.pipeline import run

config = json.loads(
    Path("scan/config.json").read_text(encoding="utf-8")
)

findings = run(config)

for finding in findings:
    print(finding["name"], finding["result"])
```

`run(config)`은 결과 객체 배열을 반환하며 화면 출력이나 결과 파일 저장은 `main()`에서 수행합니다. 현재 각 scanner는 비로그인 상태의 HTTP 검사 또는 TCP 연결 검사를 수행합니다.

HTTP 기반 scanner는 전달된 URL과 HTTP method, parameters를 사용하며 현재 별도의 로그인 세션이나 CSRF 토큰을 사용하지 않습니다. Port Scan은 HTTP 요청이 아니라 대상 host의 TCP 포트에 연결을 시도하므로 `ports`, `allowed_ports`, `timeout`을 scan 전용 설정으로 사용합니다.

## 실행 (PowerShell)

아래 명령은 프로젝트 루트에서 실행합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r scan/requirements.txt
python -m scan.pipeline --config scan/config.json --output scan/output/scan_findings.json
```

`requests`가 설치된 Python 환경에서 실행해야 합니다. 결과 JSON은 지정한 출력 경로에 생성되며 `scan/.gitignore`에 따라 `output/*.json` 결과 파일은 Git에 커밋하지 않습니다.

현재 기본 설정은 `config.json`에서 관리합니다.

* `base_url`: 대상 서버의 기본 URL
* `directory_indexing.targets`: 디렉터리 인덱싱 검사 대상
* `admin_exposure.targets`: 관리자 페이지 노출 검사 대상
* `portscan.url`: 포트 검사의 대상 host
* `portscan.ports`: 검사할 TCP 포트 목록
* `portscan.allowed_ports`: 정상적으로 허용할 포트 목록
* `portscan.timeout`: 각 포트의 TCP 연결 제한 시간(초)
* `severity`: 각 모듈의 출력 심각도

현재 `severity`의 기본값은 `INFO`로 설정되어 있으며 팀의 최종 위험도 정책이 확정되면 변경할 수 있습니다.

## Directory Indexing 판정

1. 지정된 URL에 GET 요청을 전송합니다.
2. HTTP 상태 코드와 응답 본문을 확인합니다.
3. 응답에서 `Index of /` 또는 `<title>Index of`가 확인되는지 검사합니다.
4. HTTP 200과 함께 디렉터리 목록 지표가 확인되면 VULNERABLE로 기록합니다.

탐지된 지표는 `details.matched_indicators`에 남습니다.

예:

```json
{
  "matched_indicators": [
    "Index of /",
    "<title>Index of"
  ],
  "status_code": 200
}
```

판정값은 다음과 같습니다.

* `VULNERABLE`: HTTP 200 응답에서 디렉터리 인덱싱 지표가 확인됨.
* `SAFE`: HTTP 200 응답이지만 디렉터리 인덱싱 지표가 확인되지 않음.
* `N/A`: GET 이외의 요청이나 네트워크 요청 실패 등으로 판정할 수 없음.

응답 본문에서 단순히 일반적인 디렉터리 관련 단어가 발견되는 것만으로 취약하다고 판정하지 않고, 현재 구현에 정의된 `Index of` 지표를 사용합니다.

## Admin Page Exposure 판정

1. 비로그인 상태에서 지정된 URL에 GET 요청을 전송합니다.
2. 401 또는 403 응답이면 접근이 차단된 것으로 기록합니다.
3. 로그인 페이지로 리다이렉트되는 경우 관리자 페이지 접근이 차단된 것으로 기록합니다.
4. HTTP 200 응답에서는 관리자 페이지 식별 지표를 확인합니다.
5. 다음 4개 지표 중 2개 이상이 확인되면 VULNERABLE로 기록합니다.

```text
data-active="admin"
관리자 페이지
관리자 대시보드
lab-admin-section
```

탐지된 지표와 개수는 `details`에 남습니다.

예:

```json
{
  "matched_indicators": [
    "data-active=\"admin\"",
    "관리자 페이지",
    "관리자 대시보드",
    "lab-admin-section"
  ],
  "indicator_count": 4,
  "required_indicator_count": 2,
  "status_code": 200
}
```

판정값:

* `VULNERABLE`: HTTP 200이며 관리자 페이지 식별 지표가 2개 이상 확인됨.
* `SAFE`: 401/403으로 차단되었거나 HTTP 200이지만 충분한 관리자 식별 지표가 확인되지 않음.
* `N/A`: GET 이외의 요청, 일반 리다이렉트, 네트워크 실패 등으로 판정이 어려움.

현재 구현은 비로그인 상태의 관리자 페이지 노출 여부를 점검하는 목적이므로 전달받은 cookie는 사용하지 않습니다.

## Port Scan 판정

Port Scan은 HTTP endpoint 검사와 별도로 대상 host의 TCP 포트에 연결을 시도합니다.

설정 예:

```json
{
  "url": "http://127.0.0.1:8080",
  "ports": [80, 443],
  "allowed_ports": [80, 443],
  "timeout": 1
}
```

검사 과정:

1. `url`에서 host를 추출합니다.
2. `ports`에 지정된 각 포트에 TCP 연결을 시도합니다.
3. 연결 가능한 포트를 `open_ports`에 기록합니다.
4. `open_ports` 중 `allowed_ports`에 포함되지 않은 포트를 `unexpected_ports`로 분류합니다.

판정값:

* `VULNERABLE`: 허용 목록에 없는 접근 가능한 포트가 확인됨.
* `SAFE`: 접근 가능한 포트가 없거나 모두 허용 목록에 포함됨.
* `N/A`: 포트 목록, 허용 포트 목록, timeout, host 등의 설정이 올바르지 않음.

결과의 `details`에는 다음 정보가 기록됩니다.

```json
{
  "host": "127.0.0.1",
  "scanned_ports": [80],
  "open_ports": [],
  "allowed_ports": [80],
  "unexpected_ports": [],
  "timeout": 1.0
}
```

Port Scan은 HTTP 취약점 검사가 아니므로 공통 endpoint 입력의 HTTP method를 사용하지 않고 scan 전용 `ports`, `allowed_ports`, `timeout` 설정을 사용합니다. 독립 실행 결과에서는 `method`를 `SCAN`으로 표시합니다.

## 공통 출력

`pipeline.py`는 각 scanner의 내부 결과를 다음 공통 Finding 형식으로 변환합니다.

```json
{
  "scanner_id": "scan",
  "name": "Directory Indexing",
  "url": "http://127.0.0.1:8080/uploads/",
  "method": "GET",
  "parameters": [],
  "result": "VULNERABLE",
  "severity": "INFO",
  "reason": "판정 근거",
  "details": {}
}
```

최상위 필드는 다음과 같습니다.

```text
scanner_id
name
url
method
parameters
result
severity
reason
details
```

`result`는 팀 공통 결과값으로 변환됩니다.

* `VULNERABLE`: 취약점 증거 확인
* `PASS`: 실행한 검사 범위에서 차단 또는 증거 미탐지
* `REVIEW`: 자동 판정이 어렵거나 판정 불가인 경우
* `ERROR`: 실행 또는 시스템 오류

내부 scanner의 결과와 공통 출력의 대응 관계는 다음과 같습니다.

```text
VULNERABLE → VULNERABLE
SAFE       → PASS
POTENTIAL  → REVIEW
N/A        → REVIEW
INFO       → REVIEW
ERROR      → ERROR
```

개별 검사에서 수집한 상태 코드, 탐지 지표, 검사 포트 등의 정보는 `details`에 보존합니다. `scan_id`와 `scanned_at`도 현재 독립 실행 pipeline의 추적 정보로 `details`에 포함합니다.

공통 Finding의 필드 구조는 integration 브랜치의 `pipeline/finding-output.schema.json`과 맞추어 구성했습니다.

## 검증

각 scanner에는 외부 사이트에 접속하지 않는 unittest가 포함되어 있습니다. HTTP 응답과 TCP 연결은 Mock으로 대체하므로 테스트 환경에서 실습 서버가 실행 중일 필요가 없습니다.

Directory Indexing:

```powershell
python -m unittest scan.directory_indexing.test_scanner -v
```

Admin Page Exposure:

```powershell
python -m unittest scan.admin_exposure.test_scanner -v
```

Port Scan:

```powershell
python -m unittest scan.portscan.test_scanner -v
```

전체 테스트:

```powershell
python -m unittest scan.directory_indexing.test_scanner scan.admin_exposure.test_scanner scan.portscan.test_scanner -v
```

현재 총 16개의 테스트가 작성되어 있습니다.

```text
Directory Indexing  4
Admin Page Exposure 6
Port Scan           6
----------------------
Total              16
```

현재 전체 16개 테스트가 통과합니다.

테스트는 실제 Flask/MySQL 환경이나 실제 외부 서버와의 통합 테스트를 대체하지 않습니다. 실제 환경에서는 대상 서버의 설정과 네트워크 상태에 따라 결과가 달라질 수 있습니다.

## 통합 Pipeline 연결

`scan`은 독립 실행과 공통 Finding 출력까지 구현되어 있습니다.

integration 브랜치의 `pipeline/runner.py`에 adapter를 추가하면 다른 취약점 스캐너와 함께 실행할 수 있습니다. HTTP 기반 Directory Indexing 및 Admin Page Exposure는 공통 endpoint 입력과 연결할 수 있으며, Port Scan은 TCP 포트 설정을 사용하는 별도 진단으로 연결해야 합니다.

현재 integration 브랜치의 `ADAPTERS`에는 `scan`이 아직 등록되어 있지 않으므로 통합 실행은 별도 adapter 추가 작업이 필요합니다.

## 발표용 설명

“저희 모듈은 세 가지 보안 항목을 점검합니다. 디렉터리 인덱싱은 응답에서 `Index of`와 같은 디렉터리 목록 지표를 확인하고, 관리자 페이지 노출은 비로그인 상태에서 관리자 페이지를 식별할 수 있는 HTML 지표를 확인합니다. 포트 스캔은 지정된 TCP 포트에 연결을 시도하고 허용되지 않은 포트의 노출 여부를 비교합니다. 각 검사 결과는 VULNERABLE, PASS, REVIEW, ERROR로 통일하여 공통 Finding 형식으로 출력하고, 상세한 판정 근거는 details에 보존합니다. AI는 현재 모듈 단위에서는 사용하지 않습니다.”

## 참고 문서

* ROOKIESCAN integration `endpoint-input.schema.json`
* ROOKIESCAN integration `finding-output.schema.json`
* ROOKIESCAN integration `pipeline/runner.py`
* Python `requests` 공식 문서
* Python `socket` 공식 문서
