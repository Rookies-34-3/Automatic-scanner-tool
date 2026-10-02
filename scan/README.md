# Scan Vulnerability Detection Modules

본 모듈은 웹/서버 환경에서 발생할 수 있는 다음 보안 취약점을 블랙박스 방식으로 진단하기 위한 스캐너 모음이다.

* Port Scan
* Directory Indexing
* Admin Page Exposure

각 스캐너는 공통적으로 다음 인터페이스를 사용한다.

```python
run(url, method, parameters, cookie)
```

## 1. Directory Indexing

### 진단 대상

웹 서버의 디렉터리 인덱싱 노출 여부를 검사한다.

### 진단 방식

대상 URL에 GET 요청을 전송한 후 HTTP 응답 코드와 응답 본문을 확인한다.

다음 조건을 만족하면 디렉터리 인덱싱이 노출된 것으로 판단한다.

* HTTP 상태 코드가 `200`
* 응답 본문에 `Index of /` 또는 `<title>Index of`가 포함

### 판정 기준

```text
조건                              판정
------------------------------------------------
HTTP 200 + Index of 확인          VULNERABLE
HTTP 200 + Index of 미확인        SAFE
GET 이외의 요청                   N/A
HTTP 요청 실패                    N/A
```

### 테스트 예시

```text
/uploads/ → VULNERABLE
/login    → SAFE
```

### 실행 예시

```python
from scan.directory_indexing.scanner import run

result = run(
    "http://127.0.0.1:8080/uploads/",
    "GET",
    {},
    {}
)
```

---

## 2. Admin Page Exposure

### 진단 대상

인증되지 않은 상태에서 관리자 페이지가 노출되는지를 검사한다.

### 진단 방식

비로그인 상태로 대상 URL에 GET 요청을 전송하고 HTTP 응답과 HTML 본문을 분석한다.

관리자 페이지를 식별하기 위해 다음 지표를 사용한다.

```text
data-active="admin"
관리자 페이지
관리자 대시보드
lab-admin-section
```

4개의 지표 중 2개 이상이 확인되고 HTTP 상태 코드가 `200`이면 관리자 페이지가 노출된 것으로 판단한다.

### 판정 기준

```text
조건                                      판정
------------------------------------------------------
HTTP 200 + 관리자 지표 2개 이상 확인       VULNERABLE
HTTP 200 + 관리자 지표 부족                SAFE
HTTP 401 / 403                             SAFE
로그인 페이지로 리다이렉트                  SAFE
판단할 수 없는 리다이렉트                  N/A
GET 이외의 요청                            N/A
HTTP 요청 실패                             N/A
```

### 테스트 예시

```text
/admin → VULNERABLE
/login → SAFE
```

### 주의사항

이 검사는 비로그인 상태의 관리자 페이지 노출 여부를 확인하는 것을 목적으로 한다.

따라서 현재 구현에서는 전달받은 `cookie`를 인증에 사용하지 않는다.

---

## 3. Port Scan

### 진단 대상

대상 호스트에서 TCP 연결이 가능한 포트를 확인하고, 설정된 허용 포트 목록과 비교한다.

### 진단 방식

Python `socket`을 이용하여 지정된 포트에 TCP 연결을 시도한다.

입력의 `parameters`를 통해 검사 대상 포트와 정상으로 허용할 포트를 지정할 수 있다.

```json
{
    "ports": [80],
    "allowed_ports": [80],
    "timeout": 1
}
```

### Parameters

| 항목              | 설명             |
| --------------- | -------------- |
| `ports`         | 검사할 포트 목록      |
| `allowed_ports` | 정상으로 허용할 포트 목록 |
| `timeout`       | 포트 연결 제한 시간(초) |

기본값:

```text
ports           = [80]
allowed_ports   = [80]
timeout         = 1.0
```

### 판정 기준

```text
조건                                           판정
---------------------------------------------------------
접근 가능한 포트가 허용 목록에 모두 포함        SAFE
접근 가능한 포트 중 허용 목록에 없는 포트 존재   VULNERABLE
잘못된 포트 번호 / 입력 형식                   N/A
호스트 확인 실패                               N/A
```

### 테스트 예시

```text
8080 OPEN + allowed_ports=[8080]
→ SAFE

8080 OPEN + allowed_ports=[80]
→ VULNERABLE
```

위 테스트에서 `allowed_ports`는 해당 포트를 본질적으로 위험/안전하다고 판단하는 값이 아니라, 해당 진단 환경에서 정상적으로 허용된 포트를 나타내는 설정값이다.

현재 실제 EC2 환경에서는 외부에 80번 포트가 열려 있는 것으로 확인되었으며, 추가적인 테스트용 포트 노출 여부는 환경 및 팀의 정책에 따라 설정한다.

---

## 4. 공통 출력 형식

각 스캐너는 다음과 같은 형태의 결과를 반환한다.

```json
{
    "url": "http://127.0.0.1:8080/",
    "method": "GET",
    "parameters": {},
    "vuln": "SAFE",
    "result": "검사 결과"
}
```

### `vuln`

```text
VULNERABLE
SAFE
N/A
```

* `VULNERABLE`: 취약점이 확인된 경우
* `SAFE`: 해당 검사에서 취약점이 확인되지 않은 경우
* `N/A`: 요청 실패, 잘못된 입력 등으로 명확한 판정이 어려운 경우

---

## 5. 테스트

각 모듈에는 `test_scanner.py`가 있으며 실제 외부 사이트나 실습 서버에 접속하지 않고 Mock을 사용하여 판정 로직을 검증한다.

개별 테스트:

```powershell
python -m unittest scan.directory_indexing.test_scanner -v
python -m unittest scan.admin_exposure.test_scanner -v
python -m unittest scan.portscan.test_scanner -v
```

전체 테스트:

```powershell
python -m unittest scan.directory_indexing.test_scanner scan.admin_exposure.test_scanner scan.portscan.test_scanner -v
```

현재 세 모듈에 대해 총 16개의 테스트가 작성되어 있으며 모두 통과한 상태이다.

---

## 6. 의존성

`requests`를 사용하므로 다음 파일을 통해 의존성을 관리한다.

```text
requirements.txt
```

설치:

```powershell
pip install -r scan/requirements.txt
```
