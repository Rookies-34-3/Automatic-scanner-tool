ROOKIESCAN Scan Modules

웹/서버 환경에서 다음 보안 항목을 진단하는 스캐너 모음이다.

Directory Indexing
Admin Page Exposure
Port Scan

각 취약점별 진단 로직은 독립 모듈로 구성하며, pipeline.py를 통해 공통 결과 형식으로 변환할 수 있다.

1. 디렉터리 구조
scan/
├── README.md
├── .gitignore
├── config.json
├── pipeline.py
├── requirements.txt
│
├── directory_indexing/
│   ├── scanner.py
│   └── test_scanner.py
│
├── admin_exposure/
│   ├── scanner.py
│   └── test_scanner.py
│
└── portscan/
    ├── scanner.py
    └── test_scanner.py
2. 진단 모듈
Directory Indexing

웹 서버의 디렉터리 인덱싱 노출 여부를 검사한다.

GET 요청을 대상 URL에 전송하고 응답 본문에서 다음과 같은 디렉터리 목록 표시를 확인한다.

Index of /
<title>Index of

판정 기준:

HTTP 200 + Index of 확인
→ VULNERABLE

HTTP 200 + Index of 미확인
→ SAFE

GET 이외의 요청
→ N/A

HTTP 요청 실패
→ N/A

진단 결과의 details에는 탐지된 지표와 HTTP 상태 코드가 보존된다.

예:

{
  "matched_indicators": [
    "Index of /",
    "<title>Index of"
  ],
  "status_code": 200
}
Admin Page Exposure

비로그인 상태에서 관리자 페이지가 노출되는지를 검사한다.

현재 관리자 페이지 식별 지표:

data-active="admin"
관리자 페이지
관리자 대시보드
lab-admin-section

4개 지표 중 2개 이상이 확인되고 HTTP 200이 반환되면 관리자 페이지 노출로 판정한다.

판정 기준:

HTTP 200 + 식별 지표 2개 이상
→ VULNERABLE

HTTP 200 + 식별 지표 부족
→ SAFE

HTTP 401 / 403
→ SAFE

로그인 페이지로 리다이렉트
→ SAFE

판단하기 어려운 리다이렉트
→ N/A

GET 이외의 요청
→ N/A

HTTP 요청 실패
→ N/A

진단 결과에는 다음 정보가 details에 보존된다.

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

현재 구현은 비로그인 상태의 관리자 페이지 노출 여부를 확인하는 목적이므로 전달받은 cookie를 관리자 페이지 인증에 사용하지 않는다.

Port Scan

대상 호스트의 TCP 포트에 연결을 시도하고, 접근 가능한 포트와 허용 포트를 비교한다.

기본 설정 예:

{
  "url": "http://127.0.0.1:8080",
  "ports": [80],
  "allowed_ports": [80],
  "timeout": 1
}

판정 기준:

접근 가능한 포트가 모두 허용 목록에 포함
→ SAFE

허용되지 않은 접근 가능 포트 존재
→ VULNERABLE

잘못된 포트/입력/timeout
→ N/A

결과의 details에는 다음 정보가 포함된다.

{
  "host": "127.0.0.1",
  "scanned_ports": [80],
  "open_ports": [],
  "allowed_ports": [80],
  "unexpected_ports": [],
  "timeout": 1.0
}

Port Scan은 HTTP endpoint 취약점 검사가 아니라 TCP 연결 검사이므로 공통 HTTP endpoint의 method 값으로 표현하지 않고 자체 설정의 ports, allowed_ports, timeout을 사용한다.

3. 공통 입력

HTTP 기반 모듈은 다음과 같은 endpoint 정보를 사용할 수 있다.

{
  "url": "http://127.0.0.1:8080/uploads/",
  "method": "GET",
  "parameters": []
}

parameters는 다음과 같은 구조를 사용한다.

[
  {
    "name": "keyword",
    "location": "query"
  }
]

허용되는 location은 다음과 같다.

path
query
body
header

공통 입력의 실제 스키마는 integration 브랜치의 pipeline/endpoint-input.schema.json을 기준으로 한다.

4. Scan 전용 설정

config.json에서 각 모듈의 검사 대상과 설정을 관리한다.

{
  "base_url": "http://127.0.0.1:8080",

  "directory_indexing": {
    "targets": [
      {
        "url": "http://127.0.0.1:8080/uploads/",
        "method": "GET",
        "parameters": []
      }
    ]
  },

  "admin_exposure": {
    "targets": [
      {
        "url": "http://127.0.0.1:8080/admin",
        "method": "GET",
        "parameters": []
      }
    ]
  },

  "portscan": {
    "url": "http://127.0.0.1:8080",
    "ports": [80],
    "allowed_ports": [80],
    "timeout": 1
  }
}

severity는 현재 팀의 최종 위험도 정책이 확정되지 않아 설정 파일에서 모듈별 값을 지정할 수 있도록 구성되어 있다.

5. 공통 출력

pipeline.py는 각 모듈의 내부 결과를 다음 공통 Finding 형식으로 변환한다.

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

공통 출력 필드는 다음과 같다.

scanner_id
name
url
method
parameters
result
severity
reason
details

result는 다음 네 가지 공통 값으로 변환한다.

VULNERABLE
PASS
REVIEW
ERROR

내부 스캐너의 결과와의 대응 관계:

VULNERABLE → VULNERABLE
SAFE       → PASS
POTENTIAL  → REVIEW
N/A        → REVIEW
INFO       → REVIEW
ERROR      → ERROR

추가적인 진단 근거는 details에 보존한다.

예를 들어 Directory Indexing은 탐지 지표와 HTTP 상태 코드를, Admin Page Exposure는 관리자 식별 지표를, Port Scan은 검사 포트와 열린 포트 정보를 저장한다.

공통 출력의 실제 스키마는 integration 브랜치의 pipeline/finding-output.schema.json을 기준으로 한다.

6. 독립 실행

저장소 최상위 경로에서 다음과 같이 실행할 수 있다.

python -m scan.pipeline --config scan/config.json --output scan/output/scan_findings.json

실행이 완료되면 지정한 경로에 공통 형식의 JSON 결과가 생성된다.

실행 결과 확인:

Get-Content "scan/output/scan_findings.json" -Encoding UTF8

scan/output/*.json은 실행 결과이므로 Git에 커밋하지 않는다.

7. 테스트

각 모듈에는 test_scanner.py가 있으며 실제 외부 사이트나 실습 서버에 의존하지 않고 Mock을 이용해 진단 로직을 검증한다.

개별 테스트:

python -m unittest scan.directory_indexing.test_scanner -v
python -m unittest scan.admin_exposure.test_scanner -v
python -m unittest scan.portscan.test_scanner -v

전체 테스트:

python -m unittest scan.directory_indexing.test_scanner scan.admin_exposure.test_scanner scan.portscan.test_scanner -v

현재 전체 16개 테스트가 통과한다.

Directory Indexing  4
Admin Exposure      6
Port Scan           6
---------------------
Total              16
8. 통합 Pipeline 연결

현재 scan은 독립 실행과 공통 Finding 출력까지 구현되어 있다.

전체 ROOKIESCAN 통합에서는 integration 브랜치의 pipeline/runner.py에 스캐너 adapter를 등록하여 다른 취약점 스캐너와 함께 실행할 수 있도록 연결한다.

통합 과정에서는 다음 공통 규격을 따른다.

Common Endpoint Input
        ↓
Scan Module
        ↓
Common Finding Output
        ↓
ROOKIESCAN Pipeline
        ↓
Aggregate Result

scan의 Port Scan은 일반 HTTP endpoint 진단과 달리 TCP 포트 설정을 사용하므로 integration adapter에서 별도의 scan 전용 설정을 유지해야 한다.

9. 의존성

외부 Python 패키지는 requests를 사용한다.

설치:

pip install -r scan/requirements.txt

Python 표준 라이브러리인 socket, json, argparse, unittest 등은 별도 설치가 필요하지 않다.