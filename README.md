# ROOKIESCAN 자동 취약점 스캐너 통합 가이드

이 브랜치는 팀원이 개발한 취약점 스캐너를 하나의 실행 파이프라인으로 연결하기 위한 기준 브랜치입니다. 각 스캐너의 내부 구현은 최대한 유지하고, 공통 실행기가 설정 전달·병렬 실행·결과 변환·최종 JSON 생성을 담당합니다.

> 반드시 팀 프로젝트의 허가된 실습 서버에서만 사용합니다.

## 현재 통합 상태

| 스캐너 ID | 점검 항목 | 상태 |
|---|---|---|
| `authn` | 인증 절차 누락, 유효하지 않은 세션 접근 | 연결 완료 |
| `authz` | IDOR/BOLA, 다른 사용자 객체 접근 | 연결 완료 |
| `sqli` | Error-based / Boolean-based SQL Injection | 연결 완료 |
| 그 외 스캐너 | 팀원 브랜치 전달 후 연결 | 대기 |

통합 브랜치: `integration`

## 전체 구조

```text
공통 config.json
  ├─ 대상 URL
  ├─ 실행할 스캐너
  └─ 스캐너별 엔드포인트와 파라미터
          │
          ▼
각 취약점 스캐너 병렬 실행
          │
          ▼
개별 결과 JSON 저장
          │
          ▼
공통 결과값으로 변환
VULNERABLE / PASS / REVIEW / ERROR
          │
          ▼
pipeline/results/aggregate.json
          │
          ▼
AI 종합 분석 → 백엔드/대시보드
```

AI 종합 분석은 현재 연결 위치만 준비되어 있으며 `NOT_CONFIGURED`로 표시됩니다. AI 제공자, 모델, 전달 데이터 범위를 팀에서 결정한 뒤 공통 모듈로 한 번만 연결할 예정입니다.

## 폴더 구성

```text
Automatic-scanner-tool/
├─ authn-scanner/       # 인증 스캐너
├─ authz-scanner/       # 인가 스캐너
├─ sqli/                # SQL Injection 스캐너
├─ pipeline/
│  ├─ runner.py         # 공통 실행 및 결과 변환
│  ├─ config.example.json
│  ├─ config.aws.json   # 팀 AWS 시연 환경 설정
│  └─ README.md         # 파이프라인 상세 설명
└─ requirements.txt
```

## 팀원이 스캐너를 전달할 때 필요한 자료

각 담당자는 자신의 브랜치에 다음 자료를 올린 뒤 브랜치 이름을 통합 담당자에게 전달합니다.

1. 독립적으로 실행 가능한 스캐너 소스 폴더
2. 정확한 실행 명령어
3. 설정 파일과 점검 엔드포인트
4. 필요한 환경변수 이름
5. 결과 JSON 예시
6. 의존성 파일(`requirements.txt` 등)
7. 단독 테스트 방법과 테스트 성공 여부

비밀번호, 세션 쿠키, API 키는 소스코드나 JSON에 저장하지 않습니다. 필요한 값은 환경변수 이름만 문서에 작성합니다.

### 권장 스캐너 형태

```text
scanner-name/
├─ scanner.py 또는 Python 패키지
├─ config.example.json
├─ requirements.txt
├─ README.md
└─ tests/
```

스캐너는 최소한 다음 작업이 가능해야 합니다.

```powershell
python scanner.py --config config.example.json --output results/findings.json
```

실제 옵션 이름이 달라도 괜찮습니다. 통합 담당자가 어댑터에서 실행 명령을 변환합니다.

## 공통 입력 원칙

- 점검 방식: 블랙박스 방식 우선
- 공통 엔드포인트 입력에는 `url`, `method`, `parameters` 세 필드만 사용
- 로그인 정보, 객체 ID 탐색 규칙, 민감 필드 등은 각 스캐너의 기존 config에 유지
- 비밀정보: 설정 파일에 값을 넣지 않고 환경변수로 전달

공통 설정 예시:

```json
{
  "target": {
    "base_url": "http://127.0.0.1:8080"
  },
  "scanners": [
    {
      "id": "sqli",
      "enabled": true,
      "config": "sqli/config.json",
      "endpoints": [
        {
          "url": "http://127.0.0.1:8080/my-class/board/qna",
          "method": "GET",
          "parameters": [
            {
              "name": "content",
              "location": "query"
            }
          ]
        }
      ]
    }
  ]
}
```

## 공통 출력 규약

최종 결과는 다음 네 가지 값으로 통일합니다.

| 결과 | 의미 |
|---|---|
| `VULNERABLE` | 취약점 증거가 확인됨 |
| `PASS` | 실행한 점검 범위에서 정상 차단 또는 취약점 증거 미탐지 |
| `REVIEW` | 자동 판정이 어려워 사람이 확인해야 함 |
| `ERROR` | 설정, 의존성, 통신 또는 실행 오류 |

통합 결과 예시:

```json
{
  "pipeline": "ROOKIESCAN",
  "scan_id": "SCAN-xxxxxxxxxxxx",
  "target": "http://example.com",
  "result": "VULNERABLE",
  "summary": {
    "total": 3,
    "vulnerable": 1,
    "pass": 1,
    "review": 1,
    "error": 0
  },
  "scanners": [],
  "findings": []
}
```

각 스캐너의 기존 결과 형식이 달라도 괜찮습니다. 원본 스캐너를 크게 수정하지 않고 `pipeline/runner.py`에서 공통 형식으로 변환합니다.

각 `finding`은 최소한 다음 공통 필드를 가집니다.

```json
{
  "scanner_id": "sqli",
  "name": "SQL Injection /my-class/board/qna",
  "url": "http://127.0.0.1:8080/my-class/board/qna",
  "method": "GET",
  "parameters": [
    {
      "name": "content",
      "location": "query"
    }
  ],
  "result": "VULNERABLE",
  "severity": "HIGH",
  "reason": "판정 근거",
  "details": {}
}
```

스캐너마다 다른 추가 증거는 공통 필드를 깨뜨리지 않도록 `details`에 보존합니다.

## 통합 담당자의 연결 절차

1. 팀원 브랜치에서 스캐너 폴더를 가져옵니다.
2. 스캐너를 단독 실행하고 테스트합니다.
3. `pipeline/runner.py`의 `ADAPTERS`에 실행 정보를 등록합니다.
4. `pipeline/config.aws.json`에 설정과 엔드포인트를 추가합니다.
5. 결과값을 공통 네 가지 상태로 변환합니다.
6. 전체 파이프라인을 실행해 개별 JSON과 `aggregate.json`을 확인합니다.
7. 테스트가 통과하면 `integration` 브랜치에 커밋·푸시합니다.

## 설치 및 통합 실행

저장소 최상위 폴더의 PowerShell에서 실행합니다.

```powershell
python -m pip install -r requirements.txt

$env:SSLC_LAB_PASSWORD="실습 비밀번호"
$env:ROOKIESCAN_PASSWORD="실습 비밀번호"

python -m pipeline --config pipeline/config.aws.json --authorized --no-fail-on-findings
```

일부 스캐너만 선택할 수도 있습니다.

```powershell
python -m pipeline --config pipeline/config.aws.json --authorized --only authn,authz --no-fail-on-findings
```

기본 출력 위치:

```text
pipeline/results/
├─ authn.json
├─ authz.json
├─ sqli.json
├─ runtime-configs/
└─ aggregate.json
```

## 테스트

현재 인증 4개, 인가 3개, SQLi 13개, 통합 변환 3개 테스트가 통과한 상태입니다.

```powershell
python -m unittest discover -s pipeline/tests -v
```

새 스캐너를 연결한 후에는 해당 스캐너의 단독 테스트와 공통 파이프라인 테스트를 모두 실행해야 합니다.
