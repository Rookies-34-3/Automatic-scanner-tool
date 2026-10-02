# ROOKIESCAN 공통 파이프라인

각 취약점 스캐너의 내부 구현은 유지하면서 공통 설정으로 실행하고 결과를 하나의 JSON으로 합칩니다.

## 현재 연결된 스캐너

- `authn`: 인증 절차 누락
- `authz`: IDOR/BOLA 권한 검증 누락
- `sqli`: Error-based / Boolean-based SQL Injection

새 스캐너는 먼저 독립 실행과 개별 JSON 생성이 가능해야 하며, 이후 `runner.py`의 `ADAPTERS`에 실행 정보를 추가합니다.

## 공통 입력

`config.example.json`에서 다음 값을 관리합니다.

- `target.base_url`: 검사 대상 URL
- `execution`: 병렬 실행, 제한 시간, 결과 폴더
- `scanners[].config`: 기존 스캐너 설정 파일
- `scanners[].endpoints`: 스캐너별 점검 엔드포인트와 필수 파라미터

공통 설정의 URL과 엔드포인트가 각 스캐너의 실행용 설정을 덮어씁니다. 로그인 계정 구조, CSRF 정보 등 취약점별 세부 설정은 기존 설정 파일을 재사용합니다.

## 실행

저장소 최상위 폴더의 PowerShell에서 실행합니다.

```powershell
python -m pip install -r requirements.txt
$env:SSLC_LAB_PASSWORD="실습 비밀번호"
$env:ROOKIESCAN_PASSWORD="실습 비밀번호"
python -m pipeline --config pipeline/config.example.json --authorized --no-fail-on-findings
```

AWS 시연 환경은 학생 2가 소유한 비밀 문의 테스트 데이터까지 반영한 전용 설정으로 실행합니다.

```powershell
python -m pipeline --config pipeline/config.aws.json --authorized --no-fail-on-findings
```

다른 허가된 서버에서 같은 엔드포인트 구성을 검사할 때는 `--base-url`로 URL만 덮어쓸 수도 있습니다.

일부 스캐너만 실행할 수도 있습니다.

```powershell
python -m pipeline --config pipeline/config.example.json --authorized --only authn,authz --no-fail-on-findings
```

비밀번호는 설정 및 결과 JSON에 저장하지 않습니다. 반드시 허가된 실습 대상에서만 실행합니다.

## 출력

기본 결과 폴더는 `pipeline/results`입니다.

- `authn.json`, `authz.json`, `sqli.json`: 정규화된 개별 결과
- `runtime-configs/*.json`: 공통 입력을 반영한 실행용 설정(비밀번호 미포함)
- `aggregate.json`: 대시보드와 백엔드가 사용할 최종 통합 결과

결과값은 다음 네 가지로 통일합니다.

- `VULNERABLE`: 취약점 증거 확인
- `PASS`: 실행한 점검 범위에서 차단 또는 증거 미탐지
- `REVIEW`: 자동 판정이 어려워 수동 확인 필요
- `ERROR`: 설정, 의존성, 통신 또는 실행 오류

현재 `ai_analysis`는 연결 지점만 마련되어 있으며 `NOT_CONFIGURED`로 출력됩니다. 팀에서 AI 제공자와 입력 데이터 정책을 결정한 뒤 공통 분석 모듈을 이 단계에 연결하면 됩니다.
