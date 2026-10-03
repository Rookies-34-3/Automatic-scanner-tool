# AuthZScanner

웹 개발자가 제공한 테스트 계정으로 동일 객체를 요청하고 응답을 비교하여 **불충분한 권한 검증(IDOR/BOLA)**을 탐지하는 핵심 검사 도구입니다. Bearer 토큰과 폼 로그인 기반 세션 인증을 지원하며, 실행 결과를 표준 JSON으로 반환합니다.

## 최종 전달 파일

- 실행 코드: `authz_scanner/`
- 최종 설정 예시: `examples/config.example.json`
- 최종 출력 예시: `examples/output.example.json`
- 자동 테스트: `tests/test_engine.py`
- 사용 설명: `README.md`

AWS 주소가 들어간 별도 설정과 실제 실행 결과 JSON은 저장소에서 제거했습니다. 대상별 설정이 필요하면 `config.example.json`을 `config.local.json`으로 복사해 사용하며, `*.local.json`은 Git에 올라가지 않습니다.

## 검사 항목

- 객체 소유자 계정의 정상 기준 요청
- 다른 사용자 토큰을 사용한 동일 객체 요청
- 선택적인 비로그인 요청
- HTTP 상태 코드, JSON 민감 필드 및 응답 유사도 비교

다른 사용자 요청이 `401`, `403`, `404`로 차단되면 정상으로 판정합니다. `2xx` 응답에서 소유자 기준 응답과 동일한 민감 데이터가 확인되면 취약점으로 판정합니다.

## 웹 개발자에게 받을 정보

- 테스트 웹의 기본 주소
- 객체 ID가 포함된 `GET` API 경로
- 인증 방식(Bearer 토큰 또는 폼 로그인 기반 세션)
- 폼 로그인 사용 시 로그인 경로, 입력 필드명, 세션 쿠키명과 두 테스트 계정
- Bearer 인증 사용 시 소유자 계정과 다른 사용자 계정의 토큰
- 소유자에게 속한 테스트 객체 ID
- 응답에서 비교할 객체 ID, 소유자, 제목, 내용 등의 민감 필드

받은 값은 [config.example.json](examples/config.example.json)을 복사한 설정 파일에 입력합니다. 실제 토큰은 설정 파일에 저장하지 않고 환경 변수 사용을 권장합니다.

## 실행

```powershell
python -m authz_scanner `
  --config examples\config.example.json `
  --authorized `
  --no-fail-on-findings
```

기본 동작은 결과 JSON을 터미널에 출력합니다. 파일 저장이 필요할 때만 선택 옵션을 추가합니다.

```powershell
--output-json result\authz.json
```

`result/`, `output/`, `*-result.json`은 생성 결과이므로 Git에 커밋하지 않습니다.

## 공통 입출력 계약

Function call과 통합 파이프라인에서 사용하는 공통 입력 필드는 `url`, `method`, `parameters`, `session_cookie`입니다. 인가 검사는 소유자와 다른 사용자의 세션이 모두 필요하므로 계정 역할과 객체 탐색 규칙은 추가 Tool 파라미터로 관리합니다. 쿠키 원문은 JSON에 저장하지 않습니다.

각 발견 결과는 다음 필드를 반드시 반환합니다.

동일한 내용은 [output.example.json](examples/output.example.json)에서도 확인할 수 있습니다.

```json
{
  "url": "http://127.0.0.1:8080/api/profiles/{user_id}",
  "method": "GET",
  "parameters": [
    {"name": "user_id", "location": "path"}
  ],
  "vuln": "VULNERABLE",
  "result": "다른 사용자 세션으로 소유자 데이터 조회에 성공했습니다."
}
```

계정 역할, 응답 유사도와 비교 증거는 `details`에 보존하며 토큰과 세션 쿠키 원문은 출력하지 않습니다.

## 핵심 구조

```text
authz_scanner/
├── engine.py       사용자 교차 요청, 응답 비교, IDOR 판정
├── cli.py          설정 입력 및 JSON 출력
├── http_auth.py    Bearer·폼 세션 인증 처리
├── __init__.py     run_scan 공개
└── __main__.py     python -m 실행 진입점
```

통합 진입점은 `from authz_scanner import run_scan`입니다. `main/module`의 Function call 어댑터에서는 이 함수를 호출합니다.

## 자체 테스트

테스트 파일은 최종 스캐너와 섞이지 않도록 `tests/`에만 보관합니다.

```powershell
python -m unittest discover -s tests -v
```

안전한 기본 버전은 `GET`, `HEAD`만 검사합니다. 무작위 ID 열거는 수행하지 않으며, 직접 구축했거나 명시적으로 허가받은 환경에서만 사용해야 합니다. 토큰과 실제 응답 본문은 결과 JSON에 포함하지 않습니다.
