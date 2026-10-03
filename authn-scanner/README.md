# AuthNScanner

웹 개발자가 제공한 보호 API에 정상·비정상 인증 요청을 자동 전송하여 **불충분한 인증 절차**를 탐지하는 핵심 검사 도구입니다. Bearer 토큰과 폼 로그인 기반 세션 인증을 지원하며, 실행 결과를 표준 JSON으로 반환합니다.

## 최종 전달 파일

- 실행 코드: `authn_scanner/`
- 최종 설정 예시: `examples/config.example.json`
- 최종 출력 예시: `examples/output.example.json`
- 자동 테스트: `tests/test_engine.py`
- 사용 설명: `README.md`

AWS 주소가 들어간 별도 설정과 실제 실행 결과 JSON은 저장소에서 제거했습니다. 대상별 설정이 필요하면 `config.example.json`을 `config.local.json`으로 복사해 사용하며, `*.local.json`은 Git에 올라가지 않습니다.

## 검사 항목

- 인증정보 없음
- 빈 Bearer 토큰
- 임의의 잘못된 토큰
- 잘못된 인증 스킴
- JWT 서명 변조 및 `alg=none`
- 실제 만료 토큰이 제공된 경우 만료 토큰

`401`, `403`, `404`는 정상 차단으로 판정합니다. 비정상 인증 상태에서 `2xx`와 민감 데이터가 반환되면 취약점으로 판정합니다.

## 웹 개발자에게 받을 정보

- 테스트 웹의 기본 주소
- 인증이 필요한 `GET` API 경로
- 인증 방식(Bearer 토큰 또는 폼 로그인 기반 세션)
- 폼 로그인 사용 시 로그인 경로, 입력 필드명, 세션 쿠키명과 정상 테스트 계정
- Bearer 인증 사용 시 정상 테스트 토큰
- 응답에서 비교할 사용자명, 이메일 등의 민감 필드
- JWT 만료 검사 시 서버가 발급한 만료 토큰

받은 값은 [config.example.json](examples/config.example.json)을 복사한 설정 파일에 입력합니다. 실제 토큰은 설정 파일에 저장하지 않고 환경 변수 사용을 권장합니다.

## 실행

```powershell
python -m authn_scanner `
  --config examples\config.example.json `
  --authorized `
  --no-fail-on-findings
```

기본 동작은 결과 JSON을 터미널에 출력합니다. 파일 저장이 필요할 때만 선택 옵션을 추가합니다.

```powershell
--output-json result\authn.json
```

`result/`, `output/`, `*-result.json`은 생성 결과이므로 Git에 커밋하지 않습니다.

## 공통 입출력 계약

Function call과 통합 파이프라인에서 사용하는 공통 입력 필드는 `url`, `method`, `parameters`, `session_cookie`입니다. 이 스캐너는 계정으로 정상 세션을 직접 만든 뒤 비정상 세션과 비교하므로 기본 `session_cookie` 값은 `null`입니다. 쿠키를 직접 전달해야 하면 원문 대신 `name`과 `value_env`를 사용합니다.

각 발견 결과는 다음 필드를 반드시 반환합니다.

동일한 내용은 [output.example.json](examples/output.example.json)에서도 확인할 수 있습니다.

```json
{
  "url": "http://127.0.0.1:8080/admin",
  "method": "GET",
  "parameters": [],
  "vuln": "VULNERABLE",
  "result": "유효하지 않은 인증 상태에서 보호 내용이 반환되었습니다."
}
```

상태 코드와 응답 비교 정보는 `details`에 보존되며 토큰과 세션 쿠키 원문은 출력하지 않습니다.

## 핵심 구조

```text
authn_scanner/
├── engine.py       요청 생성, 응답 비교, 취약 판정
├── cli.py          설정 입력 및 JSON 출력
├── http_auth.py    Bearer·폼 세션 인증 처리
├── __init__.py     run_scan 공개
└── __main__.py     python -m 실행 진입점
```

통합 진입점은 `from authn_scanner import run_scan`입니다. `main/module`의 Function call 어댑터에서는 이 함수를 호출합니다.

## 자체 테스트

테스트 파일은 최종 스캐너와 섞이지 않도록 `tests/`에만 보관합니다.

```powershell
python -m unittest discover -s tests -v
```

안전한 기본 버전은 `GET`, `HEAD`만 검사하며, 직접 구축했거나 명시적으로 허가받은 환경에서만 사용해야 합니다. 토큰과 실제 응답 본문은 결과 JSON에 포함하지 않습니다.
