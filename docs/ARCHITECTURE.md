# ROOKIESCAN 최소 구조 설계

## 구조

```text
Automatic-scanner-tool/
├─ streamlit_app.py
├─ sink_finder.py
├─ openai_module.py
├─ report_writer.py
├─ docs/
└─ output/
```

현재는 Streamlit 옆에 위 세 모듈의 위치와 역할만 정한다. 별도 패키지, 모델,
레지스트리, 어댑터, 스키마, 테스트 계층은 만들지 않는다.

## 흐름

```text
Streamlit에서 URL·세션 정보 입력
                ↓
sink_finder가 URL·메서드·파라미터·Sink 후보를 JSON으로 반환
                ↓
openai_module이 Sink에 맞는 SQLi·XSS 등 기존 검사 함수를 function call로 선택
                ↓
각 검사 함수가 결과 반환
                ↓
report_writer가 결과를 모아 보고서 생성
                ↓
Streamlit에서 결과 표시 및 다운로드
```

## 모듈 역할

### `sink_finder.py`

입력받은 대상에서 검사할 엔드포인트를 찾고 다음 정보만 반환한다.

```text
url
method
parameters
sink_candidates
```

### `openai_module.py`

Sink 결과와 현재 브랜치에서 import 가능한 취약점 검사 함수 목록을 OpenAI에 전달한다.
OpenAI의 function call 결과에 따라 SQLi, XSS, File I/O 등의 함수를 호출하고 결과를
모은다. 다른 브랜치의 파일은 먼저 `main`에 병합하거나 선택적으로 가져와야 한다.

### `report_writer.py`

모듈별 검사 결과를 받아 요약, 취약점 상세, 검사 실패·건너뜀 항목을 포함한 하나의
보고서로 만든다.

### `streamlit_app.py`

사용자 입력, 실행 버튼, 진행 상태, 최종 보고서 표시만 담당한다.

## 현재 범위

- 세 모듈을 Streamlit 진입점과 같은 위치에 생성
- SQLi, XSS 등 다른 브랜치의 코드는 아직 병합하지 않음
- 함수와 실행 로직은 아직 구현하지 않음
