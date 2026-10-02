# ROOKIESCAN

Streamlit에서 대상을 입력받아 Sink를 찾고, OpenAI function call로 적절한 취약점 검사
모듈을 선택한 뒤 결과를 보고서로 만드는 통합 도구의 설계 브랜치다.

## 현재 구조

```text
Automatic-scanner-tool/
├─ streamlit_app.py
├─ sink_finder.py
├─ openai_module.py
├─ report_writer.py
├─ .env                     # 로컬 OpenAI API 키 설정
├─ module/                  # 취약점 검사 function tool
│  └─ analysis_stub.py      # 임시 함수와 AI에 전달할 tool 정의
├─ docs/
└─ output/
```

`streamlit_app.py`는 대상 URL과 세션 쿠키를 입력받고 Sink 찾기를 실행한다.
Sink 찾기를 누르면 입력 화면을 로딩 표시로 바꾸고, 수집 후에는 대상 주소·발견 개수와
경로·입력 필드·후보 tool·대표 URL 표를 `Sink 탐색 보고서` 화면에 표시한다.
`취약점 분석하기`는 별도 AI 분석 화면으로 이동해 진행 상태와 `AI 분석 보고서`를 표시한다.
AI 화면의 `뒤로가기`는 Sink 탐색 보고서로, Sink 화면의 `뒤로가기`는 기존 입력 화면으로 돌아간다.
AI 화면을 다시 열 때는 저장된 결과를 보여주며, 분석 실패 시 `다시 시도`를 누를 수 있다.
`sink_finder.py`는 로컬 대상의 링크·폼·JavaScript에서 엔드포인트와 입력 후보를 수집한다.
`openai_module.py`는 전달 데이터 집계와 `gpt-6.1-sol`의 Responses API 호출을 담당한다.
현재는 대표 엔드포인트 하나에 임시 함수를 호출하고, 반환값을 AI에 전달해 후보를 요약한다.
실제 취약점 검증과 `report_writer.py`의 최종 보고서 생성은 추후 연결한다.

## OpenAI 전달용 집계

`prepare_sinks_for_openai(sinks)`는 같은 출처·HTTP 메서드·경로 템플릿을 하나로 묶는다.
반환 형식은 `{"candidate_status": "unverified", "groups": [...]}`이다.
각 그룹에는 메서드·경로·후보 tool·발견 개수를 남기고, 파라미터·전송 형식·후보 tool이
다른 요청은 `request_variants`로 구분한다. 요청 형태마다 방문한 주소를 우선해 대표 URL
하나만 유지한다. 요청 형태의 `candidate_tools`가 생략되면 그룹의 tool 목록을 사용한다.

`/uploads/`의 파일은 같은 디렉터리 템플릿·마지막 확장자·후보 tool 기준으로 묶어
`/uploads/{id}/pbl/{filename}.txt` 같은 경로로 요약한다. 디렉터리 경로는 별도로 유지한다.
상세 방문 기록·응답 코드·출처·오류·후보 설명은 원본 결과에서 확인한다.

Streamlit은 원본을 `st.session_state["sinks"]`에, 전달용 요약을
`st.session_state["openai_sinks"]`에 저장한다. 원본 목록은 변경하지 않는다.

## `module/`

다른 브랜치에서 완성한 SQLi, XSS 등의 취약점 검사 파일을 가져와 두는 위치다. 각 파일은
URL, HTTP 메서드, 파라미터를 입력받아 검사 결과를 반환하는 함수를 제공한다.

`openai_module.py`는 이 함수들을 OpenAI function tool로 등록한다. 모델이 사용할 도구를
선택하면 애플리케이션이 해당 함수를 실행하고 결과를 모델에 돌려준다.

현재 등록된 함수는 `analyze_endpoint_stub(url, method, parameters)` 하나다.
AI가 요청한 URL·메서드·입력 필드가 수집 결과와 일치할 때만 호출한다.
이 함수는 입력 정보와 `status: "stub"`, `verified: false`를 반환하며 네트워크 요청을 하지 않는다.
분석 한 번에 임시 tool을 한 번 호출하며, API 요청은 호출 선택과 결과 요약의 두 번이다.
API 키와 세션 쿠키는 AI 입력에 포함하지 않는다. 분석 결과는 세션에 저장해 화면 재실행 시 재호출하지 않는다.

## 실행

프로젝트 루트의 `.env`에 발급받은 키를 입력한다.

```dotenv
OPENAI_API_KEY=여기에_발급받은_키
```

`get_openai_client()`는 `python-dotenv`로 해당 파일을 읽어 클라이언트를 만든다.
키가 비어 있으면 입력 안내 오류를 반환한다. `.env`는 Git에서 제외된다.

```powershell
python -m pip install -r requirements.txt
streamlit run streamlit_app.py
```

## 예정 흐름

```text
Streamlit 입력
    → Sink 탐색
    → 경로별 집계와 입력 형태 보존
    → OpenAI function call
    → module/의 취약점 검사 함수 실행
    → 보고서 생성
```

다른 브랜치에서 완성한 SQLi, XSS 등의 검사 코드는 먼저 `main`으로 병합하거나 필요한
파일만 `module/`로 가져온다. function call은 다른 Git 브랜치의 파일을 직접 불러오지
않는다.

- [구조 설계](docs/ARCHITECTURE.md)
- [Sink 탐색 설계](docs/SINK_FINDER_DESIGN.md)
- [보고서 형태](docs/REPORT_SPEC.md)
