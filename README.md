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
├─ module/                  # 취약점 검사 function tool
├─ docs/
└─ output/
```

`streamlit_app.py`는 대상 URL과 세션 쿠키를 입력받고 Sink 찾기를 실행한다.
Sink 찾기를 누르면 입력 화면을 로딩 표시로 바꾸고, 수집 후에는 대상 주소·발견 개수와
경로·입력 필드·후보 tool·대표 URL 표를 `Sink 탐색 보고서` 화면에 표시한다.
`취약점 분석하기` 버튼은 준비 중 안내를 표시하고, `뒤로가기`는 기존 입력값을 복원한다.
`sink_finder.py`는 로컬 대상의 링크·폼·JavaScript에서 엔드포인트와 입력 후보를 수집한다.
`openai_module.py`에는 전달 데이터 집계를 구현했다. OpenAI API 호출과 검사 함수 실행,
취약점 분석 결과의 최종 보고서 생성은 아직 구현하지 않았다.

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

## 실행

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
