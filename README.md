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
├─ docs/
└─ output/
```

`streamlit_app.py`에는 대상 URL과 세션 쿠키를 받는 입력칸만 구현되어 있다.
나머지 세 모듈은 역할 설명만 있고 실행 로직은 없다.

## 실행

```powershell
python -m pip install -r requirements.txt
streamlit run streamlit_app.py
```

## 예정 흐름

```text
Streamlit 입력
    → Sink 탐색
    → OpenAI function call
    → 취약점 검사 모듈 실행
    → 보고서 생성
```

다른 브랜치에서 완성한 SQLi, XSS 등의 검사 코드는 먼저 `main`으로 병합하거나 필요한
파일만 가져온다. 그다음 `openai_module.py`에서 검사 함수를 import하고 function tool로
등록한다. function call은 다른 Git 브랜치의 파일을 직접 불러오지 않는다.

- [구조 설계](docs/ARCHITECTURE.md)
- [보고서 형태](docs/REPORT_SPEC.md)
