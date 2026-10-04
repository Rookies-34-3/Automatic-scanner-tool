# ROOKIESCAN

Streamlit에서 허가받은 대상을 입력받아 Sink를 찾고, OpenAI function call로 적절한
취약점 검사 모듈을 선택·실행한 뒤 통합 JSON 보고서를 만드는 도구

## 현재 구조

```text
Automatic-scanner-tool/
├─ streamlit_app.py
├─ sink_finder.py
├─ openai_module.py
├─ report_writer.py
├─ .env                     # 로컬 OpenAI API 키 설정
├─ module/                  # 취약점 검사 function tool
│  ├─ tool_registry.py      # Function tool 정의와 안전한 실행 라우터
│  ├─ scanner_tools.py      # 팀별 스캐너 공통 입출력 어댑터
│  ├─ contracts.py          # 공통 입력·출력 정규화
│  ├─ authn_scanner/        # 불충분한 인증 절차
│  ├─ authz_scanner/        # IDOR/BOLA 권한 검증
│  ├─ sqli/                 # SQL Injection
│  ├─ xss/                  # Reflected XSS
│  ├─ ssrf/                 # SSRF verifier
│  ├─ fileio_scanner/       # 파일 업로드·다운로드
│  └─ scan/                 # 관리자 노출·디렉터리 인덱싱·포트
├─ docs/
└─ output/
```

`streamlit_app.py`는 대상 URL과 세션 쿠키를 입력받고 Sink 찾기를 실행한다.
Sink 찾기를 누르면 입력 화면을 로딩 표시로 바꾸고, 수집 후에는 대상 주소·발견 개수와
경로·입력 필드·후보 tool·대표 URL 표를 `Sink 탐색 보고서` 화면에 표시한다.
집계 결과는 `output/openai-sinks-호스트-포트-날짜시각-식별자.json`으로 저장하고,
AI 분석 화면은 저장된 JSON을 읽어 사용한다. 새로 Sink를 찾을 때마다 별도 파일을 만든다.
`취약점 분석하기`는 별도 AI 분석 화면으로 이동해 진행 상태와 `AI 분석 보고서`를 표시한다.
AI 화면의 `뒤로가기`는 Sink 탐색 보고서로, Sink 화면의 `뒤로가기`는 기존 입력 화면으로 돌아간다.
AI 화면을 다시 열 때는 저장된 결과를 보여주며, 분석 실패 시 `다시 시도`를 누를 수 있다.
`sink_finder.py`는 입력한 웹사이트의 링크·폼·JavaScript에서 엔드포인트와 입력 후보를 수집한다.
AWS에 배포한 도메인이나 공인 IP도 `http` 또는 `https` URL로 입력할 수 있으며,
크롤러는 입력 URL과 동일한 출처의 주소만 방문한다.
`openai_module.py`는 전달 데이터 집계와 Responses API function call을 담당한다.
AI가 Sink 후보에 허용된 함수만 선택하면 애플리케이션이 로컬 스캐너를 실행하고 결과를
AI에 돌려줘 근거를 요약한다. 세션 쿠키와 자격 증명은 AI 입력에 포함하지 않는다.
후보가 많은 사이트에서는 한 AI 응답에 최대 20개씩 나누어 Function call을 수행하고,
모든 스캐너 결과를 모은 뒤 한 번의 최종 요약을 생성한다.
`report_writer.py`는 공통 finding과 대시보드용 그룹을 함께 가진 최종 JSON을 생성한다.

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

각 Function tool의 AI 공개 입력은 다음 세 필드로 통일한다.

```json
{"url":"https://target/path","method":"GET","parameters":[{"name":"id","location":"path"}]}
```

세션 쿠키는 Streamlit에서 받은 뒤 `execute_tool()`이 로컬 실행 시점에만 주입한다.
공통 출력은 `scanner_id`, `name`, `url`, `method`, `parameters`, `vuln`, `result`,
`severity`, `details`를 사용하며 `vuln`은 `VULNERABLE`, `PASS`, `REVIEW`, `ERROR` 중 하나다.

등록 함수는 `scan_sqli`, `scan_reflected_xss`, `scan_ssrf`, `scan_authn`, `scan_authz`,
`scan_fileio`, `scan_admin_exposure`, `scan_directory_indexing`, `scan_portscan`이다.

초기 `main`에서 정의한 `module/analysis_stub.py`의
`analyze_endpoint_stub(url, method, parameters, vulnerability_type)` 계약도 그대로 유지한다.
이제 이 함수는 임시 결과를 반환하지 않고 `vulnerability_type`을 실제 등록 스캐너로 연결한다.
새 Function tool은 더 구체적인 함수명을 사용하지만, 기존 stub 호출부도 깨지지 않는다.

AI 없이 어댑터 하나를 직접 확인할 때는 다음처럼 호출할 수 있다. 실제 세션 값은 코드나
설정 파일에 저장하지 말고 실행 시점에만 전달한다.

```python
from module.tool_registry import execute_tool

findings = execute_tool(
    "scan_sqli",
    {
        "url": "http://127.0.0.1:8080/search",
        "method": "GET",
        "parameters": [{"name": "content", "location": "query"}],
    },
    session_cookie="",
)
```

## 실행

프로젝트 루트의 `.env`에 발급받은 키를 입력한다.

```dotenv
OPENAI_API_KEY=여기에_발급받은_키
OPENAI_MODEL=gpt-6.1-sol
```

`get_openai_client()`는 `python-dotenv`로 해당 파일을 읽어 클라이언트를 만든다.
키가 비어 있으면 입력 안내 오류를 반환한다. `.env`는 Git에서 제외된다.

```powershell
python -m pip install -r requirements.txt
streamlit run streamlit_app.py
```

화면의 기본 입력은 대상 URL과 서로 다른 사용자 A·B의 로그인 세션 쿠키다. 쿠키는
`이름=값` 전체 형식뿐 아니라 값만 입력해도 기본 이름 `sslc_lab_session`으로 처리한다.
두 쿠키는 AI로 보내거나 결과 JSON에 저장하지 않고 실행 중에만 사용한다.

- 사용자 A 세션 쿠키: Sink 탐색, 파일 업로드와 소유자 기준 검사
- 사용자 B 세션 쿠키: IDOR/BOLA 및 다른 사용자 파일 접근 비교

SSRF 검사는 사용자 A 세션으로 실제 입력 폼과 최신 CSRF 토큰을 가져온 뒤
`action=preview`로 내부 서비스 검증 URL을 전송한다. 기본 실습 주소는
`http://internal-service:9000/course`이며, 응답에서 내부 서비스 고유 문구를 확인한 경우에만
취약점으로 판정한다.

이 값이 없어서 안전하게 자동 판정할 수 없는 검사는 오탐을 만들지 않고 `REVIEW`로 남긴다.

계정 기반 스캐너 설정은 필요할 때만 환경변수로 지정한다. 설정 파일과 비밀번호는 Git에
올리지 않는다.

```dotenv
ROOKIESCAN_AUTHN_CONFIG=C:/private/authn.json
ROOKIESCAN_AUTHZ_CONFIG=C:/private/authz.json
ROOKIESCAN_FILEIO_CONFIG=C:/private/fileio.json
SSRF_PROBE_URL=http://internal-service:9000/course
SSRF_EXPECTED_MARKERS=SSRF SUCCESS - internal-service reached|internal-service:9000 reached
```

안전한 설정 템플릿은 `examples/*-config.example.json`, 최종 대시보드 입력 예시는
`examples/final-output.example.json`에서 확인할 수 있다.

## 통합 흐름

```text
Streamlit 입력
    → Sink 탐색
    → 경로별 집계와 입력 형태 보존
    → OpenAI function call
    → module/의 취약점 검사 함수 실행
    → 공통 스키마 정규화
    → output/scan-results-*.json 생성
```

- [구조 설계](docs/ARCHITECTURE.md)
- [Sink 탐색 설계](docs/SINK_FINDER_DESIGN.md)
- [보고서 형태](docs/REPORT_SPEC.md)
- [스캐너 실행 메서드](docs/SCANNER_METHODS.md)
