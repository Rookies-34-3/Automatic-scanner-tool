# ROOKIESCAN

ROOKIESCAN은 웹 애플리케이션의 취약점 후보 입력 지점을 탐색하고, AI가 선택한 로컬 스캐너로 검사한 뒤 대시보드와 PDF 진단 보고서로 결과를 제공하는 도구입니다.

취약점 판정과 증거 수집은 Python 스캐너가 수행합니다. AI는 검사 도구 선택, 수집된 결과의 해석, 총평과 공격 시나리오 작성에 사용합니다. PDF 생성은 기존 분석과 기준 문서를 재사용하며 추가 AI 호출 없이 수행합니다.

## 주요 기능

- 링크·폼·JavaScript에서 엔드포인트와 입력 후보를 수집하고 검사 후보를 분류합니다.
- OpenAI Function Calling으로 후보에 허용된 스캐너를 선택하고 로컬에서 실행합니다.
- SQLi, 반사형 XSS, SSRF, 인증·권한 검증, 파일 업로드·다운로드, 관리자 페이지 노출, 디렉터리 인덱싱, 포트를 검사합니다.
- 전체 판정, 탐지 근거, 대응 방안, 수동 검토 항목과 공격 시나리오를 대시보드에 표시합니다.
- 2026년 주요정보통신기반시설 가이드의 웹 장을 검색하여 A4 PDF 진단 보고서를 생성합니다.

## 빠른 실행

### 1. 의존성 설치

프로젝트 루트에서 실행합니다.

```sh
python -m pip install -r requirements.txt
```

주요 의존성은 Streamlit, requests, BeautifulSoup, pandas, Altair, OpenAI SDK, pypdf, ReportLab입니다.

### 2. OpenAI 설정

프로젝트 루트에 `.env` 파일을 만들고 API 키를 설정합니다. `.env`는 Git에서 제외됩니다.

```dotenv
OPENAI_API_KEY=발급받은_API_키
OPENAI_MODEL=gpt-6.1-sol
```

`OPENAI_MODEL`은 `openai_module.py`에서 사용하는 모델 설정입니다. 별도 추가 분석 모듈인 `ai_analyzer.py`는 현재 코드에 지정된 `gpt-6.1-sol`을 사용합니다.

### 3. 통합 검사 화면 실행

```sh
python -m streamlit run streamlit_app.py
```

1. 대상 URL과 서로 다른 사용자 A·B의 로그인 세션 쿠키를 입력합니다.
2. **Sink 찾기**로 후보 엔드포인트와 입력 항목을 수집합니다.
3. **취약점 분석하기**로 스캐너를 실행합니다.
4. 추가 분석이 끝나면 대시보드에서 결과를 확인합니다.
5. **보고서 생성**을 누른 뒤 **PDF 보고서 다운로드**로 저장합니다.

세션 쿠키는 `쿠키명=값` 형식 또는 쿠키 값만 입력할 수 있습니다. 값만 입력할 때 기본 이름은 `sslc_lab_session`입니다. 다른 사이트에서는 실제 쿠키명을 포함한 형식을 사용하십시오.

| 세션 | 용도 |
|---|---|
| 사용자 A | Sink 탐색, 인증된 기능 검사, 소유자 기준 요청 |
| 사용자 B | 다른 사용자 접근과 IDOR/BOLA 비교 검사 |

쿠키는 AI의 도구 인자에 포함하지 않고 로컬 스캐너 실행 시 주입합니다. 검사 과정의 POST·업로드 요청은 실제 테스트 데이터를 저장하거나 상태를 변경할 수 있으므로, 승인된 대상과 범위에서 실행하고 잔여 데이터를 정리해야 합니다.

### 저장된 결과로 대시보드만 실행

```sh
python -m streamlit run app.py
```

기본적으로 `output/scan-results.json`과 `output/analysis.json`을 읽습니다. 대시보드를 실행하거나 새로고침하는 것만으로 대상 사이트를 다시 검사하지는 않습니다.

## 프로젝트 구조

```text
Automatic-scanner-tool/
├─ streamlit_app.py          # 입력 → 탐색 → 검사 → 추가 분석 → 대시보드 연결
├─ sink_finder.py            # AI 없이 후보 엔드포인트·입력 지점 탐색
├─ openai_module.py          # OpenAI 도구 선택, 로컬 실행, 결과 요약
├─ ai_analyzer.py            # 총평·영향·대응 방안·공격 시나리오 추가 분석
├─ report_writer.py          # 기존 검사 결과의 JSON 구성·저장
├─ report.py                 # 두 JSON과 기준 문서로 PDF 보고서 생성
├─ app.py                    # 결과 대시보드, report.run() 호출
├─ dashboard.css             # 대시보드 스타일
├─ requirements.txt
├─ .streamlit/config.toml    # 밝은 화면 테마
├─ .env                     # 로컬 API 키, Git 제외
├─ module/
│  ├─ tool_registry.py       # 도구 스키마, 허용 인자 검증, 실행 라우터
│  ├─ scanner_tools.py       # 각 스캐너의 공통 입출력 어댑터
│  ├─ contracts.py           # 판정·파라미터·세션 쿠키 정규화
│  ├─ analysis_stub.py       # 기존 호출 계약을 실제 스캐너에 연결
│  ├─ authn_scanner/         # 불충분한 인증 절차
│  ├─ authz_scanner/         # IDOR/BOLA 및 객체 접근 권한
│  ├─ sqli/                 # SQL Injection
│  ├─ xss/                  # Reflected XSS, 정상 폼 구성, 한국어 근거
│  ├─ ssrf/                 # 내부 서비스 접근 증거 검증
│  ├─ fileio_scanner/        # 파일 업로드·다운로드 검사
│  └─ scan/                 # 관리자 노출·디렉터리 인덱싱·포트 검사
├─ examples/                # 스캐너 설정과 결과 형식 예시
├─ docs/
│  ├─ reference/2026-guide.pdf  # 기준 PDF
│  ├─ fonts/                # PDF용 한글 글꼴과 라이선스
│  └─ report-generation.md  # 문서 검색·보고서 생성 설명
└─ output/                  # 실행 결과, Git 제외
   ├─ openai-sinks-*.json    # 탐색할 때마다 별도 저장
   ├─ scan-results.json     # 최신 검사 결과
   ├─ analysis.json         # 해당 검사에 대한 추가 AI 분석
   ├─ rag-index/            # 기준 문서의 로컬 검색 인덱스
   └─ reports/              # PDF 보고서와 증적 보관용 JSON
```

`report_writer.py`와 `report.py`의 역할은 구분되어 있습니다. 통합 스캐너는 기존 `report_writer.py`로 검사 JSON을 저장하고, 대시보드의 보고서 버튼은 `report.py`의 `run()`을 호출합니다.

## 전체 파이프라인

```text
대상 URL + 사용자 A·B 세션 쿠키
    → sink_finder.py: 링크·폼·입력 후보 탐색
    → openai_module.py: 요청 형태 집계 및 AI 도구 선택
    → module/: 로컬 스캐너 실행, 판정 및 증거 수집
    → report_writer.py: output/scan-results.json 저장
    → ai_analyzer.py: 총평·대응 방안·공격 시나리오 분석
    → output/analysis.json 저장
    → app.py: 대시보드 표시
    → 보고서 생성 버튼
    → report.py: 기준 문서 검색 + 기존 결과 조합
    → output/reports/: PDF 및 보관 JSON 생성
```

### Sink 탐색과 도구 선택

Sink는 취약점이 확정된 위치가 아니라 **검사가 필요한 입력 후보 지점**입니다. 탐색 단계에서는 AI를 호출하지 않고 링크, 폼, JavaScript와 규칙으로 후보를 수집합니다. 크롤러는 입력한 URL과 동일한 출처의 주소를 방문합니다.

`prepare_sinks_for_openai()`는 같은 출처·HTTP 메서드·경로 템플릿을 묶고, 파라미터나 전송 형식이 다른 요청은 `request_variants`로 보존합니다. `/uploads/` 파일은 디렉터리와 확장자 등으로 묶되 디렉터리 경로는 별도로 유지합니다.

AI는 제공된 후보에 허용된 함수와 URL·메서드·파라미터 조합만 선택할 수 있습니다. 로컬 디스패처가 선택을 검증한 후 실행합니다. 후보가 많으면 도구 선택을 분할하며, 현재 한 선택 묶음의 제한은 20개, 전체 도구 호출 제한은 100개입니다.

### AI 사용 범위

| 단계 | 처리 방식 |
|---|---|
| 엔드포인트·입력 후보 탐색 | Python 규칙 기반, AI 호출 없음 |
| 실행할 스캐너 선택 | `openai_module.py`의 Function Calling |
| 취약점 판정·근거 수집 | 각 Python 스캐너 |
| 통합 검사 결과 요약 | `openai_module.py`의 AI 요약 |
| 총평·예상 영향·대응 방안·공격 시나리오 | `ai_analyzer.py`의 추가 AI 분석 |
| 집계·판정 설명·기준 문서 검색·PDF 구성 | `report.py`, 추가 AI 호출 없음 |

전체 AI 호출 수가 항상 두 번인 것은 아닙니다. 후보 수와 도구 호출 흐름에 따라 선택 요청이 여러 번 발생할 수 있습니다. 추가 분석은 기존 검사 증거를 설명하며, 확인되지 않은 RCE·권한 획득·데이터 탈취를 확정하지 않도록 구성되어 있습니다.

## 결과 형식과 판정 의미

등록 스캐너는 다음과 같습니다.

```text
scan_sqli                  scan_reflected_xss          scan_ssrf
scan_authn                 scan_authz                  scan_fileio
scan_admin_exposure        scan_directory_indexing     scan_portscan
```

AI에 공개하는 도구 입력은 다음 세 필드입니다.

```json
{
  "url": "https://target.example/search",
  "method": "GET",
  "parameters": [{"name": "content", "location": "query"}]
}
```

공통 검사 결과는 `scanner_id`, `name`, `url`, `method`, `parameters`, `vuln`, `result`, `severity`, `details`를 사용합니다.

| 판정 | 의미 |
|---|---|
| `VULNERABLE` | 스캐너가 취약 판정에 사용한 증거를 확인함. 실제 영향 범위는 추가 검증 필요 |
| `PASS` | 실행한 조건에서 취약점 증거가 발견되지 않음. 시스템 전체의 안전을 보장하지 않음 |
| `REVIEW` | 증거 부족이나 요청 조건 등의 이유로 판정 보류. 수동 확인 필요 |
| `ERROR` | 통신·실행 오류로 검사 미완료. 원인 해결 후 재검사 필요 |

HIGH·CRITICAL 등급만으로 시스템 장악이나 RCE가 확인된 것은 아닙니다. 스캐너의 심각도와 기준 문서의 항목 중요도도 별도로 해석합니다.

### 두 JSON의 역할

| 파일 | 주요 내용 |
|---|---|
| `scan-results.json` | 대상, 검사 시각, 집계, 전체 `findings`, 대시보드용 `results`, 통합 AI 요약 |
| `analysis.json` | 출처 해시, 분석 버전·모델, 종합 위험도, 총평, `key_findings`, 공격 시나리오, 조치 우선순위 |

대시보드의 대응 방안은 위치·파라미터·근거가 일치하는 `analysis.key_findings[].recommendation`을 우선 사용하고, 없으면 스캐너의 조치 정보를 사용합니다.

## PDF 진단 보고서

대시보드에서 **보고서 생성 → PDF 보고서 다운로드**를 사용하거나, 프로젝트 루트에서 직접 실행합니다.

```sh
python report.py
```

입력과 출력 경로를 직접 지정할 수도 있습니다.

```sh
python report.py --scan output/scan-results.json --analysis output/analysis.json --guide docs/reference/2026-guide.pdf --start-page 676 --output-dir output/reports
```

기준 PDF의 기본 경로는 `docs/reference/2026-guide.pdf`이며, `--guide` 또는 `ROOKIESCAN_GUIDE_PDF` 환경변수로 변경할 수 있습니다. 상대 경로는 프로그램 파일이 있는 프로젝트 디렉터리를 기준으로 해석합니다.

### 문서 검색과 작성 방식

- 2026년 가이드의 PDF 뷰어 기준 **676페이지부터 웹 장만** 읽습니다. 현재 기준 파일의 웹 장은 676~786페이지이며 다음 장은 제외합니다.
- 점검 항목의 목적, 보안 위협, 판단 기준과 조치 방법을 추출하고 페이지별 청크를 로컬 BM25로 검색합니다.
- 검색 문맥을 새로운 LLM에 보내는 대신, 검색한 기준과 기존 두 JSON을 Python 템플릿으로 조합합니다. **보고서 생성 시 추가 AI 호출은 0회**입니다.
- `analysis.json.source_hash`가 현재 스캔과 일치하지 않으면 이전 AI 총평·대응 방안·시나리오를 사용하지 않습니다.
- 기준 항목과 페이지를 표시하고, 자동 판정과 공식 기준 적합성을 구분합니다. 포트 검사처럼 웹 장에 직접 대응하지 않는 항목은 억지로 연결하지 않습니다.

### 문서 구성

표지, 문서 관리, 실제 페이지에 연결된 목차, 진단 개요, 종합 위험 평가, 주요 취약점 목록, 항목별 상세 분석, 수동 검토·재검사, 공격 시나리오, 개선 우선순위, 자동화 검사 주의사항, 전체 결과와 기준 연결 부록을 포함합니다.

A4 PDF에 한글 글꼴, 머리말·꼬리말, 페이지 번호와 북마크를 포함합니다. 날짜는 한국 시간(KST)으로 표시합니다. Word나 LibreOffice 없이 ReportLab으로 직접 생성합니다.

`output/reports/`에는 고유한 이름의 PDF와 증적 보관용 JSON을 함께 저장합니다. 화면에는 PDF 다운로드 버튼 하나만 표시합니다. 검토자·승인자·조치 완료 상태는 임의로 작성하지 않습니다.

## 폼 검사 개선

### XSS

`module/xss/` 안에서 폼 구성과 한국어 판정 근거를 처리합니다.

- POST 검사 직전에 실제 폼을 가져와 최신 CSRF 토큰과 세션 쿠키를 사용합니다.
- 필수 제목·본문과 유효한 선택값을 구성하고 검사 대상 필드 하나만 교체합니다.
- 숨김 토큰·비밀번호·파일·선택형 항목은 일반 텍스트 주입 대상에서 제외합니다.
- 현재 화이트박스 대상에 맞춰 `/login`은 기존 인증 쿠키를 제외한 새 세션으로 검사합니다. 새로 발급받은 비인증 세션 쿠키는 유지합니다.
- HTTP 오류는 PASS로 처리하지 않고 REVIEW·ERROR로 구분하며, 서버 오류 설명을 수집합니다.
- 동일 사유는 입력 항목별로 묶어 한국어로 출력하고, 개별 증거는 `details.raw_result`에 보관합니다.

검사 문자열의 반영은 실제 브라우저 실행과 구분해야 합니다. 현재 폼 수집은 HTML 기반이며, JavaScript가 생성하거나 별도 API·헤더로 전달하는 토큰은 추가 처리가 필요합니다. `/login` 예외도 다른 사이트의 모든 로그인 경로를 자동 식별하는 기능은 아닙니다.

### SSRF

사용자 A 세션으로 폼과 CSRF 토큰을 수집하고 `action=preview`로 검증 URL을 전송합니다. 내부 서비스의 고유 증거 문구가 확인된 경우 취약 판정을 내립니다.

기본 실습 검증 URL은 `http://internal-service:9000/course`입니다. 대상 환경에 맞게 URL과 기대 문구를 설정해야 합니다.

## 선택 설정과 스캐너 직접 실행

필요한 경우 스캐너 설정 파일과 검증 대상을 환경변수로 지정합니다.

```dotenv
ROOKIESCAN_AUTHN_CONFIG=/private/authn.json
ROOKIESCAN_AUTHZ_CONFIG=/private/authz.json
ROOKIESCAN_FILEIO_CONFIG=/private/fileio.json
SSRF_PROBE_URL=http://internal-service:9000/course
SSRF_EXPECTED_MARKERS=SSRF SUCCESS - internal-service reached|internal-service:9000 reached
```

설정 예시는 `examples/*-config.example.json`, 결과 형식 예시는 `examples/final-output.example.json`에서 확인할 수 있습니다. 비밀번호와 실제 세션 값은 코드나 Git에 저장하지 않습니다.

AI 없이 스캐너 하나를 실행할 수 있습니다.

```python
from module.tool_registry import execute_tool

findings = execute_tool(
    "scan_reflected_xss",
    {
        "url": "http://127.0.0.1:8080/login",
        "method": "POST",
        "parameters": [
            {"name": "userId", "location": "form"},
            {"name": "password", "location": "form"},
            {"name": "csrf_token", "location": "form"},
        ],
    },
    session_cookie="",
)
```

## 결과 재사용과 트러블슈팅

| 상황 | 확인 사항 |
|---|---|
| 코드 수정 후 이전 동작이 계속됨 | 실행 중인 Python이 이전 하위 모듈을 유지할 수 있음. Streamlit 프로세스를 종료 후 재실행하고 새 검사 수행 |
| 대시보드 새로고침 후 결과가 그대로임 | 저장된 JSON을 다시 표시하는 동작임. 새 결과는 탐색·분석을 다시 실행해야 생성됨 |
| 같은 URL을 다시 검사함 | URL만으로 검사 생략하지 않음. `scan-results.json`은 최신 결과로 덮어씀 |
| 추가 분석 API 호출이 생략됨 | 입력 JSON 해시·분석 버전·모델이 같은 기존 `analysis.json`을 재사용한 경우 |
| CSRF 적용 후에도 HTTP 400 발생 | 필수 입력값·선택값·접근 조건과 서버 오류 설명 확인. 400만으로 CSRF 실패라고 단정하지 않음 |
| 결과 JSON을 찾지 못함 | 프로젝트 기준 경로와 현재 생성된 파일 확인. 통합 실행에서는 저장한 경로를 대시보드에 전달함 |
| PDF 의존성 오류 | `python -m pip install -r requirements.txt`로 pypdf·ReportLab 설치 |
| PDF나 한글 글꼴 파일을 찾지 못함 | `docs/reference/2026-guide.pdf`, `docs/fonts/` 파일 또는 지정한 기준 PDF 경로 확인 |

`st.session_state`에는 현재 화면의 검사 결과가 유지됩니다. `output/rag-index/`는 PDF 해시와 시작 페이지에 따른 **문서 검색 인덱스**이며, 취약점 검사 결과를 대신하는 캐시가 아닙니다. 기준 PDF가 바뀌면 새 인덱스를 생성합니다.

탐색 JSON과 PDF는 실행마다 별도 이름으로 저장하지만, `scan-results.json`과 `analysis.json`은 최신 결과용 고정 파일입니다. 이전 진단을 보관하려면 해당 JSON을 별도로 보관하십시오.

## 관련 문서

- [구조 설계](docs/ARCHITECTURE.md)
- [Sink 탐색 설계](docs/SINK_FINDER_DESIGN.md)
- [검사 결과 형식](docs/REPORT_SPEC.md)
- [스캐너 실행 메서드](docs/SCANNER_METHODS.md)
- [기준 문서 검색과 PDF 보고서](docs/report-generation.md)
- [PDF용 한글 글꼴 라이선스](docs/fonts/LICENSE.txt)
