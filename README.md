# ROOKIESCAN 통합 설계 안내

`main` 브랜치는 Streamlit 입력, Sink 탐색, OpenAI function call, 보고서 작성을 위한
최소 구조만 정리한다. 이 단계에는 실행 코드를 넣지 않았다.

- [통합 구조 설계](docs/ARCHITECTURE.md)
- [보고서 형식 설계](docs/REPORT_SPEC.md)

현재 파일 업로드·다운로드 스캐너의 사용법은 아래에 유지한다.

---

# fileio_scanner — 파일 업로드/다운로드 취약점 블랙박스 스캐너 (JSON 출력)

허가된 대상에만 사용하세요. **설정 JSON 하나**만 두면 어떤 사이트에도 적용됩니다.
사이트 주소·계정·기능 경로만 적으면, 나머지(필드명·확장자·다운로드 패턴 등)는
**코드가 자동으로 정찰(recon)해서 채웁니다.** 결과는 **JSON finding 배열**로 출력됩니다.

---

## 1. 빠른 시작

```bash
cd fileio-scanner
python -m fileio_scanner --config targets/sslc_lab_minimal.json
```

출력: `output/<name>_result.json` — finding 배열(기계 판독용)

CLI 옵션:
| 옵션 | 설명 |
|---|---|
| `--config, -c` | 타깃 설정 JSON (필수) |
| `--out, -o` | 결과 JSON 경로 지정 |

---

## 2. 최소 설정 (권장)

사용자가 적는 것은 **5가지뿐**입니다.

```json
{
  "target_name": "mysite",
  "base_url": "http://127.0.0.1:8080",
  "login_path": "/login",
  "credentials": {
    "victim":   { "userId": "student1", "password": "Lab1234!" },
    "attacker": { "userId": "student2", "password": "Lab1234!" },
    "admin":    { "userId": "admin",    "password": "Lab1234!" }
  },
  "upload_path": "/my-class/board/write/qna",
  "notice_path": "/my-class/board/write/notice"
}
```

| 적는 값 | 의미 | 필수 |
|---|---|---|
| `base_url` | 대상 사이트 주소 | ✅ |
| `login_path` | 로그인 폼이 제출되는 경로 | ✅ |
| `credentials.victim` | 기준 계정(파일 주인) | ✅ |
| `credentials.attacker` | 낮은 권한 계정 — IDOR 판정 기준 | 권장 |
| `credentials.admin` | 관리자 계정 — 수직 권한상승 표적 | 선택 |
| `upload_path` | 업로드 폼 경로 | ✅ |
| `notice_path` | (선택) 관리자 전용 쓰기 경로 | 선택 |

### 코드가 자동으로 채우는 값 (recon.py)
로그인/업로드 폼을 파싱하고 프로브 파일을 1회 올려서 CSRF 필드명, 아이디/비번
필드명, 파일 필드명, 추가 폼필드, 허용 확장자, 다운로드 링크 패턴, ID 열거 범위,
업로드 성공 지표를 자동 탐지합니다. 실행 시 `[recon] ...` 로 결과가 출력됩니다.

---

## 3. 검사 항목 (커버리지)

**업로드**: 위험확장자(php/jsp/asp/aspx/exe), 저장형 XSS(HTML/SVG), 이중확장자, 대소문자,
트레일링 점/공백, 널바이트, 대체확장자(phar/phtml), MIME 위조, 매직바이트 폴리글랏,
파일명 경로조작, .htaccess/web.config, CRLF 파일명, 업로드 인증 누락, 접근제어 우회(강제 브라우징).

**다운로드**: 경로순회/LFI(인코딩·우회 변형 9종), 수평 IDOR, 수직 권한상승,
순차 ID 열거, 인증 누락, Content-Disposition inline(XSS), X-Content-Type-Options 누락.

---

## 4. 계정 역할 매트릭스

취약점의 정의는 "**권한 낮은 사용자가 하면 안 되는 걸 하는가**" 입니다.

| 역할 | 계정 | 용도 |
|---|---|---|
| victim | 일반1 | 파일을 올려두는 주인 |
| **attacker** | 일반2 | **낮은 권한으로 남의 파일 접근 시도 → 판정 기준** |
| admin | 관리자 | "관리자 파일을 일반유저가 뺏는가"의 **표적** |

> admin 세션을 "주체"로 스캔하면 모든 게 허용돼 취약점이 안 잡힙니다.

---

## 5. 출력 스키마 (finding 1건)

```json
{
  "scan_id": "SCAN-001",
  "category": "IDOR - Horizontal (Download)",
  "target_url": "http://.../download/23",
  "method": "GET",
  "parameter": "id",
  "payload": "/download/23",
  "status_code": 200,
  "result": "VULNERABLE",        // VULNERABLE | POTENTIAL | SAFE | INFO | ERROR
  "severity": "HIGH",            // CRITICAL | HIGH | MEDIUM | LOW | INFO
  "evidence": "...판단 근거...",
  "details": { }
}
```
최상위에 `meta`(대상/시각/집계)와 `findings`(배열)이 함께 저장됩니다.
`SAFE`(방어됨) 항목도 결과에 포함되어 점검 범위를 함께 보여줍니다.

---

## 6. 자동 탐지가 안 통할 때 — 수동 override

recon 은 서버 렌더링 HTML 폼 기준으로 동작합니다. 아래 경우엔 자동 탐지가
빗나갈 수 있고, 그때는 **해당 값만 설정에 직접 적으면** 그 값이 우선합니다
(recon 은 이미 있는 값을 덮어쓰지 않음). 전체 상세 설정 예시는 `targets/_template.json` 참고.

| 상황 | 증상 | 수동으로 적을 값 |
|---|---|---|
| 로그인이 JS/SPA/API 기반 | `[recon] 로그인필드 {}` | `auth` 블록 전체 |
| 업로드 폼을 못 찾음 | `파일필드=file`(기본값 추정) | `upload.file_field`, `upload.extra_fields` |
| 다운로드가 POST이거나 링크 미노출 | `다운로드=None` | `download` 블록 |
| ID가 UUID/문자열 | 열거 불가 | 열거는 자연히 비활성(정상) |
| 성공 지표 오탐 | 멀쩡한데 거부로 뜸 | `upload.success_indicators` |
| 자체서명 HTTPS | TLS 오류 | `"verify_tls": false` |
| Burp로 트래픽 보기 | — | `"proxy": "http://127.0.0.1:8080"` |

> `type: "none"` 이면 비인증 대상으로 동작합니다.
> `download` 블록을 통째로 빼면 다운로드 검사를 건너뛰고 업로드만 점검합니다.

---

## 7. 구조

```
fileio_scanner/
  recon.py            자동 정찰 + 설정 정규화 (최소설정 → 완전설정)
  client.py           범용 로그인/CSRF/업로드/다운로드
  checks_upload.py    업로드 취약점 체크 (페이로드 매트릭스)
  checks_download.py  다운로드 취약점 체크 (IDOR/경로순회/열거 등)
  finding.py          출력 JSON 스키마(Finding)
  engine.py           오케스트레이터 → findings + 요약
  __main__.py         CLI (JSON 출력)
targets/
  _template.json              전체 필드 주석 템플릿
  sslc_lab_minimal.json       최소 설정 예시 (권장)
  sslc_lab.json               상세 설정 예시
  sslc_lab_notice_admin.json  관리자 전용 기능 진단 예시
output/                       결과 JSON
```

---

## 8. 확장 지점
- `checks_upload.PAYLOADS` 에 업로드 페이로드 추가 → 즉시 커버리지 확대
- `checks_download.TRAVERSAL` 에 경로순회 변형 추가
- 새 체크 함수는 `Finding` 리스트만 반환하면 engine 이 scan_id 채번·정렬·집계
- `recon.py` 의 폼 파서/탐지 규칙 보강으로 자동화 적용 범위 확대
