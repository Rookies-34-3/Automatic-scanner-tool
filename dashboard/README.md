# ROOKIESCAN 대시보드 UI 복구본

Flask + Jinja2 + Chart.js. 이전에 제작한 네이비 헤더, 요약 카드 4개, 유형별 막대그래프, 위험도 도넛, 판정별 색상과 행 클릭 시 대응 방안 펼치기를 복구했습니다. 스캐너와 수집 도구와 독립적인 폴더입니다.

## 실행

ZIP을 압축 해제한 뒤 `dashboard` 폴더에서 PowerShell을 엽니다.

```powershell
python -m pip install -r requirements.txt
python app.py
```

브라우저에서 http://127.0.0.1:5000 으로 접속합니다. 종료는 서버 터미널에서 Ctrl+C입니다. 이미 5000번 포트에 다른 프로그램이 있다면 기존 서버를 종료하거나 app.py 마지막 줄의 port를 변경하세요.

실제 결과가 없을 때는 샘플 7건이 자동으로 열립니다. 상단 배너에 샘플 모드라고 표시됩니다. 샘플 집계는 전체 7 / 취약 4 / 양호 2 / 판정불가 1입니다. 실제 스캔이나 외부 서버 접속은 하지 않습니다. Chart.js CDN 그래프를 위해 인터넷 연결이 필요합니다. CDN 실패 시에도 카드·표·펼치기는 동작합니다.

## 실데이터 연결

이 폴더 안에 `results` 폴더를 만들고 결과 JSON 배열을 `results/findings.json`으로 저장합니다. 앱을 새로고침한 뒤 ‘실제 결과 보기’를 누르세요. 원본 스캐너 프로젝트의 결과 파일은 전달 ZIP에 포함하지 않았습니다.

- 기존 포맷: `target_url`, `parameter`, `result`(판정 문자열), `payload`, `evidence`, `status_code`.
- 팀 공통 포맷: `url`, `parameters`, `vuln`(판정 문자열), `result`(payload/evidence/status_code 등의 객체).
- 공통 추가 필드: `scan_id`, `category`, `method`, `severity`, `scanned_at`, `remediation`.

두 포맷 모두 지원합니다. parameters는 문자열 또는 문자열 배열을 표시할 수 있습니다. 매 페이지 요청마다 파일을 다시 읽습니다. 잘못된 파일/항목은 경고하고 정상 항목만 집계합니다. 여러 파일은 app.py의 FINDING_FILES 목록에 추가합니다. 파일을 단순 합산하므로 중복 결과를 넣지 마세요.

카드는 모든 항목, 막대그래프는 VULNERABLE 건수, 도넛은 SAFE/N/A를 포함한 전체 severity 분포입니다. 페이로드는 Jinja 자동 이스케이프로 실행 없이 표시하며, 그래프 데이터는 tojson으로 전달합니다.

## 팀원에게 전달할 파일

- `app.py`: 파일 로드, 호환 변환, 집계, Flask 라우트
- `templates/dashboard.html`: UI 전체(CSS와 JavaScript 포함)
- `samples/findings.json`: 화면 확인용 샘플
- `requirements.txt`: Flask 의존성
- `test_dashboard.py`: 검증 테스트

UI만 가져갈 경우 templates/dashboard.html과 app.py의 템플릿 전달 변수 구조를 참고하세요. 서버나 스캐너를 통합할 필요 없이 JSON 입력만 연결할 수 있습니다.

```powershell
python -m unittest -v
```
