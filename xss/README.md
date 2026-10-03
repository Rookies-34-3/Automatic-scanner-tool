# Reflected XSS Scanner

주어진 웹 엔드포인트(Endpoint)와 파라미터(Parameter)를 입력받아 **Reflected XSS(Cross-Site Scripting)** 가능성을 자동으로 진단하는 Python 기반 스캐너입니다.

현재 버전은 엔드포인트 자동 탐색(Crawling)이나 입력 지점 자동 탐색 없이, 사전에 정의된 URL과 파라미터를 입력받아 검사하는 방식으로 동작합니다.

---

## 1. 주요 기능

- GET 요청 지원
- POST Form 요청 지원
- 여러 Parameter 자동 검사
- Session Cookie 지원
- 입력값 Reflection 여부 확인
- HTML Context 간단 분석
- Context 기반 XSS Payload 선택
- Payload 반사 여부 검사
- 검사 결과 JSON 파일 출력

---

## 2. 프로젝트 구조

```text
project/
├── reflected_xss.py
├── input.json
├── requirements.txt : 겹쳐서 제거하였습니다
└── README.md
```

---

## 3. 요구사항

- Python 3.10 이상 권장
- `requests`

설치:

```bash
pip install requests
```

또는 `requirements.txt`를 사용하는 경우:

```bash
pip install -r requirements.txt
```

`requirements.txt`:

```text
requests
```

---

## 4. 입력 JSON 포맷

Scanner는 다음 형식의 JSON 파일을 입력으로 사용합니다.

```json
{
  "url": "http://127.0.0.1:8080/my-class/board/qna",
  "method": "GET",
  "parameters": {
    "content": "hello"
  },
  "session_cookie": "sslc_lab_session=..."
}
```

### 입력 필드

| 필드 | 설명 |
|---|---|
| `url` | 검사할 Endpoint URL |
| `method` | HTTP Method (`GET`, `POST`) |
| `parameters` | 검사할 Parameter와 기본값 |
| `session_cookie` | 인증이 필요한 경우 사용할 Session Cookie |

로그인이 필요하지 않은 경우:

```json
"session_cookie": ""
```

로 입력합니다.

---

## 5. 여러 Parameter 검사

여러 Parameter가 존재하는 경우 다음과 같이 입력합니다.

```json
{
  "url": "http://127.0.0.1:8080/search",
  "method": "GET",
  "parameters": {
    "keyword": "hello",
    "page": "1",
    "category": "all"
  },
  "session_cookie": ""
}
```

Scanner는 각 Parameter를 하나씩 변경하며 검사합니다.

```text
keyword → XSS 검사
page    → XSS 검사
category → XSS 검사
```

검사하지 않는 Parameter는 기존 값을 유지합니다.

---

## 6. 실행 방법

```bash
python reflected_xss.py input.json
```

기본 출력 파일:

```text
xss_result.json
```

출력 파일명을 지정하려면:

```bash
python reflected_xss.py input.json -o result.json
```

---

## 7. 동작 과정

Scanner는 다음 순서로 동작합니다.

```text
Endpoint 입력
    │
    ▼
Parameter 선택
    │
    ▼
Canary 문자열 삽입
    │
    ▼
HTTP Request
    │
    ▼
Response Reflection 확인
    │
    ├─ Reflection 없음
    │      └─ 취약 가능성 없음
    │
    ▼
Context 분석
    │
    ▼
Context별 XSS Payload 삽입
    │
    ▼
HTTP Request
    │
    ▼
Payload 반사 여부 검사
    │
    ▼
JSON 결과 생성
```

---

## 8. Canary

실제 XSS Payload를 바로 전송하기 전에 고유한 테스트 문자열(Canary)을 사용해 입력값이 HTTP Response에 반사되는지 먼저 확인합니다.

예:

```text
XSS_CANARY_a12b34cd
```

응답에서 Canary가 발견되지 않으면 해당 Parameter에 대한 추가 XSS 테스트를 수행하지 않습니다.

---

## 9. Context 분석

현재 Scanner는 입력값이 반사되는 위치를 간단히 분석하여 다음 Context 중 하나로 분류합니다.

```text
HTML_TEXT
HTML_ATTRIBUTE
JAVASCRIPT
UNKNOWN
```

예:

```html
<div>XSS_CANARY</div>
```

```text
HTML_TEXT
```

```html
<input value="XSS_CANARY">
```

```text
HTML_ATTRIBUTE
```

```html
<script>
const value = "XSS_CANARY";
</script>
```

```text
JAVASCRIPT
```

Context에 따라 서로 다른 테스트 Payload를 사용합니다.

---

## 10. 출력 JSON 포맷

출력은 다음 구조를 사용합니다.

```json
{
  "url": "http://127.0.0.1:8080/my-class/board/qna",
  "method": "GET",
  "parameters": {
    "content": "hello"
  },
  "vuln": true,
  "result": [
    {
      "parameter": "content",
      "vulnerable": true,
      "context": "HTML_TEXT",
      "payload": "<svg onload=alert(1337)>",
      "evidence": "...<svg onload=alert(1337)>..."
    }
  ]
}
```

### 출력 필드

| 필드 | 설명 |
|---|---|
| `url` | 검사 대상 URL |
| `method` | 사용된 HTTP Method |
| `parameters` | 원본 Parameter |
| `vuln` | 취약 가능성 발견 여부 |
| `result` | Parameter별 검사 결과 |

---

## 11. `vuln` 판정

다음 조건으로 전체 취약 여부를 판단합니다.

```text
모든 Parameter 안전
→ vuln = false

Parameter 중 하나 이상 취약 가능성 발견
→ vuln = true
```

각 Parameter에 대한 상세 결과는 `result` 배열에서 확인할 수 있습니다.

---

## 12. 취약하지 않은 경우

입력값이 Response에 반사되지 않는 경우:

```json
{
  "parameter": "content",
  "vulnerable": false,
  "reason": "input value was not reflected in response"
}
```

Payload가 HTML Encoding된 경우:

```json
{
  "parameter": "content",
  "vulnerable": false,
  "context": "HTML_TEXT",
  "payload": "<svg onload=alert(1337)>",
  "reason": "payload was HTML-encoded",
  "evidence": "&lt;svg onload=alert(1337)&gt;"
}
```

---

## 13. 현재 지원 범위

현재 버전:

```text
Reflected XSS        O
GET Parameter        O
POST Form Parameter  O
Session Cookie       O
Multiple Parameter   O
Reflection Detection O
Context Detection    O
JSON Result          O
```

현재 미지원:

```text
Endpoint Crawling       X
Parameter 자동 탐색      X
Stored XSS              X
DOM XSS                 X
Blind XSS               X
Browser 실행 검증        X
JSON Body               X
WAF Bypass              X
로그인 자동화            X
```

---

## 14. 주의사항

현재 Scanner는 HTTP Response에 Payload가 Encoding 없이 반사되는지를 기준으로 Reflected XSS 가능성을 판단합니다.

따라서:

```text
vuln = true
```

라고 해서 실제 브라우저에서 JavaScript가 반드시 실행된다는 의미는 아닙니다.

현재 판정은 다음 수준에 해당합니다.

```text
Payload가 실행 가능한 형태로 반사됨
        ↓
Reflected XSS 가능성이 높음
```

정확한 취약점 확정을 위해서는 향후 Playwright 등의 Browser Automation 도구를 이용해 실제 JavaScript 실행 여부를 검증할 수 있습니다.

---

## 15. 향후 개선 사항

- Playwright 기반 Browser Verification
- HTML Attribute Context 세분화
- JavaScript Context 세분화
- Payload 다양화
- POST JSON Body 지원
- Header / Cookie Injection 지원
- Scanner 공통 Interface 적용
- 다른 취약점 Scanner와 통합
- 대시보드(Dashboard) 연동
- AI 기반 취약점 설명 및 대응 방안 생성

---

## 16. 사용 목적

본 프로젝트는 웹 취약점 진단 자동화 학습 및 보안 교육을 목적으로 제작되었습니다.

Scanner는 반드시 본인이 소유하거나 테스트 권한을 부여받은 시스템에서만 사용해야 합니다.