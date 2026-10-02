# ROOKIESCAN Sink 탐색 설계

## 결론

유효한 세션 쿠키를 사용하는 로그인 크롤러로 SQLi, XSS, SSRF, IDOR, 비밀글 권한 우회와
파일 업로드에 필요한 입력 지점을 대부분 찾을 수 있다.

크롤러가 찾는 것은 취약점 자체가 아니라 검사할 URL, 메서드, 파라미터와 그 근거다. 실제
취약점 판정은 `module/`의 `sqli`, `xss`, `ssrf`, `authz`, `fileio` 함수가 수행한다.

```text
로그인 세션으로 크롤링
        ↓
링크·폼·JavaScript에서 endpoint 수집
        ↓
URL·파라미터·입력 형식을 규칙으로 분류
        ↓
Sink 후보 JSON
        ↓
openai_module이 알맞은 검사 tool 호출
```

## 두 가지 탐색 방식

현재 대상은 `127.0.0.1` 또는 `localhost`의 로컬 Docker 서비스로 제한한다. endpoint는
크롤링과 숨겨진 경로 wordlist 요청을 서로 구분해 수집한다.

### 로그인 크롤러

로그인된 사이트의 링크, form과 JavaScript를 따라가며 입력 가능한 지점을 최대한 찾는다.
다음 경로는 미리 넣지 않고 크롤러가 화면과 JavaScript에서 발견해야 한다.

```text
/my-class/board/qna
/pre-course/write
/my-class/pbl
/my-class/board/task
/mypage/my-information/<user_id>
/api/profiles/<user_id>
/customer/contact/<inquiry_id>
```

ID가 필요한 URL은 숫자를 임의로 만들지 않는다. 로그인된 화면에서 발견한 실제 링크와
JavaScript 경로를 사용한다.

### 숨겨진 endpoint wordlist

사이트맵, 링크와 JavaScript 어디에도 나오지 않는 경로는 DirBuster와 같은 방식으로 별도
wordlist의 경로를 직접 요청한다. 현재 모의 도구의 wordlist는 두 개뿐이다.

```text
/admin
/uploads/
```

현재는 이 두 경로의 존재 여부와 응답 특징만 수집한다. 나중에는 wordlist 항목을 늘리거나
DirBuster류 도구의 결과를 같은 입력으로 전달해 범위를 넓힌다.

### `sink_finder.py`

- 사용자가 입력한 세션 쿠키를 적용한 로그인 세션 하나를 사용한다.
- 로그인된 화면의 링크, 폼과 JavaScript에서 endpoint를 모은다.
- SQLi, XSS, SSRF, IDOR, 권한 우회와 파일 업로드 검사 후보를 만든다.
- 공격 요청은 보내지 않고 후보 JSON을 반환한다.

세션 쿠키가 만료되어 `/login`으로 돌아오거나 `401`이 발생하면 탐색 결과를 계속 만들지 않고
`session_expired` 오류를 반환한다.

## 함수 입력과 출력

첫 구현은 `sink_finder.py`의 함수 하나로 구성한다.

```python
find_sinks(
    target_url: str,
    session_cookie: str,
    seed_paths: list[str] | None = None,
) -> list[dict]
```

| 입력 | 용도 |
| --- | --- |
| `target_url` | `http://127.0.0.1:8080/login`에서 기준 출처 `http://127.0.0.1:8080`을 얻는다. |
| `session_cookie` | 모든 크롤링 요청에 적용하는 로그인 세션 쿠키다. |
| `seed_paths` | 숨겨진 endpoint wordlist다. 기본값은 `/admin`, `/uploads/` 두 개다. |

쿠키 값은 로그, 예외 메시지, 반환 JSON과 Streamlit 화면에 포함하지 않는다.

## 크롤링 방식

### 1. 시작 URL

입력 URL의 기준 출처를 구한 뒤 다음 URL만 크롤러 방문 대기열에 넣는다.

```text
http://127.0.0.1:8080/
http://127.0.0.1:8080/login
```

로그인 쿠키를 적용하고 redirect를 따라가면 로그인 후 첫 화면과 메뉴를 수집할 수 있다.
크롤러가 HTML과 JavaScript에서 새 URL을 발견할 때만 이 대기열이 늘어난다.

`seed_paths`는 일반 크롤링 대기열과 별도로 기준 출처에 결합해 직접 요청한다.

```text
http://127.0.0.1:8080/admin
http://127.0.0.1:8080/uploads/
```

응답이 존재하면 endpoint 결과에 추가한다. 반환된 HTML에 링크나 form이 있으면 그때 해당
응답을 크롤러가 분석한다.

### 2. HTML에서 수집

| 태그 | 수집할 값 |
| --- | --- |
| `<a>` | `href`, query 이름, 경로의 숫자·UUID |
| `<form>` | `action`, `method`, `enctype` |
| `<input>` | `name`, `type`, hidden 여부, 기본값 존재 여부 |
| `<textarea>` | `name` |
| `<select>` | `name`, option 값 |
| `<button>` | `name`, `value`, submit 동작 |
| `<script>` | `src`, inline JavaScript의 내부 URL |

폼은 제출하지 않고 구조만 기록한다. `csrf_token`, submit 버튼과 화면 상태용 hidden 값은
`control`로 표시해 일반 입력 파라미터와 구분한다.

### 3. JavaScript에서 수집

정적 JavaScript에서 다음 형태를 찾아 같은 출처의 URL로 추가한다.

- `fetch("/api/...")`
- `axios.get`, `axios.post`, XHR 대상
- `/api/`, `/mypage/`, `/customer/`, `/my-class/` 형태의 문자열
- 폼 제출 URL과 API prefix

현재 대상의 `/static/app.js`에서도 `/api/profiles/`, `/my-class/board/qna`,
`/my-class/board/task`, `/my-class/pbl` 경로를 얻을 수 있다.

### 4. 순회 제한

- 시작 URL과 같은 scheme, host, port만 방문
- 같은 URL은 한 번만 방문
- fragment 제거 및 query 순서 정규화
- 최대 100페이지, 깊이 5, 요청 timeout 5초
- `logout`, 삭제 버튼과 외부 URL 제외
- 이미지, CSS, 폰트는 제외하고 JavaScript만 추가 분석

숨겨진 경로가 HTML과 JavaScript 어디에도 없으면 크롤러만으로 발견할 수 없다. 이 경우에만
별도 wordlist 요청을 사용한다. 향후 DirBuster류 도구가 찾은 경로 목록을 `seed_paths`로
전달하면 각 응답을 같은 HTML·form 분석기로 처리한다.

## URL과 입력 규칙

정규식은 크롤링으로 수집된 URL을 분류하는 데 사용한다. 경로를 무작위로 생성하는 용도로
사용하지 않는다.

### 객체 ID

다음 형태를 객체 참조 후보로 수집한다.

```regex
/(\d+)(?=/|$)
```

```regex
/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,36}(?=/|$)
```

숫자만 있으면 페이지 번호나 강좌 번호일 수도 있다. 다음처럼 객체 의미가 있는 경로 또는
파라미터 이름과 함께 나타날 때 IDOR 우선순위를 높인다.

```text
user, users, profile, profiles
contact, inquiry, post, board
file, attachment, document
user_id, inquiry_id, post_id, file_id
```

예시:

```text
/mypage/my-information/17
    → /mypage/my-information/{id}
    → IDOR 후보

/api/profiles/17
    → /api/profiles/{id}
    → IDOR 후보
```

### 권한을 바꾸는 query

객체 ID가 있는 URL에서 다음 query 이름을 발견하면 권한 우회 후보로 분류한다.

```regex
(?i)^(secret|private|visibility|owner|public)$
```

예시:

```text
/customer/contact/31?secret=1
```

결과에는 다음 정보를 넣는다.

```json
{
  "type": "access_control",
  "subtype": "query_flag_bypass",
  "endpoint_template": "/customer/contact/{id}",
  "object_id": "31",
  "control_parameter": "secret",
  "tool": "authz"
}
```

`authz` tool은 이 정보를 받아 원래 URL과 `secret`을 제거한 URL의 상태 코드, 본문과 객체
소유권을 비교한다. 숫자 경로와 `secret` query의 존재만으로 취약점을 확정하지 않는다.

### SQLi와 XSS

검색·필터·본문·제목처럼 사용자가 입력하는 문자열 파라미터는 SQLi와 XSS 양쪽 후보로
등록한다.

```text
input type=text
input type=search
textarea
GET query 문자열
POST form 문자열
```

다음 control 입력은 기본 후보에서 제외한다.

```text
csrf_token
submit 버튼
페이지 상태용 hidden 값
```

예시:

```text
GET /my-class/board/qna?content=...
    → content를 sqli tool 후보로 등록
    → content를 xss tool 후보로 등록

POST /login
    → userId를 xss tool 후보로 등록
```

실제 SQL 오류, 응답 차이와 HTML 반영 위치는 각 tool이 확인한다.

### SSRF

다음 입력 이름 또는 `input type=url`을 SSRF 후보로 분류한다.

```regex
(?i)^(url|uri|link|callback|webhook|redirect|image|thumbnail)$
```

`preview`, `fetch`, `import`, `save` 같은 submit 동작이 함께 있으면 우선순위를 높인다.

```text
POST /pre-course/write
url=<사용자 입력>
action=preview 또는 save
    → ssrf tool 후보
```

### 파일 업로드

다음 두 조건 중 하나를 만족하면 파일 업로드 Sink로 분류한다.

```text
input type=file
form enctype=multipart/form-data
```

하나의 업로드 Sink에서 다음 검사를 실행할 수 있도록 `fileio` tool에 전달한다.

- 확장자 검증 우회
- 파일명 Path Traversal
- 업로드 파일 직접 접근
- 실행 확장자 처리

크롤러는 form action, method, 파일 필드 이름, 함께 필요한 hidden 필드와 CSRF 토큰 위치를
반환한다. 실제 파일은 `fileio` tool이 업로드한다.

## 예상 탐지 범위

| 항목 | 크롤러로 Sink 발견 | 취약점 확정에 필요한 단계 |
| --- | --- | --- |
| SQL Injection | 가능 | `sqli`가 파라미터별 응답 차이 확인 |
| Reflected XSS | 가능 | `xss`가 반영 위치와 실행 가능성 확인 |
| SSRF | 가능 | `ssrf`가 서버 측 요청 발생 여부 확인 |
| IDOR | 숫자·UUID와 객체 경로로 후보 발견 가능 | `authz`가 다른 객체 접근 결과 확인 |
| 비밀글 권한 우회 | 객체 ID와 `secret` query로 후보 발견 가능 | `authz`가 query 유무에 따른 접근 결과 비교 |
| 파일 업로드 취약점 | 업로드 form 발견 가능 | `fileio`가 파일명과 파일 내용별 동작 확인 |
| 관리자 인증 누락 | 두 항목 wordlist에서 `/admin` 요청 | 비로그인 `/admin` 응답 확인 |
| 디렉터리 인덱싱 | 두 항목 wordlist에서 `/uploads/` 요청 | `/uploads/` 응답 형식 확인 |

따라서 로그인 후 접근 가능한 기능이 링크, form 또는 JavaScript에 나타나는 현재 대상에서는
요청한 주요 Sink를 거의 모두 수집할 수 있다. 완전히 숨겨진 `/admin`, `/uploads/`만 현재의
두 항목 wordlist로 보완하고, 나중에는 wordlist 또는 endpoint 탐색 결과를 늘린다.

## 반환 형식

```json
[
  {
    "url": "http://127.0.0.1:8080/my-class/board/qna",
    "method": "GET",
    "parameters": [
      {
        "name": "content",
        "location": "query",
        "input_type": "search"
      }
    ],
    "sink_candidates": [
      {
        "type": "injection_input",
        "parameter": "content",
        "tools": ["sqli", "xss"],
        "reason": "검색 문자열 입력"
      }
    ],
    "source": "html_form"
  }
]
```

`openai_module.py`에는 URL 전체, 메서드, 파라미터 위치와 `tools` 목록을 전달한다. 모델은
등록된 tool 중 필요한 함수를 선택하고 애플리케이션이 해당 함수를 실행한다.

## Streamlit 흐름

```text
대상 URL 입력
세션 쿠키 입력
Sink 찾기 버튼
        ↓
find_sinks(target_url, session_cookie)
        ↓
발견한 endpoint와 후보 표 출력
        ↓
openai_module로 전달
```

초기 화면에는 다음만 표시한다.

1. 방문한 페이지 수
2. 찾은 endpoint 수
3. URL, method, parameter, 후보 tool 표
4. 세션 만료 또는 접근 실패 경로

## 구현 순서

1. 세션 쿠키 적용과 같은 출처 제한
2. 로그인 만료 확인
3. 링크와 form 크롤러
4. JavaScript URL 수집
5. `/admin`, `/uploads/` 두 항목 wordlist 요청
6. 크롤링 결과와 wordlist 결과 병합
7. URL template과 query 정규식 분류
8. SQLi·XSS·SSRF·IDOR·권한·파일 후보 생성
9. Streamlit 결과 표 연결
10. 후보 JSON을 `openai_module.py`에 전달

첫 구현의 wordlist에는 `/admin`, `/uploads/`만 둔다. 향후 목록을 늘리거나 DirBuster류
endpoint 탐색 결과를 `seed_paths`로 전달하는 방식으로 범위를 확장한다.
