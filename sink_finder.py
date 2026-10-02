"""URL과 세션 정보를 받아 엔드포인트의 Sink 후보를 찾을 모듈.

출력 형식: URL, HTTP 메서드, 파라미터, Sink 후보를 담은 JSON 목록.
구현은 다음 단계에서 추가한다.
"""

def find_sinks(target_url: str, session_cookie: str = "",seed_paths: list[str] | None = None,) -> list[dict]:
    print('더미')