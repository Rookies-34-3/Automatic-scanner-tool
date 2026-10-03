"""URL과 세션 정보를 받아 엔드포인트의 Sink 후보를 찾을 모듈.

출력 형식: URL, HTTP 메서드, 파라미터, Sink 후보를 담은 JSON 목록.
"""

import re
from collections import deque
from html.parser import HTMLParser
from http.cookiejar import Cookie, CookieJar
from http.cookies import CookieError, SimpleCookie
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, ProxyHandler, Request, build_opener


WORDLIST = ("/admin", "/uploads/")
SESSION_COOKIE_NAME = "sslc_lab_session"
MAX_PAGES = 100
MAX_DEPTH = 5
TIMEOUT = 5
MAX_BODY = 2 * 1024 * 1024

# 정규식 패턴 
ID_PATTERN = re.compile(r"^(?:\d+|[\da-fA-F]{8}(?:-[\da-fA-F]{4}){3}-[\da-fA-F]{12})$")
CONTROL_PATTERN = re.compile(r"(?i)(?:csrf|token|password|session|cookie)")
FLAG_PATTERN = re.compile(r"(?i)^(?:secret|private|visibility|owner|public)$")
URL_PATTERN = re.compile(r"(?i)^(?:url|uri|link|callback|webhook|redirect|image|thumbnail)$")
OBJECT_PATTERN = re.compile(r"(?i)(?:user|profile|information|contact|inquiry|post|board|file|attachment|document)")
UNSAFE_PATTERN = re.compile(r"(?i)(?:^|[/_=-])(?:logout|signout|delete|remove|destroy|revoke|reset|unsubscribe)(?:$|[/_?&=-])")
STATIC_PATTERN = re.compile(r"(?i)\.(?:css|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|pdf|zip|mp[34]|php|py|cgi)$")


class _PageParser(HTMLParser):
    # HTML 페이지를 파싱해 링크, 폼, 스크립트, DOM 요소 등의 정보를 수집하는 파서

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.forms = []
        self.scripts = []
        self.elements = {}
        self.inline_scripts = []
        self.title = ""
        self.form = None
        self.in_script = False
        self.in_title = False

    def handle_starttag(self, tag, attributes):
        # HTML 시작 태그를 처리해 링크, 폼 입력값, 스크립트 등의 정보를 수집
        attrs = dict(attributes)
        if attrs.get("id"):
            self.elements[attrs["id"]] = attrs
        if tag in {"a", "area"} and attrs.get("href") and "download" not in attrs:
            self.links.append(attrs["href"])
        elif tag == "script":
            self.in_script = True
            if attrs.get("src"):
                self.scripts.append(attrs["src"])
        elif tag == "title":
            self.in_title = True
        elif tag == "form":
            self.form = {"action": attrs.get("action", ""), "method": attrs.get("method", "GET").upper(),
                         "enctype": attrs.get("enctype", ""), "parameters": []}
            self.forms.append(self.form)
        elif tag in {"input", "textarea", "select", "button"} and self.form and attrs.get("name"):
            if "disabled" in attrs:
                return
            kind = (attrs.get("type") or ("submit" if tag == "button" else "text")) if tag in {"input", "button"} else tag
            parameter = {"name": attrs["name"], "input_type": kind.lower(), "required": "required" in attrs}
            if kind.lower() in {"hidden", "submit", "button", "reset", "password"} or CONTROL_PATTERN.search(attrs["name"]):
                parameter["role"] = "control"
            if attrs["name"].lower() == "action" and attrs.get("value"):
                parameter["value"] = attrs["value"]
            if kind.lower() == "file" and attrs.get("accept"):
                parameter["accept"] = attrs["accept"]
            self.form["parameters"].append(parameter)

    def handle_endtag(self, tag):
        # HTML 종료 태그를 처리해 form/script/title 파싱 상태를 종료
        if tag == "form":
            self.form = None
        elif tag == "script":
            self.in_script = False
        elif tag == "title":
            self.in_title = False

    def handle_data(self, data):
        # script와 title 내부의 텍스트 데이터를 수집
        if self.in_script:
            self.inline_scripts.append(data)
        elif self.in_title:
            self.title += data


class _NoRedirect(HTTPRedirectHandler):
    # HTTP 리다이렉트를 자동으로 따라가지 않도록 막는 핸들러
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None  


def _normal_url(base, value, origin):
    # 상대 URL을 절대 URL로 변환하고 동일 출처·안전성 조건을 검사해 정규화
    try:
        parts = urlsplit(urljoin(base, value))
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or parts.username or parts.password:
        return None
    if (parts.scheme, parts.hostname, port) != origin:
        return None
    query = parse_qsl(parts.query, keep_blank_values=True)
    if UNSAFE_PATTERN.search(parts.path) or any(UNSAFE_PATTERN.search(f"/{key}={val}") for key, val in query):
        return None
    if any(CONTROL_PATTERN.search(key) for key, _ in query):
        return None
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, urlencode(sorted(query)), ""))


def _parameters(url):
    # URL의 쿼리스트링과 경로 ID에서 엔드포인트 파라미터 정보를 추출
    parameters = [{"name": name, "location": "query", "input_type": "text"}
                  for name, _ in dict(parse_qsl(urlsplit(url).query, keep_blank_values=True)).items()]
    for part in urlsplit(url).path.split("/"):
        if ID_PATTERN.fullmatch(part):
            parameters.append({"name": f"path_id_{len([p for p in parameters if p['location'] == 'path']) + 1}",
                               "location": "path", "input_type": "object_id", "value": part})
    return parameters


def _endpoint_template(url):
    # 숫자나 UUID 형태의 경로 값을 {id}로 바꿔 엔드포인트 템플릿을 생성
    return "/".join("{id}" if ID_PATTERN.fullmatch(part) else part for part in urlsplit(url).path.split("/"))


def _classify(endpoint):
    # 엔드포인트의 경로와 파라미터를 규칙 기반으로 분석해 취약점 Sink 후보를 분류
    url = endpoint["url"]
    path = urlsplit(url).path
    candidates = []
    object_reference = any(p["location"] == "path" or re.search(r"(?i)(?:^id$|_?id$)", p["name"])
                           for p in endpoint["parameters"])
    for parameter in endpoint["parameters"]:
        name, kind = parameter["name"], parameter["input_type"]
        if parameter["location"] == "path" or re.search(r"(?i)(?:^id$|_?id$)", name):
            candidates.append({"type": "idor", "parameter": name, "tools": ["authz"],
                               "confidence": "medium" if OBJECT_PATTERN.search(path + name) else "low",
                               "reason": "객체 ID로 사용할 수 있는 경로 또는 파라미터"})
        if object_reference and FLAG_PATTERN.fullmatch(name):
            candidates.append({"type": "access_control", "subtype": "query_flag_bypass", "parameter": name,
                               "tools": ["authz"], "reason": "객체 URL에 접근 제어와 관련된 파라미터가 있음"})
            continue
        if parameter.get("role") == "control":
            continue
        if kind == "file":
            candidates.append({"type": "file_upload", "parameter": name, "tools": ["fileio"],
                               "reason": "파일 입력 필드"})
            for check in ("file_extension_bypass", "upload_path_traversal", "upload_code_execution"):
                candidates.append({"type": check, "parameter": name, "filename_parameter": "filename",
                                   "tools": ["fileio"], "reason": "파일 입력을 발견해 파일명·업로드 처리 검사 대상으로 등록"})
        elif kind in {"text", "search", "textarea", "email", "tel", "url"}:
            checks = [("reflected_xss", "xss")] if path.rstrip("/") == "/login" else [("sqli", "sqli"), ("reflected_xss", "xss")]
            for check, tool in checks:
                candidates.append({"type": check, "parameter": name, "tools": [tool],
                                   "reason": "사용자가 입력할 수 있는 문자열"})
        if kind == "url" or URL_PATTERN.fullmatch(name):
            actions = [p["value"] for p in endpoint["parameters"] if p["name"] == "action" and "value" in p]
            candidates.append({"type": "ssrf", "parameter": name, "tools": ["ssrf"],
                               "actions": actions, "reason": "URL 입력 형식 또는 URL 관련 파라미터 이름"})
    if "multipart/form-data" in endpoint.get("enctype", "") and not any(c["type"] == "file_upload" for c in candidates):
        candidates.append({"type": "file_upload", "tools": ["fileio"], "reason": "multipart form"})
    if path.rstrip("/") == "/admin":
        candidates.append({"type": "missing_admin_auth", "tools": ["admin_exposure", "authn"],
                           "reason": "관리 경로 후보. 비로그인 접근과 인증 누락은 미검증"})
    if endpoint.get("directory_listing"):
        candidates.append({"type": "directory_indexing", "tools": ["directory_indexing"],
                           "reason": "응답 제목에 Index of가 있음"})
    if path == "/":
        candidates.append({"type": "network_exposure", "tools": ["portscan"],
                           "reason": "대상 호스트의 허용 포트 기준 점검 후보"})
    if path.startswith("/uploads/"):
        candidates.append({"type": "public_file_access", "tools": ["fileio", "authz"],
                           "reason": "업로드 경로 후보. 공개 접근 여부는 미검증"})
        if re.search(r"(?i)\.(?:php|py|cgi)$", path):
            candidates.append({"type": "upload_code_execution", "tools": ["fileio"],
                               "reason": "실행 확장자의 업로드 파일 링크를 발견함. 파일 실행은 미검증"})
    for candidate in candidates:
        candidate["verified"] = False
    endpoint["sink_candidates"] = candidates
    endpoint["endpoint_template"] = _endpoint_template(url)


def _javascript_endpoints(script, page):
   # JavaScript 코드에서 fetch/axios 호출과 API 엔드포인트 정보를 정적으로 추출
    variables = {}
    bindings = dict(re.findall(r"(?:const|let|var)\s+(\w+)\s*=\s*document\.getElementById\(['\"]([^'\"]+)['\"]\)", script))

    def resolve(template):
        def replace(match):
            variable, field = match.group(1), match.group(2)
            element = page.elements.get(bindings.get(variable, ""), {})
            attribute = "data-" + re.sub(r"[A-Z]", lambda m: "-" + m.group().lower(), field)
            return element.get(attribute, match.group())
        value = re.sub(r"\$\{(\w+)\.dataset\.(\w+)\}", replace, template)
        return value if "${" not in value else None

    literal = r"(?P<quote>['\"`])(?P<literal>[^'\"`\n]+)(?P=quote)"
    for match in re.finditer(r"(?:const|let|var)\s+(?P<variable>\w+)\s*=\s*" + literal, script):
        value = resolve(match.group("literal"))
        if value:
            variables[match.group("variable")] = value
    found = []
    call = r"\b(fetch|axios\.(?:get|post|patch|put|delete))\s*\(\s*(['\"`][^'\"`\n]+['\"`]|\w+)"
    for match in re.finditer(call, script):
        argument = match.group(2)
        value = resolve(argument[1:-1]) if argument[0] in "'\"`" else variables.get(argument)
        if not value:
            continue
        options = ""
        tail = script[match.end():]
        if re.match(r"\s*,\s*\{", tail):
            braces = 0
            for token in re.finditer(r"[{}]|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`", tail):
                if token.group() == "{":
                    braces += 1
                elif token.group() == "}":
                    braces -= 1
                    if braces == 0:
                        options = tail[:token.end()]
                        break
        method_match = re.search(r"\bmethod\s*:\s*['\"](GET|POST|PATCH|PUT|DELETE)['\"]", options, re.I)
        method = match.group(1).split(".")[-1].upper() if match.group(1).startswith("axios.") else "GET"
        if method_match:
            method = method_match.group(1).upper()
        body = re.search(r"JSON\.stringify\s*\(\s*\{([\s\S]*?)\}\s*\)", options)
        parameters = [{"name": name, "location": "json", "input_type": "text"}
                      for name in re.findall(r"(?:^|,)\s*([\w]+)\s*:", body.group(1))] if body else []
        found.append((value, method, parameters))
    called_urls = {url for url, _, _ in found}
    for match in re.finditer(literal, script):
        value = resolve(match.group("literal"))
        if value and value.startswith(("/", "http://", "https://")) and value not in called_urls:
            found.append((value, "GET", []))
    return found


def find_sinks(target_url: str, session_cookie: str = "", seed_paths: list[str] | None = None) -> list[dict]:
    """로그인 세션을 사용해 대상 웹사이트를 순회하고 엔드포인트와 Sink 후보를 수집

    session_cookie는 쿠키 값만 또는 '쿠키명=값; 다른쿠키명=값' 형식이다. seed_paths의 기본값은
    WORDLIST 두 항목이며, 빈 목록을 전달하면 숨겨진 경로 요청을 생략한다.
    URL·쿠키 입력 오류와 확인된 로그인 리다이렉트는 ValueError로 알린다.
    """
    try:
        target = urlsplit(target_url.strip())
        target.port  # 잘못된 포트 형식을 확인한다.
    except ValueError as exc:
        raise ValueError("대상 URL 형식이 올바르지 않습니다.") from exc
    if target.scheme not in {"http", "https"} or not target.hostname or target.username or target.password:
        raise ValueError("대상 URL은 호스트를 포함한 http 또는 https 주소로 입력하세요.")
    raw_cookie = session_cookie.strip()
    if raw_cookie.lower().startswith("cookie:"):
        raw_cookie = raw_cookie[7:].strip()
    if not raw_cookie or "\n" in raw_cookie or "\r" in raw_cookie:
        raise ValueError("로그인 세션 쿠키를 입력하세요.")
    if "=" not in raw_cookie:
        raw_cookie = f"{SESSION_COOKIE_NAME}={raw_cookie}"
    cookies = SimpleCookie()
    try:
        cookies.load(raw_cookie)
    except CookieError as exc:
        raise ValueError("세션 쿠키 형식이 올바르지 않습니다.") from exc
    if not cookies:
        raise ValueError("세션 쿠키 형식이 올바르지 않습니다. '쿠키명=값'을 입력하세요.")
    jar = CookieJar()
    cookie_domain = "localhost.local" if target.hostname == "localhost" else target.hostname
    for name, morsel in cookies.items():
        jar.set_cookie(Cookie(0, name, morsel.value, None, False, cookie_domain, False, False,
                              "/", True, target.scheme == "https", None, True, None, None, {}))
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(jar), _NoRedirect())
    origin = (target.scheme, target.hostname, target.port or (443 if target.scheme == "https" else 80))
    root = urlunsplit((target.scheme, target.netloc, "/", "", ""))
    initial = _normal_url(root, target_url.strip(), origin)
    if not initial:
        raise ValueError("탐색할 수 없는 시작 URL입니다.")
    if STATIC_PATTERN.search(urlsplit(initial).path) or (urlsplit(initial).path.startswith("/uploads/") and not urlsplit(initial).path.endswith("/")):
        raise ValueError("시작 URL은 다운로드 파일 대신 웹 페이지로 지정하세요.")
    words = [_normal_url(root, path, origin) for path in (WORDLIST if seed_paths is None else seed_paths)]
    words = list(dict.fromkeys(url for url in words if url and not STATIC_PATTERN.search(urlsplit(url).path)
                               and not (urlsplit(url).path.startswith("/uploads/") and not urlsplit(url).path.endswith("/"))))[:MAX_PAGES - 2]
    records, visited, scripts, template_visits = {}, set(), {}, {}
    public_opener = build_opener(ProxyHandler({}), _NoRedirect())

    def record(url, method="GET", parameters=(), source="crawler", source_page=None, **metadata):
        # 발견한 URL과 메서드, 파라미터 등의 엔드포인트 정보를 records에 등록하거나 갱신
        key = (url, method)
        endpoint = records.setdefault(key, {"url": url, "method": method, "parameters": _parameters(url),
                                            "source": source, "sources": [], "sink_candidates": []})
        if source not in endpoint["sources"]:
            endpoint["sources"].append(source)
        if source == "wordlist":
            endpoint["source"] = source
        if source_page:
            endpoint["source_page"] = source_page
        for parameter in parameters:
            existing = next((p for p in endpoint["parameters"] if p["name"] == parameter["name"]
                             and p["location"] == parameter["location"] and p.get("value") == parameter.get("value")), None)
            if existing is None:
                endpoint["parameters"].append(parameter)
            else:
                existing.update(parameter)
        endpoint.update(metadata)
        return endpoint

    def fetch(url, authenticated=True):
        # 지정한 URL에 GET 요청을 보내고 상태 코드, 헤더, 응답 본문을 반환
        path = urlsplit(url).path
        if STATIC_PATTERN.search(path) or (path.startswith("/uploads/") and not path.endswith("/")) or path.startswith("/download/"):
            raise ValueError("file_download_skipped")
        try:
            client = opener if authenticated else public_opener
            response = client.open(Request(url, headers={"User-Agent": "ROOKIESCAN-local/0.1"}), timeout=TIMEOUT)
        except HTTPError as exc:
            response = exc
        with response:
            status, headers = response.code, response.headers
            content = response.read(MAX_BODY + 1)
            if len(content) > MAX_BODY:
                raise ValueError("response_too_large")
            try:
                body = content.decode(headers.get_content_charset() or "utf-8", errors="replace")
            except LookupError:
                body = content.decode("utf-8", errors="replace")
            return status, headers, body

    def javascript(script, page, page_url, depth, queue):
         # JavaScript에서 발견한 API URL을 엔드포인트로 기록하고 필요하면 크롤링 큐에 추가
        for reference, method, parameters in _javascript_endpoints(script, page):
            url = _normal_url(page_url, reference, origin)
            if not url or STATIC_PATTERN.search(urlsplit(url).path):
                continue
            record(url, method, parameters, "javascript", page_url)
            if method == "GET" and depth < MAX_DEPTH and not (urlsplit(url).path.startswith("/uploads/") and not urlsplit(url).path.endswith("/")):
                queue.append((url, depth + 1))

    for starts, source in (([root, initial], "crawler"), (words, "wordlist")):
        queue = deque((url, 0) for url in starts)
        while queue:
            url, depth = queue.popleft()
            if url in visited:
                if url in words and (url, "GET") in records:
                    record(url, source="wordlist")
                continue
            if len(visited) >= MAX_PAGES - (len(words) if source == "crawler" else 0):
                break
            template = _endpoint_template(url)
            if template_visits.get(template, 0) >= 3:
                record(url, source="wordlist" if url in words else "crawler", crawl_state="not_visited")
                continue
            template_visits[template] = template_visits.get(template, 0) + 1
            visited.add(url)
            endpoint = record(url, source="wordlist" if url in words else "crawler", crawl_state="visited")
            try:
                status, headers, body = fetch(url)
            except (URLError, OSError, ValueError) as exc:
                endpoint["error"] = str(exc) if str(exc) in {"response_too_large", "file_download_skipped"} else "request_failed"
                continue
            endpoint["status_code"] = status
            if urlsplit(url).path.rstrip("/") == "/login" and status in {301, 302, 303, 307, 308}:
                # 로그인 상태에서 숨겨지는 로그인 폼만 별도의 공개 GET으로 읽는다.
                try:
                    status, headers, body = fetch(url, authenticated=False)
                    endpoint.update(status_code=status, auth_context="anonymous")
                except (URLError, OSError, ValueError):
                    endpoint["error"] = "login_form_unavailable"
                    continue
            if status == 401:
                raise ValueError("session_expired: 로그인 세션을 확인하세요.")
            if status in {301, 302, 303, 307, 308}:
                redirect = _normal_url(url, headers.get("Location", ""), origin)
                if redirect and urlsplit(redirect).path.rstrip("/") == "/login" and urlsplit(url).path.rstrip("/") != "/login":
                    if source == "wordlist":
                        endpoint["error"] = "authentication_required"
                        continue
                    raise ValueError("session_expired: 로그인 화면으로 이동했습니다.")
                if redirect:
                    endpoint["redirect_to"] = redirect
                    if depth < MAX_DEPTH:
                        queue.append((redirect, depth + 1))
                else:
                    endpoint["error"] = "redirect_out_of_scope"
                continue
            if status >= 400:
                endpoint["error"] = "not_found" if status == 404 else "http_error"
                continue
            if "html" not in headers.get("Content-Type", "").lower():
                continue
            page = _PageParser()
            page.feed(body)
            endpoint["directory_listing"] = page.title.strip().lower().startswith("index of ")
            for form in page.forms:
                action = _normal_url(url, form["action"], origin)
                if not action:
                    continue
                method = form["method"] if form["method"] in {"GET", "POST"} else "GET"
                parameters = [dict(parameter, location="query" if method == "GET" else "form") for parameter in form["parameters"]]
                record(action, method, parameters, "html_form", url, enctype=form["enctype"],
                       auth_context=endpoint.get("auth_context", "authenticated"))
            for link in page.links:
                linked = _normal_url(url, link, origin)
                if not linked:
                    continue
                if urlsplit(linked).path.startswith("/uploads/") and not urlsplit(linked).path.endswith("/"):
                    record(linked, source="html_link", source_page=url, crawl_state="link_only")
                elif urlsplit(linked).path.startswith("/download/"):
                    record(linked, source="html_link", source_page=url, crawl_state="link_only")
                elif not STATIC_PATTERN.search(urlsplit(linked).path):
                    record(linked, source="html_link", source_page=url)
                    if depth < MAX_DEPTH:
                        queue.append((linked, depth + 1))
            for inline_script in page.inline_scripts:
                javascript(inline_script, page, url, depth, queue)
            for script_reference in page.scripts:
                script_url = _normal_url(url, script_reference, origin)
                if not script_url:
                    continue
                if script_url not in scripts:
                    try:
                        status, _, script = fetch(script_url)
                        scripts[script_url] = script if status == 200 else ""
                    except (URLError, OSError, ValueError):
                        scripts[script_url] = ""
                javascript(scripts[script_url], page, url, depth, queue)
    for endpoint in records.values():
        if "crawl_state" not in endpoint:
            endpoint["crawl_state"] = "discovered"
        _classify(endpoint)
        if endpoint.get("status_code") in {404, 410}:
            endpoint["sink_candidates"] = []
    return list(records.values())
