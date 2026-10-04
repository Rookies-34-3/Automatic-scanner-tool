"""범용 HTTP 클라이언트 - 설정(config) 기반.

특정 사이트에 종속되지 않도록 로그인/CSRF/업로드/다운로드 동작을
모두 타깃 설정으로 파라미터화한다.
"""
import re
import requests
from urllib.parse import urljoin


class Client:
    def __init__(self, base_url, timeout=15, verify_tls=True, proxy=None):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.s = requests.Session()
        self.s.verify = verify_tls
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}
        self.s.headers.update({"User-Agent": "fileio-scanner/1.0"})

    def url(self, path):
        if path.startswith("http"):
            return path
        return urljoin(self.base + "/", path.lstrip("/"))

    def get(self, path, **kw):
        kw.setdefault("timeout", self.timeout)
        return self.s.get(self.url(path), **kw)

    def post(self, path, **kw):
        kw.setdefault("timeout", self.timeout)
        return self.s.post(self.url(path), **kw)

    def extract_token(self, path, field_name):
        """페이지에서 숨은 토큰(csrf 등) 추출. 없으면 None."""
        if not field_name:
            return None
        html = self.get(path).text
        m = re.search(r'name="%s"[^>]*value="([^"]*)"' % re.escape(field_name), html)
        if not m:
            m = re.search(r'value="([^"]*)"[^>]*name="%s"' % re.escape(field_name), html)
        return m.group(1) if m else None

    # ---------- 인증 ----------
    def login(self, auth):
        """auth 설정에 따라 로그인. 성공 여부(bool) 반환.

        auth = {
          type: "form" | "session" | "none",
          login_path, csrf_field, fields{...}, success_check_path
        }
        """
        if not auth or auth.get("type") == "none":
            return True
        if auth.get("type") == "session":
            cookies = auth.get("cookies")
            if not isinstance(cookies, dict) or not cookies:
                return False
            self.s.cookies.update(cookies)
        else:
            data = dict(auth.get("fields", {}))
            csrf_field = auth.get("csrf_field")
            if csrf_field:
                tok = self.extract_token(auth["login_path"], csrf_field)
                if tok is not None:
                    data[csrf_field] = tok
            self.post(auth["login_path"], data=data, allow_redirects=True)
        check = auth.get("success_check_path")
        if not check:
            return True
        r = self.get(check, allow_redirects=False)
        return r.status_code == 200

    # ---------- 업로드 ----------
    def upload(self, up, filename, content, content_type=None, extra_overrides=None):
        """up 설정으로 파일 업로드. requests.Response 반환.

        up = {
          path, method, csrf_field, csrf_from,
          file_field, extra_fields{...}
        }
        """
        path = up["path"]
        data = dict(up.get("extra_fields", {}))
        if extra_overrides:
            data.update(extra_overrides)
        csrf_field = up.get("csrf_field")
        if csrf_field:
            tok = self.extract_token(up.get("csrf_from", path), csrf_field)
            if tok is not None:
                data[csrf_field] = tok
        file_field = up.get("file_field", "file")
        if content_type:
            files = {file_field: (filename, content, content_type)}
        else:
            files = {file_field: (filename, content)}
        return self.post(path, data=data, files=files, allow_redirects=True)

    def find_download_links(self, html, regex=None):
        """응답 HTML 에서 다운로드 링크 추출."""
        if regex:
            return sorted(set(re.findall(regex, html)))
        hrefs = re.findall(r'(?:href|src)="([^"]+)"', html)
        keys = ("download", "attach", "file", "uploads", "attachment")
        out = [h for h in hrefs
               if any(k in h.lower() for k in keys)
               and "/static/reference" not in h]
        return sorted(set(out))
