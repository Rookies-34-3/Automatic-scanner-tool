from __future__ import annotations

import os
from dataclasses import dataclass
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener


class ScanConfigError(ValueError):
    pass


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HiddenInputParser(HTMLParser):
    def __init__(self, field_name: str):
        super().__init__()
        self.field_name = field_name
        self.value: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        if tag.lower() != "input":
            return
        values = dict(attrs)
        if values.get("name") == self.field_name and values.get("value") is not None:
            self.value = values["value"]


@dataclass
class AuthContext:
    kind: str
    bearer_token: str | None = None
    cookies: CookieJar | None = None

    def opener(self, *, follow_redirects: bool):
        processors: list[Any] = []
        if self.cookies is not None:
            processors.append(HTTPCookieProcessor(self.cookies))
        if not follow_redirects:
            processors.append(NoRedirectHandler())
        return build_opener(*processors)


def authentication_type(authentication: dict[str, Any]) -> str:
    kind = str(authentication.get("type", "bearer")).lower()
    if kind not in {"bearer", "form_session"}:
        raise ScanConfigError("authentication.type은 bearer 또는 form_session이어야 합니다.")
    return kind


def validate_relative_path(path: Any, field_name: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ScanConfigError(f"{field_name}은 /로 시작하는 상대 경로여야 합니다.")
    return path


def validate_credential(
    authentication: dict[str, Any], credential: dict[str, Any], label: str
) -> None:
    if authentication_type(authentication) == "bearer":
        if not credential.get("token") and not credential.get("token_env"):
            raise ScanConfigError(f"{label}에 token 또는 token_env가 필요합니다.")
        return
    for direct, environment in (("username", "username_env"), ("password", "password_env")):
        if not credential.get(direct) and not credential.get(environment):
            raise ScanConfigError(f"{label}에 {direct} 또는 {environment}가 필요합니다.")


def validate_authentication(authentication: dict[str, Any]) -> None:
    if authentication_type(authentication) == "bearer":
        return
    validate_relative_path(authentication.get("login_path"), "authentication.login_path")
    validate_relative_path(authentication.get("verify_path"), "authentication.verify_path")
    if not authentication.get("session_cookie_name"):
        raise ScanConfigError("form_session에는 session_cookie_name이 필요합니다.")


def resolve_value(
    container: dict[str, Any], direct_key: str, env_key: str, label: str
) -> str:
    if container.get(env_key):
        env_name = str(container[env_key])
        value = os.environ.get(env_name)
        if not value:
            raise ScanConfigError(f"{label} 환경 변수 {env_name}가 비어 있습니다.")
        return value
    value = container.get(direct_key)
    if value is None or value == "":
        raise ScanConfigError(f"{label} 값이 비어 있습니다.")
    return str(value)


def _read(opener, request: Request, timeout: float) -> tuple[int, bytes, str]:
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as exc:
        response = exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ScanConfigError(f"인증 요청을 완료하지 못했습니다: {exc}") from exc
    with response:
        return response.code, response.read(1_048_577), response.geturl()


def _extract_hidden(body: bytes, field_name: str) -> str:
    parser = HiddenInputParser(field_name)
    parser.feed(body.decode("utf-8", errors="replace"))
    if parser.value is None:
        raise ScanConfigError(f"로그인 페이지에서 {field_name} 값을 찾지 못했습니다.")
    return parser.value


def build_auth_context(
    base_url: str,
    authentication: dict[str, Any],
    credential: dict[str, Any],
    label: str,
    timeout: float,
) -> AuthContext:
    kind = authentication_type(authentication)
    if kind == "bearer":
        token = resolve_value(credential, "token", "token_env", f"{label} 토큰")
        return AuthContext(kind="bearer", bearer_token=token)

    username = resolve_value(
        credential, "username", "username_env", f"{label} 사용자명"
    )
    password = resolve_value(
        credential, "password", "password_env", f"{label} 비밀번호"
    )
    cookie_jar = CookieJar()
    context = AuthContext(kind="form_session", cookies=cookie_jar)
    opener = context.opener(follow_redirects=True)
    login_path = validate_relative_path(authentication["login_path"], "login_path")
    login_url = urljoin(base_url.rstrip("/") + "/", login_path.lstrip("/"))

    fields = {
        str(key): str(value)
        for key, value in authentication.get("extra_fields", {}).items()
    }
    csrf_field = authentication.get("csrf_field")
    if csrf_field:
        source_path = validate_relative_path(
            authentication.get("csrf_source_path", login_path), "csrf_source_path"
        )
        source_url = urljoin(base_url.rstrip("/") + "/", source_path.lstrip("/"))
        status, body, _ = _read(
            opener,
            Request(source_url, headers={"User-Agent": "SecurityScanner/2.0"}),
            timeout,
        )
        if not 200 <= status < 300:
            raise ScanConfigError(f"{label} 로그인 준비 요청이 HTTP {status}를 반환했습니다.")
        fields[str(csrf_field)] = _extract_hidden(body, str(csrf_field))

    fields[str(authentication.get("username_field", "username"))] = username
    fields[str(authentication.get("password_field", "password"))] = password
    _read(
        opener,
        Request(
            login_url,
            data=urlencode(fields).encode("utf-8"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "SecurityScanner/2.0",
            },
            method=str(authentication.get("login_method", "POST")).upper(),
        ),
        timeout,
    )

    cookie_name = str(authentication["session_cookie_name"])
    if not any(cookie.name == cookie_name for cookie in cookie_jar):
        raise ScanConfigError(f"{label} 로그인 후 {cookie_name} 쿠키가 발급되지 않았습니다.")

    verify_path = validate_relative_path(authentication["verify_path"], "verify_path")
    verify_url = urljoin(base_url.rstrip("/") + "/", verify_path.lstrip("/"))
    status, _, _ = _read(
        context.opener(follow_redirects=False),
        Request(verify_url, headers={"User-Agent": "SecurityScanner/2.0"}),
        timeout,
    )
    if not 200 <= status < 300:
        raise ScanConfigError(
            f"{label} 로그인 검증이 실패했습니다(보호 경로 HTTP {status})."
        )
    return context
