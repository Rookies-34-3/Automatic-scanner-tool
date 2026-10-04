"""자동 정찰(recon) + 설정 정규화.

목표: 사용자는 최소한의 값만 적고, 나머지는 코드가 알아낸다.

사용자가 적는 최소 설정(minimal config):
  {
    "target_name": "...",
    "base_url": "http://...",
    "sessions": {
      "victim":  {"cookies": {"sslc_lab_session": "..."}},
      "attacker": {"cookies": {"sslc_lab_session": "..."}}
    },
    "upload_path": "/my-class/board/write/qna",
    "notice_path": "/my-class/board/write/notice"          # 선택(접근제어용)
  }

이 모듈이 폼을 파싱해 csrf 필드명/파일 필드명/허용확장자/
다운로드 링크 패턴/ID 범위를 자동으로 채워 '완전한 cfg' 로 변환한다.
기존의 상세(verbose) 설정도 그대로 호환된다(이미 채워진 값은 건드리지 않음).
"""
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from .client import Client

# ---------- 코드가 정하는 기본값(defaults) ----------
DEFAULT_EXTS = [".pdf", ".txt", ".zip", ".doc", ".docx", ".ppt", ".pptx",
                ".xls", ".xlsx", ".hwp", ".hwpx", ".rtf",
                ".png", ".jpg", ".jpeg", ".gif", ".webp"]
DEFAULT_DL_REGEX = r"/(?:download|file|files|attach|attachment|uploads?)[^\"']*"
PROBE_NAME = "recon_probe.txt"
PROBE_BODY = b"RECONPROBE"


# ---------- HTML 폼 파서 ----------
def parse_forms(html):
    """HTML 내 모든 <form> 을 구조화해 반환."""
    forms = []
    for form in BeautifulSoup(html, "html.parser").select("form"):
        inputs = []
        for field in form.select("input, textarea, select, button"):
            if field.name == "input":
                kind = field.get("type", "text").lower()
                value = field.get("value", "")
            elif field.name == "textarea":
                kind = "textarea"
                value = field.get_text()
            elif field.name == "select":
                kind = "select"
                options = field.select("option:not([disabled])")
                selected = next((option for option in options if option.has_attr("selected")), None)
                selected = selected or next(
                    (option for option in options if option.get("value", option.get_text(strip=True))),
                    options[0] if options else None,
                )
                value = selected.get("value", selected.get_text(strip=True)) if selected else ""
            else:
                kind = field.get("type", "submit").lower()
                value = field.get("value", "")
            inputs.append({
                "name": field.get("name", ""),
                "type": kind,
                "value": value,
                "accept": field.get("accept", ""),
                "checked": field.has_attr("checked"),
                "required": field.has_attr("required"),
                "disabled": field.has_attr("disabled"),
            })
        forms.append({
            "action": form.get("action", ""),
            "method": form.get("method", "get").lower(),
            "enctype": form.get("enctype", "").lower(),
            "inputs": inputs,
        })
    return forms


def _find_csrf(inputs):
    for i in inputs:
        if i["type"] == "hidden" and ("csrf" in i["name"].lower()
                                      or "token" in i["name"].lower()):
            return i["name"]
    return None


# ---------- 업로드 폼 자동 탐지 ----------
def detect_upload(client, upload_path):
    """업로드 페이지 폼에서 파일필드/csrf/기타필드/허용확장자를 알아낸다."""
    html = client.get(upload_path).text
    forms = parse_forms(html)
    up_form = None
    for f in forms:
        if any(i["type"] == "file" for i in f["inputs"]):
            up_form = f
            break
    if not up_form:
        return {}
    file_field = next(i["name"] for i in up_form["inputs"] if i["type"] == "file")
    accept = next((i["accept"] for i in up_form["inputs"]
                   if i["type"] == "file" and i["accept"]), "")
    exts = [e.strip().lower() for e in accept.split(",") if e.strip().startswith(".")]
    csrf = _find_csrf(up_form["inputs"])
    # 공격 파일 외의 모든 정상 폼 필드를 채워 CSRF나 필수값 누락으로 인한
    # HTTP 400을 파일 차단으로 오인하지 않게 한다.
    extra = {}
    submit_added = False
    safe_values = {
        "email": "rookiescan@example.com",
        "tel": "010-0000-0000",
        "url": "https://example.com/",
        "number": "1",
    }
    for i in up_form["inputs"]:
        name, kind = i["name"], i["type"]
        if not name or name == csrf or i.get("disabled") or kind in {
            "file", "reset", "image",
        }:
            continue
        if kind in {"submit", "button"}:
            if not submit_added and i["value"]:
                extra[name] = i["value"]
                submit_added = True
            continue
        if kind in {"checkbox", "radio"}:
            if i.get("checked") or i.get("required"):
                extra.setdefault(name, i["value"] or "on")
            continue
        if kind == "hidden":
            if i["value"]:
                extra[name] = i["value"]
            continue
        extra[name] = i["value"] or safe_values.get(kind, "rookiescan")
    action = urljoin(client.url(upload_path), up_form["action"] or upload_path)
    return {"file_field": file_field, "csrf_field": csrf,
            "allowed_extensions": exts or DEFAULT_EXTS, "extra_fields": extra,
            "action": action}


# ---------- 다운로드 링크 패턴 자동 탐지 ----------
def detect_download(client, up_cfg):
    """프로브 파일을 올려 응답에서 다운로드 링크/ID 패턴을 알아낸다."""
    try:
        resp = client.upload(up_cfg, PROBE_NAME, PROBE_BODY, "text/plain",
                             extra_overrides=up_cfg.get("extra_fields"))
    except Exception:
        return {}
    # 업로드가 안착한 상세페이지 URL → 성공 지표 자동 도출
    success_indicator = None
    try:
        from urllib.parse import urlparse
        p = urlparse(resp.url).path
        # 마지막 경로세그먼트(글 번호)를 떼고 부모 경로를 지표로
        success_indicator = p.rsplit("/", 1)[0] + "/" if "/" in p.strip("/") else p
    except Exception:
        pass

    # 응답 + (리다이렉트된) 상세페이지에서 링크 긁기
    html = resp.text
    links = re.findall(DEFAULT_DL_REGEX, html)
    links = [l for l in links if "/static" not in l]
    out = {"success_indicator": success_indicator}
    if not links:
        return out
    link = links[0]
    # 끝의 숫자를 {id} 로 → 템플릿화
    m = re.search(r"(\d+)(?!.*\d)", link)
    if m:
        cur = int(m.group(1))
        template = link[:m.start()] + "{id}" + link[m.end():]
        out.update({"url_template": template, "id_range": [1, cur + 10],
                    "traversal_template": template, "probe_id": cur})
    else:
        out.update({"url_template": link, "id_range": None})
    return out


# ---------- 설정 정규화(핵심 진입점) ----------
def normalize(cfg):
    """minimal/verbose 설정을 받아 '완전한 cfg' 로 채워 반환.

    이미 값이 있으면 보존, 없으면 자동 탐지/기본값으로 채운다.
    """
    base = cfg["base_url"]
    # 1) success_check_path: 업로드 경로로 기본 설정(로그인해야 접근되는 곳)
    up_path = cfg.get("upload_path") or cfg.get("upload", {}).get("path")
    for key in ("auth", "attacker_auth", "admin_auth"):
        if cfg.get(key) and not cfg[key].get("success_check_path"):
            cfg[key]["success_check_path"] = up_path

    # 2) 업로드 설정 자동 탐지
    if up_path:
        # 로그인한 세션으로 폼을 봐야 정확(비로그인은 리다이렉트될 수 있음)
        sess = Client(base, verify_tls=cfg.get("verify_tls", True), proxy=cfg.get("proxy"))
        sess.login(cfg.get("auth"))
        det = detect_upload(sess, up_path)
        up = cfg.setdefault("upload", {})
        up.setdefault("path", det.get("action") or up_path)
        up.setdefault("method", "POST")
        up.setdefault("file_field", det.get("file_field", "file"))
        up.setdefault("csrf_field", det.get("csrf_field", "csrf_token"))
        up.setdefault("csrf_from", up_path)
        up.setdefault("extra_fields", det.get("extra_fields", {"title": "scan", "body": "scan"}))
        up.setdefault("allowed_extensions", det.get("allowed_extensions", DEFAULT_EXTS))
        up.setdefault("download_link_regex", cfg.get("download_link_regex", DEFAULT_DL_REGEX))

        # 3) 프로브 업로드로 성공지표 + 다운로드 패턴 자동 탐지
        dd = detect_download(sess, up)
        if not up.get("success_indicators"):
            si = cfg.get("success_indicators")
            if not si and dd.get("success_indicator"):
                si = [dd["success_indicator"]]
            up["success_indicators"] = si or []
        if not cfg.get("download") and dd.get("url_template"):
            cfg["download"] = {
                "url_template": dd["url_template"],
                "id_range": dd.get("id_range") or [1, 50],
                "traversal_template": dd.get("traversal_template", dd["url_template"]),
            }

    # 4) 접근제어(공지 등) 자동 구성
    notice = cfg.get("notice_path")
    if notice and not cfg.get("access_control"):
        cfg["access_control"] = {
            "restricted_path": notice,
            "csrf_from": up_path,
            "file_field": cfg.get("upload", {}).get("file_field", "file"),
            "extra_fields": cfg.get("upload", {}).get("extra_fields", {"title": "fio", "body": "fio"}),
            "success_indicators": [],
        }

    cfg["_recon"] = {"session_auth": bool(cfg.get("auth")),
                     "upload_field": cfg.get("upload", {}).get("file_field"),
                     "download": cfg.get("download")}
    return cfg
