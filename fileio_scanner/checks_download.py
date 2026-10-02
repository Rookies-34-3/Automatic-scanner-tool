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
import re as _re
from urllib.parse import quote
from .client import Client
from .finding import (Finding, VULNERABLE, POTENTIAL, SAFE, INFO,
                      CRITICAL, HIGH, MEDIUM, LOW, SEV_INFO, skipped)

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
    """지정 계정으로 마커 첨부 업로드 → (client, download_path, content, post_url)."""
    c = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    if not c.login(auth):
        return None, None, None, None
    ups = cfg["upload"]
    content = MARK + f"-owner={_who(auth)}-{tag}".encode()
    resp = c.upload(ups, f"{tag}.txt", content, "text/plain",
                    extra_overrides={"title": f"fio-{tag}", "body": "fio"})
    regex = ups.get("download_link_regex")
    links = c.find_download_links(resp.text, regex)
    return c, (links[0] if links else None), content, resp.url


def _ui_visibility(cfg, auth, post_url, dl_path):
    """다른 계정이 '정상 UI 탐색'으로 해당 글/다운로드 링크에 도달 가능한지.

    IDOR 판정의 핵심 사실: 링크가 정상 노출되면 접근은 설계상 정상(IDOR 아님),
    노출 안 되는데 직접 ID로만 받아지면 진짜 IDOR.
    반환: {can_view_post, sees_download_link, post_status}
    """
    out = {"can_view_post": None, "sees_download_link": None, "post_status": None}
    if not post_url:
        return out
    c = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    if not c.login(auth):
        return out
    try:
        r = c.get(post_url, allow_redirects=False)
    except Exception:
        return out
    out["post_status"] = r.status_code
    out["can_view_post"] = (r.status_code == 200)
    if r.status_code == 200:
        dl_id = dl_path.rsplit("/", 1)[-1] if dl_path else ""
        out["sees_download_link"] = (dl_path in r.text) or (dl_id and dl_id in r.text)
    return out


def check_download_access(cfg) -> list[Finding]:
    """인증우회 / 수평 IDOR / 수직 권한상승."""
    findings = []
    victim_auth = cfg.get("auth")
    attacker_auth = cfg.get("attacker_auth")
    admin_auth = cfg.get("admin_auth")

    vclient, vpath, vcontent, vpost = _upload_marker(cfg, victim_auth, "victim")
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
    if not attacker_auth:
        findings.append(skipped(
            "IDOR - Horizontal (Download)",
            "attacker 계정 미설정 - 타 사용자 권한으로 접근 테스트 불가"))
    if attacker_auth:
        ac = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
        if ac.login(attacker_auth):
            r = ac.get(vpath, allow_redirects=False)
            # 사실 수집: 공격자가 정상 UI 로 그 글/링크에 도달 가능한가?
            vis = _ui_visibility(cfg, attacker_auth, vpost, vpath)
            downloaded = (r.status_code == 200 and vcontent in r.content)
            f = Finding(category="IDOR - Horizontal (Download)", target_url=base_dl,
                        method="GET", parameter=_param(cfg), payload=vpath,
                        status_code=r.status_code,
                        details={"victim": _who(victim_auth),
                                 "attacker": _who(attacker_auth),
                                 "downloaded": downloaded,
                                 "content_matched": downloaded,
                                 "victim_post_url": vpost,
                                 "attacker_can_view_post": vis["can_view_post"],
                                 "attacker_sees_download_link": vis["sees_download_link"]})
            if downloaded and vis["sees_download_link"]:
                # 공격자가 정상 화면에서 그 링크를 볼 수 있음 → 개별 열람은 정상(공유 자원).
                # 단, 엔드포인트에 자원별 인가가 없다는 사실은 단서로 남긴다(공유 가정 하에서만 안전).
                f.result, f.severity = SAFE, SEV_INFO
                f.evidence = ("타 사용자 첨부를 받았으나 해당 글/링크가 공격자에게 정상 노출됨(공유 자원) "
                              "- 개별 열람은 IDOR 아님. 단, 엔드포인트에 자원별 인가가 없어 "
                              "'공유 게시판 가정 하에서만' 안전(열거 항목 참고)")
                f.details["note_authz"] = "no per-resource authorization; safe only under shared-board assumption"
            elif downloaded:
                # 받아졌는데 정상 UI 로는 접근 불가 → 진짜 IDOR 의심
                f.result, f.severity = VULNERABLE, HIGH
                f.evidence = ("정상 UI 로는 접근 불가한 타 사용자 첨부를 직접 ID 로 다운로드 성공 "
                              "- 소유권 검증 부재(IDOR)")
            else:
                f.result, f.severity = SAFE, SEV_INFO
                f.evidence = f"타 사용자 접근 차단(status={r.status_code})"
            findings.append(f)

    # 3) 수직 권한상승 (관리자 파일을 일반사용자가)
    if not (admin_auth and attacker_auth):
        miss = []
        if not admin_auth:
            miss.append("admin 계정")
        if not attacker_auth:
            miss.append("attacker 계정")
        findings.append(skipped(
            "IDOR - Vertical / Privilege Escalation (Download)",
            f"{', '.join(miss)} 미설정 - 일반 사용자의 관리자 파일 접근 테스트 불가"))
    if admin_auth and attacker_auth:
        _, apath, acontent, apost = _upload_marker(cfg, admin_auth, "adminsecret")
        if apath:
            ac = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
            if ac.login(attacker_auth):
                r = ac.get(apath, allow_redirects=False)
                vis = _ui_visibility(cfg, attacker_auth, apost, apath)
                downloaded = (r.status_code == 200 and acontent in r.content)
                f = Finding(category="IDOR - Vertical / Privilege Escalation (Download)",
                            target_url=ac.url(apath), method="GET",
                            parameter=_param(cfg), payload=apath,
                            status_code=r.status_code,
                            details={"owner": _who(admin_auth),
                                     "attacker": _who(attacker_auth),
                                     "downloaded": downloaded,
                                     "content_matched": downloaded,
                                     "owner_post_url": apost,
                                     "attacker_can_view_post": vis["can_view_post"],
                                     "attacker_sees_download_link": vis["sees_download_link"]})
                if downloaded and vis["sees_download_link"]:
                    f.result, f.severity = SAFE, SEV_INFO
                    f.evidence = ("관리자 첨부를 받았으나 해당 글/링크가 일반 사용자에게 정상 노출됨"
                                  "(공개 자료) - 개별 열람은 권한 경계 아님. 단, 엔드포인트에 "
                                  "자원별 인가가 없어 공유 가정 하에서만 안전(열거 항목 참고)")
                    f.details["note_authz"] = "no per-resource authorization; safe only under shared assumption"
                elif downloaded:
                    f.result, f.severity = VULNERABLE, HIGH
                    f.evidence = ("정상 UI 로는 접근 불가한 관리자 첨부를 일반 사용자가 직접 ID 로 "
                                  "다운로드 성공 - 권한 검증 부재")
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
        return [skipped("Path Traversal / LFI (Download)",
                        "download.traversal_template/url_template 미설정 - 주입 지점 없음")]
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


def _id_pattern(tpl):
    """url_template 의 {id} 자리를 숫자 캡처로 바꾼 정규식 문자열."""
    esc = _re.escape(tpl).replace(_re.escape("{id}"), r"(\d+)")
    return esc


def _collect_ui_visible_ids(cfg, auth, max_posts=25):
    """공격자가 '정상 UI 탐색'으로 도달 가능한 다운로드 ID 집합.

    게시판 목록(upload_path 에서 유도하거나 download.ui_seed_paths)에서 시작해
    글들을 따라가며 보이는 /download/{id} 링크의 id 를 모은다.
    """
    dl = cfg.get("download", {})
    tpl = dl.get("url_template", "")
    pat = _id_pattern(tpl)
    c = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    if not c.login(auth):
        return None  # 수집 불가(판정은 보수적으로)
    # 시작(seed) 페이지: 설정 우선, 없으면 upload_path 에서 게시판 루트 유도
    seeds = dl.get("ui_seed_paths")
    if not seeds:
        up = cfg.get("upload", {}).get("path", "")
        if "/write/" in up:
            seeds = [up.replace("/write/", "/")]
        elif up.endswith("/write"):
            seeds = [up[:-len("/write")]]
        else:
            seeds = [up]
    ids = set()
    post_links = set()
    for seed in seeds:
        try:
            html = c.get(seed).text
        except Exception:
            continue
        ids.update(int(x) for x in _re.findall(pat, html))
        prefix = seed.rstrip("/")
        post_links.update(_re.findall(r'href="(%s/[^"#?]+)"' % _re.escape(prefix), html))
    crawled = list(post_links)[:max_posts]
    for pl in crawled:
        try:
            ph = c.get(pl).text
        except Exception:
            continue
        ids.update(int(x) for x in _re.findall(pat, ph))
    coverage = {"posts_found": len(post_links), "posts_crawled": len(crawled),
                "complete": len(post_links) <= len(crawled)}
    return ids, coverage


def check_enumeration(cfg) -> list[Finding]:
    """순차 ID 열거 - 공격자 세션으로 범위 접근 + UI 가시성 대조."""
    dl = cfg.get("download", {})
    tpl = dl.get("url_template")
    rng = dl.get("id_range")
    if not tpl or "{id}" not in tpl or not rng:
        return [skipped("IDOR - Enumeration (Download)",
                        "download.url_template({id}) 또는 id_range 미설정 - 순차 열거 불가(예: UUID)")]
    auth = cfg.get("attacker_auth") or cfg.get("auth")
    c = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    c.login(auth)

    # 열거 범위 상한: DB 가 커져도 속도가 일정하도록 스캔할 ID 개수를 제한.
    # 범위가 상한보다 크면 '최근(높은 ID)' 쪽 window 만 스캔한다.
    start, end = rng[0], rng[1]
    max_scan = dl.get("id_max_scan", 100)
    scan_start = start
    if max_scan and (end - start + 1) > max_scan:
        scan_start = end - max_scan + 1
    scanned_window = [scan_start, end]

    accessible = []
    for i in range(scan_start, end + 1):
        path = tpl.replace("{id}", str(i))
        try:
            r = c.get(path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200 and r.content:
            accessible.append(i)

    # UI 가시성 대조: 공격자가 정상 탐색으로 볼 수 있는 id 집합
    collected = _collect_ui_visible_ids(cfg, auth)
    ui_ids, coverage = (collected if collected is not None else (None, None))
    hidden = None
    if ui_ids is not None:
        hidden = sorted(set(accessible) - ui_ids)
    # 크롤이 불완전하면(글이 더 있는데 일부만 봄) hidden 은 과대추정이므로 신뢰 낮음
    crawl_complete = bool(coverage and coverage.get("complete"))

    details = {"range": rng, "scanned_window": scanned_window,
               "accessible_count": len(accessible), "as_user": _who(auth),
               "ui_visible_count": (len(ui_ids) if ui_ids is not None else None),
               "ui_crawl_coverage": coverage,
               "ui_crawl_complete": crawl_complete,
               "hidden_from_ui_count": (len(hidden) if hidden is not None else None),
               "hidden_from_ui_sample": (hidden[:10] if hidden else [])}
    f = Finding(category="IDOR - Enumeration (Download)",
                target_url=c.url(tpl), method="GET", parameter="id",
                payload=f"{scanned_window[0]}..{scanned_window[1]}",
                status_code=200, details=details)

    # 판정 원칙(정직하게):
    #  - 크롤로 'UI 전수 확인'은 사실상 불가(페이지네이션 등) → hidden 을 IDOR 증거로 단정하지 않음
    #  - 접근된 게 '전부' UI 에 보이면 → 공유 자원이 증명됨(SAFE)
    #  - 안 보이는 게 있으면 → 진짜 IDOR 일 수도, 단지 안 크롤한 글일 수도 → POTENTIAL(수동확인)
    #  - 수평/수직 IDOR 체크가 '특정 파일'로 확증을 담당하고, 열거는 '넓은 스윕 단서' 역할
    if not accessible:
        f.result, f.severity = SAFE, SEV_INFO
        f.evidence = "접근 가능한 파일 없음"
    elif hidden is None:
        f.result, f.severity = POTENTIAL, MEDIUM
        f.evidence = (f"순차 ID 열거로 {len(accessible)}개 접근 가능. "
                      "UI 가시성 확인 불가 - 수동 확인 필요")
    elif not hidden:
        # 전부 UI 에 보이는 공유 자원이라 '개별 열람'은 정상이지만,
        # 예측가능 ID + 자원별 인가 부재라는 '구조적 약점'은 남아있음(대량 수집 가능).
        f.result, f.severity = POTENTIAL, MEDIUM
        f.evidence = (f"순차 ID 열거로 {len(accessible)}개 전부 접근 가능. 개별 파일은 공유 자원이나, "
                      "예측가능한 순차 ID + 자원별 인가 부재로 전역 엔드포인트에서 전체 파일을 "
                      "대량 수집(scraping) 가능 - 구조적 접근제어 약점(Broken Access Control)")
        details["structural_weakness"] = ("predictable_sequential_id + no_per_resource_authorization "
                                          "→ bulk enumeration/scraping possible")
    else:
        # UI 샘플에 없는 파일 존재: 진짜 IDOR 일 수도, 안 크롤한 글일 수도 → 단정 불가
        f.result, f.severity = POTENTIAL, MEDIUM
        cov = coverage or {}
        f.evidence = (f"순차 ID 열거로 {len(accessible)}개 접근(샘플 UI {cov.get('posts_crawled','?')}개 글엔 "
                      f"없는 파일 {len(hidden)}개 포함). 예측가능 ID + 인가 부재로 대량 수집 가능한 "
                      f"구조적 약점이며, 예시 ID({hidden[:5]})는 접근제어 자원일 수 있어 수동 확인 권장")
        details["structural_weakness"] = ("predictable_sequential_id + no_per_resource_authorization "
                                          "→ bulk enumeration/scraping possible")
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


def check_private_idor(cfg) -> list[Finding]:
    """비밀글(접근제어 자원) IDOR - 진짜 IDOR 확증 테스트.

    cfg["access_controlled"] = {
      "write_path": "/.../write/inquiry",      # 소유자만 보는 글 작성 경로
      "csrf_from": "/.../write/inquiry",
      "file_field": "file",
      "extra_fields": { "title": "...", "body": "..." },
      "private_fields": { "secret": "1" },      # 글을 '비공개'로 만드는 필드
      "success_indicators": ["/inquiry/"],
      "download_link_regex": "/download/\\d+"
    }
    절차:
      1) victim 이 '비공개 글 + 첨부' 작성 → 다운로드 경로 + 글 URL 확보
      2) attacker 가 그 글을 '정상 UI'로 열람 시도 → 차단돼야 정상(접근경계 확인)
      3) attacker 가 첨부를 직접 ID 로 다운로드 시도
      → 글은 못 보는데 첨부는 받아지면: 접근경계가 증명된 상태에서 뚫림 = 확실한 IDOR
    """
    ac = cfg.get("access_controlled")
    if not ac:
        return [skipped("IDOR - Private Resource (Download)",
                        "access_controlled 미설정 - 비밀글 등 접근제어 자원 없음")]
    victim_auth = cfg.get("auth")
    attacker_auth = cfg.get("attacker_auth")
    if not attacker_auth:
        return [skipped("IDOR - Private Resource (Download)",
                        "attacker 계정 미설정 - 타 사용자 접근 테스트 불가")]

    marker = MARK + b"-PRIVATE"
    # 1) victim 이 비공개 글+첨부 작성
    vc = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    if not vc.login(victim_auth):
        return [Finding(category="IDOR - Private Resource (Download)",
                        target_url=cfg["base_url"], result="ERROR", severity=SEV_INFO,
                        evidence="victim 로그인 실패")]
    up = {"path": ac["write_path"], "csrf_field": cfg.get("upload", {}).get("csrf_field", "csrf_token"),
          "csrf_from": ac.get("csrf_from", ac["write_path"]),
          "file_field": ac.get("file_field", "file"),
          "extra_fields": {**ac.get("extra_fields", {"title": "fio-priv", "body": "secret"}),
                           **ac.get("private_fields", {})},
          "download_link_regex": ac.get("download_link_regex",
                                        cfg.get("upload", {}).get("download_link_regex"))}
    try:
        resp = vc.upload(up, "private.txt", marker, "text/plain",
                         extra_overrides=up["extra_fields"])
    except Exception as e:
        return [Finding(category="IDOR - Private Resource (Download)",
                        target_url=vc.url(ac["write_path"]), result="ERROR",
                        severity=SEV_INFO, evidence=f"비공개 글 작성 오류: {e}")]
    links = vc.find_download_links(resp.text, up["download_link_regex"])
    dl_path = links[0] if links else None
    post_url = resp.url
    if not dl_path:
        return [Finding(category="IDOR - Private Resource (Download)",
                        target_url=post_url, result="ERROR", severity=SEV_INFO,
                        evidence="비공개 글의 다운로드 링크를 못 찾음 - 설정 확인")]

    # 2) attacker 가 '정상 UI'로 글 열람 시도 → 차단 여부
    ac_cli = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    ac_cli.login(attacker_auth)
    pr = ac_cli.get(post_url, allow_redirects=False)
    # 200 으로 글이 열리면 열람 가능(=접근경계 없음), 아니면 차단으로 간주
    can_view_post = (pr.status_code == 200)

    # 3) attacker 가 첨부 직접 다운로드
    dr = ac_cli.get(dl_path, allow_redirects=False)
    downloaded = (dr.status_code == 200 and marker in dr.content)

    f = Finding(category="IDOR - Private Resource (Download)",
                target_url=ac_cli.url(dl_path), method="GET",
                parameter=_param(cfg), payload=dl_path, status_code=dr.status_code,
                details={"owner": _who(victim_auth), "attacker": _who(attacker_auth),
                         "private_post_url": post_url,
                         "attacker_can_view_post": can_view_post,
                         "post_status_for_attacker": pr.status_code,
                         "downloaded": downloaded})
    if downloaded and not can_view_post:
        f.result, f.severity = VULNERABLE, HIGH
        f.evidence = ("공격자가 열람 불가한 비공개 글의 첨부를 직접 ID 로 다운로드 성공 "
                      "- 접근제어 경계가 증명된 상태에서 우회됨(확실한 IDOR)")
    elif downloaded and can_view_post:
        f.result, f.severity = POTENTIAL, MEDIUM
        f.evidence = ("첨부가 받아졌으나 공격자가 글 자체도 열람 가능(비공개 설정 미작동?) "
                      "- 접근제어 자체를 점검 필요")
    else:
        f.result, f.severity = SAFE, SEV_INFO
        f.evidence = f"비공개 글 첨부가 타 사용자에게 차단됨(status={dr.status_code})"
    return [f]


def run(cfg) -> list[Finding]:
    out = []
    out += check_download_access(cfg)
    out += check_traversal(cfg)
    out += check_enumeration(cfg)
    out += check_private_idor(cfg)
    return out
