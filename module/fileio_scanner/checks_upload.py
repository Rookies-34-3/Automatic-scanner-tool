"""업로드 취약점 체크 모음.

각 체크는 Finding 리스트를 반환한다. 엔진에서 인증된 client 와
타깃 설정(cfg)을 받아 호출된다.
"""
import re as _re
from .client import Client
from .finding import (Finding, VULNERABLE, POTENTIAL, SAFE, INFO,
                      CRITICAL, HIGH, MEDIUM, LOW, SEV_INFO, skipped)

MARK = b"FIOSCANMARKER"
CONTROL_FILENAME = "rookiescan-control.txt"
CONTROL_CONTENT = MARK + b"-CONTROL"
CONTROL_FIELDS = {"title": "rookiescan-control", "body": "rookiescan-control"}

# 업로드 페이로드 매트릭스
# (category, filename, content, content_type, severity_if_accepted, note)
PAYLOADS = [
    ("Dangerous File Extension (PHP)", "sh.php", b"<?php echo 'FIO';?>", "application/x-php", CRITICAL, "서버측 스크립트 실행 가능 확장자"),
    ("Dangerous File Extension (JSP)", "sh.jsp", b"<% out.print(1); %>", "application/octet-stream", CRITICAL, "JSP 실행 확장자"),
    ("Dangerous File Extension (ASP)", "sh.asp", b"<% Response.Write(1) %>", "application/octet-stream", CRITICAL, "ASP 실행 확장자"),
    ("Dangerous File Extension (ASPX)", "sh.aspx", b"<% %>", "application/octet-stream", CRITICAL, "ASPX 실행 확장자"),
    ("Dangerous File Extension (Executable)", "run.exe", b"MZ\x90\x00", "application/octet-stream", HIGH, "실행파일 업로드"),
    ("Stored XSS via File Upload (HTML)", "x.html", b"<script>alert(1)</script>", "text/html", HIGH, "HTML 파일 업로드"),
    ("SVG XSS", "x.svg", b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>", "image/svg+xml", HIGH, "스크립트 포함 SVG"),
    ("Extension Bypass - Double Extension", "a.php.png", b"<?php echo 'FIO';?>", "image/png", HIGH, "이중 확장자"),
    ("Extension Bypass - Double Extension", "a.php.txt", b"<?php echo 'FIO';?>", "text/plain", HIGH, "이중 확장자"),
    ("Extension Bypass - Case Variation", "a.PhP", b"<?php echo 'FIO';?>", "text/plain", HIGH, "대소문자 혼용 확장자"),
    ("Extension Bypass - Trailing Dot", "a.php.", b"<?php echo 'FIO';?>", "text/plain", HIGH, "확장자 뒤 점"),
    ("Extension Bypass - Trailing Space", "a.php ", b"<?php echo 'FIO';?>", "text/plain", HIGH, "확장자 뒤 공백"),
    ("Extension Bypass - Null Byte", "a.php\x00.png", b"<?php echo 'FIO';?>", "image/png", CRITICAL, "널바이트 확장자 우회"),
    ("Extension Bypass - Alternate (phar)", "a.phar", b"<?php echo 'FIO';?>", "text/plain", HIGH, "대체 실행 확장자"),
    ("Extension Bypass - Alternate (php5/phtml)", "a.phtml", b"<?php echo 'FIO';?>", "text/plain", HIGH, "대체 실행 확장자"),
    ("MIME Type Spoofing", "a.php", b"<?php echo 'FIO';?>", "image/png", HIGH, "Content-Type 를 이미지로 위조"),
    ("Content Validation Bypass (Magic Bytes)", "poly.php", b"GIF89a;\n<?php echo 'FIO';?>", "image/gif", HIGH, "GIF 매직바이트 + 코드 폴리글랏"),
    ("Content Validation Bypass (Magic Bytes)", "poly.png", b"\x89PNG\r\n\x1a\n<?php echo 'FIO';?>", "image/png", MEDIUM, "PNG 헤더 + 코드"),
    ("Path Traversal in Filename", "../../fio_traversal.txt", b"traversal", "text/plain", HIGH, "파일명에 경로 이탈 시도"),
    ("Path Traversal in Filename", "..\\..\\fio_win.txt", b"traversal", "text/plain", HIGH, "윈도우 경로 이탈 시도"),
    ("Special File Upload (.htaccess)", ".htaccess", b"AddType application/x-httpd-php .txt", "text/plain", HIGH, "서버 설정 파일 업로드"),
    ("Special File Upload (web.config)", "web.config", b"<configuration/>", "application/xml", HIGH, "IIS 설정 파일 업로드"),
    ("Filename Injection (CRLF)", "a%0d%0a.txt", b"crlf", "text/plain", LOW, "파일명 CRLF 주입"),
]


def _accepted(cfg, resp):
    """업로드 성공 판정."""
    ups = cfg["upload"]
    if resp.status_code not in (200, 201, 302):
        return False
    inds = ups.get("success_indicators")
    if inds:
        return any(i in resp.url for i in inds) or any(i in resp.text for i in inds)
    # 성공 지표가 없을 때: 로그인/인증 페이지로 튕기면 '실패'로 간주(오탐 방지)
    low = resp.url.lower()
    if any(x in low for x in ("login", "signin", "signon", "/auth", "denied", "403")):
        return False
    return True


def _fetch_back(client: Client, cfg, resp):
    """업로드 결과에서 다운로드 링크를 찾아 되받아온다.

    (download_path, served_resp) 또는 (None, None).
    """
    regex = cfg["upload"].get("download_link_regex")
    links = client.find_download_links(resp.text, regex)
    if not links:
        return None, None
    d = client.get(links[0], allow_redirects=False)
    return links[0], d


def _control_upload(client: Client, cfg):
    """허용 파일의 정상 업로드가 성공하는지 먼저 확인한다."""
    ups = cfg["upload"]
    field = ups.get("file_field", "file")
    target = client.url(ups["path"])
    try:
        response = client.upload(
            ups,
            CONTROL_FILENAME,
            CONTROL_CONTENT,
            "text/plain",
            extra_overrides=CONTROL_FIELDS,
        )
    except Exception as exc:
        finding = Finding(
            category="Upload Control Request",
            target_url=target,
            method="POST",
            parameter=field,
            payload=CONTROL_FILENAME,
            result="ERROR",
            severity=SEV_INFO,
            evidence=f"정상 허용 파일 업로드 요청 실패: {type(exc).__name__}",
        )
        return None, finding

    accepted = _accepted(cfg, response)
    download_path, served = _fetch_back(client, cfg, response)
    retrievable = bool(
        served is not None
        and served.status_code == 200
        and CONTROL_CONTENT in served.content
    )
    details = {
        "filename": CONTROL_FILENAME,
        "status_code": response.status_code,
        "final_url": response.url,
        "accepted": accepted,
        "download_path": download_path,
        "content_retrievable": retrievable,
    }
    if accepted:
        return details, None

    rejection = _reject_reason(response)
    details["rejection"] = rejection
    finding = Finding(
        category="Upload Control Request",
        target_url=target,
        method="POST",
        parameter=field,
        payload=CONTROL_FILENAME,
        status_code=response.status_code,
        result=POTENTIAL,
        severity=SEV_INFO,
        evidence=(
            "정상 허용 파일 업로드가 성공하지 않아 위험 파일의 거부 응답을 "
            f"안전으로 판정할 수 없습니다. (HTTP {response.status_code})"
        ),
        details=details,
    )
    return details, finding


def _collapse_rejected_payloads(findings, target, field, control):
    """정상 기준 요청 뒤 거부된 공격 파일을 한 개의 PASS로 묶는다."""
    rejected = [
        finding for finding in findings
        if finding.result == SAFE and finding.details.get("accepted") is False
    ]
    if len(rejected) < 2:
        return findings
    checks = [{
        "category": finding.category,
        "filename": finding.payload,
        "status_code": finding.status_code,
        "evidence": finding.evidence,
        "rejection": finding.details.get("rejection"),
    } for finding in rejected]
    summary = Finding(
        category="Rejected Upload Payloads",
        target_url=target,
        method="POST",
        parameter=field,
        result=SAFE,
        severity=SEV_INFO,
        evidence=(
            f"정상 허용 파일 업로드 성공 후 위험 파일 {len(rejected)}종이 서버에서 거부됨"
        ),
        details={
            "control_upload": control,
            "rejected_count": len(rejected),
            "checks": checks,
        },
    )
    return [finding for finding in findings if finding not in rejected] + [summary]


def check_payloads(client: Client, cfg) -> list[Finding]:
    ups = cfg["upload"]
    file_field = ups.get("file_field", "file")
    target = client.url(ups["path"])
    allowed = [e.lower() for e in ups.get("allowed_extensions", [])]
    findings = []

    control, control_failure = _control_upload(client, cfg)
    if control_failure:
        return [control_failure]

    for category, fname, content, ctype, sev, note in PAYLOADS:
        payload_content = content.replace(b"FIO", MARK)
        try:
            resp = client.upload(ups, fname, payload_content, ctype,
                                 extra_overrides={"title": "fio-scan",
                                                  "body": "fio-scan"})
        except Exception as e:
            findings.append(Finding(category=category, target_url=target,
                                    parameter=file_field, payload=fname,
                                    result="ERROR", severity=SEV_INFO,
                                    evidence=f"요청 오류: {e}",
                                    details={"control_upload": control}))
            continue

        accepted = _accepted(cfg, resp)
        dl_path, served = _fetch_back(client, cfg, resp)
        stored_name = served_ct = disp = ""
        inline = retrievable = False
        if served is not None:
            served_ct = served.headers.get("Content-Type", "")
            disp = served.headers.get("Content-Disposition", "")
            inline = (disp == "" or disp.lower().startswith("inline"))
            retrievable = served.status_code == 200 and MARK in served.content
            if "filename=" in disp:
                stored_name = disp.split("filename=", 1)[1].strip('"; ')

        f = _judge(category, fname, sev, note, target, file_field, resp,
                   accepted, dl_path, stored_name, served_ct, inline,
                   retrievable, allowed)
        f.details["control_upload"] = control
        findings.append(f)
    return _collapse_rejected_payloads(findings, target, file_field, control)


# 거부 메시지 후보 키워드(한/영)
_REJECT_KW = ("허용되지", "허용 되지", "허용되는", "확장자", "형식", "파일 형식", "업로드할 수",
              "업로드 할 수", "용량", "크기", "초과", "실패", "오류", "불가", "잘못",
              "유효하지", "not allowed", "invalid", "too large", "forbidden",
              "error", "unsupported", "denied")


def _reject_reason(resp):
    """업로드 거부 시 '어떤 반응으로 거부했는지'를 사실로 추출.

    반환: {status, landing, message, inferred}
      - status  : 응답 상태코드
      - landing : 어디로 떨어졌나(폼 재표시/리다이렉트 등)
      - message : 응답에서 찾은 거부 메시지(있으면)
      - inferred: 추정 검증 단계(확장자/크기/CSRF/인증/기타)
    """
    status = resp.status_code
    url = resp.url or ""
    low = url.lower()
    # landing 판정
    if any(x in low for x in ("login", "signin")):
        landing = "로그인 페이지로 리다이렉트"
    elif "/write" in low or status == 200:
        landing = "업로드 폼으로 복귀/재표시"
    else:
        landing = f"status {status}"

    # 응답 본문에서 거부 메시지 추출 (태그를 먼저 제거해 '보이는 텍스트'에서만 검색)
    text = ""
    try:
        text = resp.text
    except Exception:
        pass
    visible = _re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text, flags=_re.S | _re.I)
    visible = _re.sub(r"<[^>]+>", " ", visible)
    visible = _re.sub(r"\s+", " ", visible).strip()
    message = ""
    for kw in _REJECT_KW:
        idx = visible.find(kw)
        if idx != -1:
            seg = visible[max(0, idx - 30): idx + 50].strip()
            # 의미있는 한글/영문이 충분할 때만 메시지로 채택(기호 쪼가리 제외)
            if len(_re.sub(r"[^\w가-힣]", "", seg)) >= 4:
                message = seg[:120]
            break

    # 추정 검증 단계
    if "로그인" in landing:
        inferred = "인증 요구"
    elif any(k in message for k in ("확장자", "형식", "허용")):
        inferred = "확장자/형식 검증"
    elif any(k in message for k in ("용량", "크기", "초과", "too large")):
        inferred = "크기 제한"
    elif any(k in message.lower() for k in ("csrf", "토큰", "token")):
        inferred = "CSRF 검증"
    elif status in (400, 403, 415):
        inferred = f"서버 거부(HTTP {status})"
    else:
        inferred = "서버측 검증(상세 미상)"
    return {"status": status, "landing": landing, "message": message, "inferred": inferred}


def _ext(fname):
    base = fname.rstrip(". ").split("\x00")[0]
    return ("." + base.rsplit(".", 1)[1].lower()) if "." in base else ""


def _judge(category, fname, sev, note, target, field, resp, accepted,
           dl_path, stored_name, served_ct, inline, retrievable, allowed):
    details = {
        "uploaded_filename": fname,
        "accepted": accepted,
        "download_path": dl_path,
        "stored_filename": stored_name,
        "served_content_type": served_ct,
        "served_inline": inline,
        "content_retrievable": retrievable,
        "note": note,
    }
    base = Finding(category=category, target_url=target, method="POST",
                   parameter=field, payload=fname,
                   status_code=resp.status_code, details=details)

    # 1) 거부됨 → 안전 (어떤 반응으로 거부했는지까지 기록)
    if not accepted:
        rej = _reject_reason(resp)
        details["rejection"] = rej
        base.result, base.severity = SAFE, SEV_INFO
        msg = f" 메시지:'{rej['message']}'" if rej["message"] else ""
        base.evidence = (f"서버가 거부함 [{rej['inferred']}] "
                         f"(status={rej['status']}, 결과={rej['landing']}{msg})")
        return base

    # 2) 수락됨 → 유형별 판단
    # 저장형 XSS: html/svg 가 실행가능 타입으로 inline 제공
    if category.startswith(("Stored XSS", "SVG XSS")):
        dangerous_ct = ("html" in served_ct.lower()) or ("svg" in served_ct.lower())
        if retrievable and inline and dangerous_ct:
            base.result, base.severity = VULNERABLE, HIGH
            base.evidence = "스크립트 파일이 inline+실행가능 Content-Type 으로 제공 → 저장형 XSS"
        elif retrievable:
            base.result, base.severity = POTENTIAL, MEDIUM
            base.evidence = f"업로드 수락됨(제공 ct={served_ct}, inline={inline}) - 렌더 환경 수동확인"
        else:
            base.result, base.severity = POTENTIAL, LOW
            base.evidence = "업로드는 수락되었으나 되받기 실패 - 저장경로 수동확인"
        return base

    # 경로조작 파일명: 저장명에 경로문자 잔존 여부
    if category.startswith("Path Traversal"):
        has_sep = ("/" in stored_name) or ("\\" in stored_name)
        if stored_name and has_sep:
            base.result, base.severity = VULNERABLE, HIGH
            base.evidence = f"파일명 미살균: 저장명에 경로구분자 잔존('{stored_name}') → 디렉토리 이탈 가능"
        elif stored_name and ".." in stored_name:
            base.result, base.severity = SAFE, SEV_INFO
            base.evidence = f"경로구분자가 제거되어 상위 디렉터리 이동이 발생하지 않음(저장명='{stored_name}')"
        else:
            base.result, base.severity = SAFE, SEV_INFO
            base.evidence = "수락되었으나 파일명 정규화됨"
        return base

    # CR/LF 문자열이 파일명으로 수락됐다는 사실만으로 헤더 분할 취약점은
    # 성립하지 않는다. 저장명이나 응답 헤더에 실제 개행 영향이 있어야 확증한다.
    if category.startswith("Filename Injection (CRLF)"):
        if "\r" in stored_name or "\n" in stored_name:
            base.result, base.severity = VULNERABLE, LOW
            base.evidence = "저장 파일명에 CR/LF가 남아 응답 헤더 분할 가능성이 확인됨"
        else:
            base.result, base.severity = SAFE, SEV_INFO
            base.evidence = "CR/LF 파일명을 전송했으나 저장명·응답 헤더에 개행 영향이 확인되지 않음"
        return base

    # 위험 확장자/우회류: 수락 자체가 문제
    ext = _ext(fname)
    if allowed and ext and ext not in allowed:
        base.result, base.severity = VULNERABLE, sev
        base.evidence = f"허용목록 외 확장자('{ext}')가 업로드 수락됨 - 서버측 확장자 검증 미흡"
    elif allowed and ext in allowed:
        # 최종 확장자가 허용목록이어도, 서버측 코드가 든 이중 확장자나
        # 폴리글랏이 실제 저장되고 동일 내용으로 다시 제공되면 내용 검증
        # 우회는 관찰이 아니라 확증이다. 실행 가능성은 별도 단계의 문제다.
        content_bypass = category.startswith((
            "Extension Bypass - Double Extension",
            "Content Validation Bypass (Magic Bytes)",
        ))
        if content_bypass and retrievable:
            base.result = VULNERABLE
            base.severity = sev if sev in (CRITICAL, HIGH, MEDIUM) else MEDIUM
            base.evidence = (
                "코드가 포함된 이중 확장자/폴리글랏 파일이 저장되고 동일 내용으로 "
                "다운로드되어 서버측 파일 내용 검증 우회가 확인됨"
            )
        elif content_bypass:
            base.result, base.severity = POTENTIAL, MEDIUM
            base.evidence = "우회 파일 업로드는 수락됐으나 저장 파일을 되받지 못해 수동 확인 필요"
        else:
            base.result, base.severity = SAFE, SEV_INFO
            base.evidence = "허용 확장자 파일이 정상 정책 범위에서 처리됨"
    else:
        base.result, base.severity = VULNERABLE, sev
        base.evidence = "위험 파일 업로드가 수락됨"
    return base


def check_missing_auth(cfg) -> list[Finding]:
    """미인증 세션으로 업로드 시도."""
    ups = cfg["upload"]
    target = Client(cfg["base_url"]).url(ups["path"])
    anon = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    try:
        resp = anon.upload(ups, "anon.txt", MARK + b" anon", "text/plain",
                           extra_overrides={"title": "fio", "body": "fio"})
        accepted = _accepted(cfg, resp)
    except Exception as e:
        return [Finding(category="Missing Authentication (Upload)",
                        target_url=target, parameter=ups.get("file_field", "file"),
                        payload="anon.txt", result="ERROR", severity=SEV_INFO,
                        evidence=f"요청 오류: {e}")]
    f = Finding(category="Missing Authentication (Upload)", target_url=target,
                parameter=ups.get("file_field", "file"), payload="anon.txt",
                status_code=resp.status_code,
                details={"accepted": accepted, "final_url": resp.url})
    if accepted:
        f.result, f.severity = VULNERABLE, HIGH
        f.evidence = "로그인 없이 파일 업로드가 수락됨"
    else:
        f.result, f.severity = SAFE, SEV_INFO
        f.evidence = "미인증 업로드 차단됨"
    return [f]


def check_broken_access_control(cfg) -> list[Finding]:
    """권한 제한 업로드 경로에 낮은 권한 계정으로 강제 POST(forced browsing).

    cfg["access_control"] = {
      "restricted_path": "/my-class/board/write/notice",
      "low_priv_auth": {...},     # 보통 attacker_auth 재사용
      "csrf_from": "/my-class/board/write/qna",  # 토큰 얻을 접근가능 페이지
      "file_field": "file",
      "extra_fields": {...},
      "success_indicators": ["/board/notice/"]
    }
    화면에서 버튼을 숨겼는지가 아니라, 서버가 실제로 막는지 검증한다.
    """
    ac = cfg.get("access_control")
    if not ac:
        return [skipped("Broken Access Control (Privileged Upload)",
                        "notice_path/access_control 미설정 - 권한 제한 업로드 경로 없음")]
    low = ac.get("low_priv_auth") or cfg.get("attacker_auth")
    if not low:
        return [skipped("Broken Access Control (Privileged Upload)",
                        "attacker 계정 미설정 - 저권한 강제 접근 테스트 불가")]
    c = Client(cfg["base_url"], verify_tls=cfg.get("verify_tls", True))
    if not c.login(low):
        return [Finding(category="Broken Access Control (Privileged Upload)",
                        target_url=c.url(ac["restricted_path"]),
                        result="ERROR", severity=SEV_INFO,
                        evidence="저권한 계정 로그인 실패")]
    # 접근 가능한 페이지에서 csrf 토큰 확보(제한 페이지는 403이라 토큰 못 얻음)
    tok = None
    csrf_from = ac.get("csrf_from")
    if csrf_from:
        tok = c.extract_token(csrf_from, cfg.get("upload", {}).get("csrf_field", "csrf_token"))
    data = dict(ac.get("extra_fields", {"title": "fio-bac", "body": "fio"}))
    if tok:
        data[cfg.get("upload", {}).get("csrf_field", "csrf_token")] = tok
    field = ac.get("file_field", "file")
    files = {field: ("bac.txt", MARK + b"-forced", "text/plain")}
    target = c.url(ac["restricted_path"])
    try:
        r = c.post(ac["restricted_path"], data=data, files=files, allow_redirects=True)
    except Exception as e:
        return [Finding(category="Broken Access Control (Privileged Upload)",
                        target_url=target, parameter=field, payload="bac.txt",
                        result="ERROR", severity=SEV_INFO, evidence=f"오류: {e}")]
    inds = ac.get("success_indicators", [])
    succeeded = r.status_code in (200, 201, 302) and (
        any(i in r.url for i in inds) or (not inds and r.status_code != 403))
    f = Finding(category="Broken Access Control (Privileged Upload)",
                target_url=target, method="POST", parameter=field, payload="bac.txt",
                status_code=r.status_code,
                details={"low_priv_user": low.get("fields", {}),
                         "final_url": r.url, "csrf_reused": bool(tok)})
    if succeeded:
        f.result, f.severity = VULNERABLE, HIGH
        f.evidence = "저권한 사용자가 관리자 전용 업로드 경로에 강제 POST 성공 - 서버측 인가 부재"
    else:
        f.result, f.severity = SAFE, SEV_INFO
        f.evidence = f"저권한 강제 POST 차단됨(status={r.status_code})"
    return [f]


def run(client: Client, cfg) -> list[Finding]:
    out = []
    out += check_payloads(client, cfg)
    out += check_missing_auth(cfg)
    out += check_broken_access_control(cfg)
    return out
