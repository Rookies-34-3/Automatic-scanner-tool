"""기존 스캔·분석 JSON과 기준 문서로 PDF 진단 보고서를 생성한다."""

import argparse
import hashlib
import json
import math
import os
import re
from collections import Counter
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from pathlib import Path
from uuid import uuid4
from zoneinfo import ZoneInfo

from report_writer import redact_sensitive


REPORT_VERSION = "1.1"
GUIDE_INDEX_VERSION = "2"
GUIDE_START_PAGE = 676  # PDF 뷰어 기준, 1부터 시작
VERDICT_MEANINGS = {
    "VULNERABLE": "자동 검사에서 취약점 판단에 사용한 증거가 확인되었습니다. 실제 영향 범위와 가이드 기준의 최종 판정은 담당자가 추가 검증해야 합니다.",
    "PASS": "실행한 검사 조건과 페이로드 범위에서 취약점 증거를 발견하지 못했습니다. 웹 시스템 전체의 안전이나 미점검 기능의 양호를 의미하지 않습니다.",
    "REVIEW": "증거가 불충분하거나 인증·입력 조건 등의 이유로 취약 여부를 확정하지 못했습니다. 수동 재현과 정책 확인이 필요합니다.",
    "ERROR": "통신 또는 스캐너 실행 오류로 검사를 완료하지 못했습니다. 취약·양호 판정으로 집계하지 않고 원인을 해결한 뒤 재검사해야 합니다.",
}
AUTOMATION_NOTES = [
    "검사 시점의 응답과 제공된 계정·세션·탐색 경로에 한정된 결과입니다. 탐색하지 못한 기능, 동적 JavaScript 화면, 다른 사용자 역할은 별도 점검이 필요합니다.",
    "HTTP 200이나 응답 유사도만으로 인증·인가 우회를 확정할 수 없습니다. 실제 보호 데이터 노출 여부와 공개 정책을 확인해야 합니다.",
    "HTTP 400은 CSRF 검증, 필수 입력값 또는 선택값 검증 등 여러 원인으로 발생합니다. HTTP 오류 자체를 취약점이나 양호의 증거로 해석하지 않습니다.",
    "XSS 문자열 반영은 브라우저 실행의 확정 증거와 다릅니다. 출력 문맥, 인코딩, CSP와 실제 실행 조건을 추가 확인해야 합니다.",
    "위험 파일 업로드나 경로 문자열 잔존만으로 원격 코드 실행(RCE) 또는 시스템 장악을 확정하지 않습니다. 저장 위치와 실행 가능 여부를 별도 검증해야 합니다.",
    "공격 시나리오는 개별 취약점의 연계 가능성을 설명합니다. 필요한 권한·환경·전제 조건이 검증되지 않았다면 실제 공격 성공으로 간주하지 않습니다.",
    "작성·업로드 검사 과정에서 테스트 데이터가 저장되거나 상태가 변경될 수 있습니다. 승인된 범위에서 수행하고 검사 후 잔여 데이터를 정리해야 합니다.",
    "가이드의 판단 기준과 항목 중요도는 자동 스캐너의 판정·위험도와 구분합니다. 기준 문서 연결은 전체 항목 점검 완료나 공식 적합성 판정을 의미하지 않습니다.",
    "조치 이후 동일 조건의 재검사와 역할별 수동 검증을 수행하고, 기존 결과 파일이 갱신되기 전에 진단 증적을 보관해야 합니다.",
]
GUIDE_TOPICS = {
    "sqli": ["SQL 인젝션"], "xss": ["크로스사이트 스크립트"],
    "ssrf": ["서버사이드 요청 위조"], "authn": ["불충분한 인증 절차"],
    "authz": ["불충분한 권한 검증"], "directory_indexing": ["디렉터리 인덱싱"],
    "admin_exposure": ["관리자페이지 노출"],
}


def _project_path(value) -> Path:
    path = Path(value)
    return path if path.is_absolute() else Path(__file__).resolve().parent / path


def _json_hash(value) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _tokens(text):
    """한국어 띄어쓰기 차이를 고려한 단어와 한글 2글자 검색 토큰."""
    words = re.findall(r"[a-z0-9]+|[가-힣]+", str(text).lower())
    return words + [word[index:index + 2] for word in words if re.fullmatch(r"[가-힣]+", word)
                    for index in range(len(word) - 1)]


def _guide_field(text, start, end):
    # '점검 대상 및 판단 기준'이라는 절 제목 대신 실제 필드 라벨에서 추출한다.
    match = re.search(r"(?:^|\n)[ \t]*" + re.escape(start) + r"\s*(.*?)\n[ \t]*" + re.escape(end), text, re.S)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def load_guide_index(pdf_path, *, start_page=GUIDE_START_PAGE, cache_dir=None):
    """웹 장만 추출하여 페이지·항목·기준을 보존한다. 외부 API를 호출하지 않는다."""
    pdf_path = _project_path(pdf_path)
    if not pdf_path.is_file():
        raise FileNotFoundError(f"2026년 기준 PDF를 찾을 수 없습니다: {pdf_path}")
    digest = hashlib.sha256(pdf_path.read_bytes()).hexdigest()
    cache_dir = _project_path(cache_dir or "output/rag-index")
    cache_path = cache_dir / f"guide-{digest[:16]}-{start_page}-v{GUIDE_INDEX_VERSION}.json"
    if cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if cached.get("pdf_sha256") == digest and cached.get("index_version") == GUIDE_INDEX_VERSION:
                cached["source_file"] = pdf_path.name
                return cached
        except (OSError, ValueError):
            pass
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise RuntimeError("PDF 검색을 위해 requirements.txt의 pypdf를 설치하세요.") from exc
    reader = PdfReader(str(pdf_path))
    if start_page < 1 or start_page > len(reader.pages):
        raise ValueError("PDF 시작 페이지가 문서 범위를 벗어났습니다.")
    cover = reader.pages[0].extract_text() or ""
    if "2026" not in cover:
        raise ValueError("기준 PDF 표지에서 2026년을 확인하지 못했습니다.")
    pages = []
    for index in range(start_page - 1, len(reader.pages)):
        text = reader.pages[index].extract_text() or ""
        if pages and re.search(r"Chapter\s*(?:1[1-9]|[2-9]\d)\b", text):
            break
        pages.append((index + 1, text))
    if not pages or not re.search(r"Web\s*Application|웹", pages[0][1], re.I):
        raise ValueError("시작 페이지에서 웹 애플리케이션 장을 확인하지 못했습니다.")
    catalog = []
    for _, text in pages[:4]:
        for match in re.finditer(r"(?m)^([^\n]+?)\s+(상|중|하)\s+([A-Z]{2})\s*$", text):
            catalog.append({"title": match[1].strip(), "importance": match[2], "code": match[3]})
    items, chunks = [], []
    current = None
    header_pattern = r"(?m)^\s*([A-Z]{2})\s*\n\s*\((상|중|하)\)\s*\n\s*Web Application\(웹\)\s*\n\s*(\d+)\.\s*([^\n]+)"
    for page, text in pages:
        header = re.search(header_pattern, text)
        if header:
            number = int(header[3])
            entry = catalog[number - 1] if 0 < number <= len(catalog) else {}
            current = {"code": entry.get("code", header[1]), "source_header_code": header[1],
                       "title": entry.get("title", header[4].strip()),
                       "importance": entry.get("importance", header[2]), "page": page,
                       "purpose": _guide_field(text, "점검 목적", "보안 위협"),
                       "threat": _guide_field(text, "보안 위협", "참고"),
                       "criteria": _guide_field(text, "판단 기준", "조치 방법"),
                       "remediation": _guide_field(text, "조치 방법", "조치 시 영향")}
            items.append(current)
        if current is None:
            continue  # 목차는 검색 증거로 사용하지 않는다.
        cleaned = re.sub(r"\n{3,}", "\n\n", text).strip()
        for offset in range(0, len(cleaned), 1080):
            fragment = cleaned[offset:offset + 1200]
            if not fragment:
                continue
            chunks.append({"chunk_id": f"P{page}-{offset}", "page": page,
                           "item_code": current["code"], "title": current["title"], "text": fragment})
    if not items or not chunks:
        raise ValueError("웹 점검 항목의 텍스트를 추출하지 못했습니다. 스캔 PDF는 OCR 처리가 필요합니다.")
    result = {"index_version": GUIDE_INDEX_VERSION, "pdf_sha256": digest, "source_file": pdf_path.name,
              "document_title": "2026 주요정보통신기반시설 기술적 취약점 분석·평가방법 상세가이드",
              "start_page": start_page, "end_page": pages[-1][0], "items": items, "chunks": chunks}
    cache_dir.mkdir(parents=True, exist_ok=True)
    _write_text(cache_path, json.dumps(result, ensure_ascii=False, indent=2))
    return result


def retrieve_guide(index, query, *, topics=None, limit=2):
    """로컬 BM25 검색. 관련 항목의 개요·판단 기준과 검색 구절을 함께 반환한다."""
    documents = index["chunks"]
    terms = [Counter(_tokens(item["title"] + " " + item["text"])) for item in documents]
    lengths = [sum(term.values()) for term in terms]
    average = sum(lengths) / max(1, len(lengths))
    frequencies = Counter(token for term in terms for token in term)
    query_tokens = set(_tokens(query))
    scores = []
    for item, term, length in zip(documents, terms, lengths):
        if topics and not any(re.sub(r"\s", "", topic) in re.sub(r"\s", "", item["title"]) for topic in topics):
            continue
        score = 0.0
        for token in query_tokens:
            frequency = term.get(token, 0)
            if frequency:
                idf = math.log(1 + (len(documents) - frequencies[token] + 0.5) / (frequencies[token] + 0.5))
                score += idf * frequency * 2.5 / (frequency + 1.5 * (0.25 + 0.75 * length / max(1, average)))
        if score > 0:
            scores.append((score, item))
    scores.sort(key=lambda pair: (-pair[0], pair[1]["page"], pair[1]["chunk_id"]))
    references, seen = [], set()
    for score, chunk in scores:
        if chunk["item_code"] in seen:
            continue
        seen.add(chunk["item_code"])
        item = next(item for item in index["items"] if item["code"] == chunk["item_code"])
        references.append({**item, "matched_page": chunk["page"], "chunk_id": chunk["chunk_id"],
                           "excerpt": chunk["text"], "score": round(score, 4)})
        if len(references) >= limit:
            break
    return references


def _finding_key(item, *, ai=False):
    parameters = tuple(sorted({(str(p.get("name", "")), str(p.get("location", "")))
                               for p in item.get("parameters", []) if isinstance(p, dict)}))
    return (item.get("scanner_id", ""), item.get("url", ""), str(item.get("method", "")).upper(),
            item.get("name", ""), parameters, str(item.get("evidence" if ai else "result", "")))


def _finding_topics(item):
    scanner = item.get("scanner_id", "")
    if scanner == "fileio":
        text = (str(item.get("name", "")) + " " + str(item.get("url", ""))).lower()
        return ["파일 다운로드"] if "download" in text or "enumeration" in text else ["악성 파일 업로드"]
    return GUIDE_TOPICS.get(scanner, [])


def _review_steps(item):
    steps = ["원본 요청·응답과 서버 오류 메시지를 확인하고 동일 조건으로 재현합니다.",
             "유효한 인증 세션, CSRF 토큰, 필수 입력값과 선택값으로 요청을 구성합니다."]
    if item.get("scanner_id") in {"authn", "authz", "admin_exposure"}:
        steps.append("비로그인·소유자·다른 사용자 응답을 비교하고 실제 공개 정책과 보호 데이터를 확인합니다.")
    if item.get("scanner_id") == "xss":
        steps.append("출력 문맥과 인코딩, CSP를 확인하고 브라우저 실행 여부를 별도 검증합니다.")
    steps.append("검사 오류를 해소한 후 재점검하고 최종 판정을 기록합니다.")
    return steps


def build_diagnostic_report(scan_data, analysis_data, guide_index):
    """통계·판정 의미는 Python, 해석은 기존 AI JSON, 기준은 검색 문서에서 구성한다."""
    if not isinstance(scan_data, dict) or not isinstance(analysis_data, dict):
        raise ValueError("스캔 및 추가 분석 JSON의 최상위 값은 객체여야 합니다.")
    if not isinstance(scan_data.get("findings"), list):
        raise ValueError("scan-results.json에 정규화된 findings 목록이 필요합니다.")
    findings = scan_data["findings"]
    if not all(isinstance(item, dict) for item in findings):
        raise ValueError("findings의 각 항목은 객체여야 합니다.")
    findings = [{**item, "vuln": str(item.get("vuln", "REVIEW")).upper()
                 if str(item.get("vuln", "REVIEW")).upper() in VERDICT_MEANINGS else "REVIEW"}
                for item in findings]
    notes = []
    analysis = analysis_data.get("analysis", {})
    analysis_current = bool(analysis_data) and analysis_data.get("source_hash") == _json_hash(scan_data)
    if not analysis_current:
        notes.append("analysis.json이 현재 스캔과 일치하지 않거나 출처 해시가 없습니다. 이전 총평·대응 방안·공격 시나리오는 사용하지 않았습니다.")
        analysis = {}
    ai_findings = {_finding_key(item, ai=True): item for item in analysis.get("key_findings", [])
                   if isinstance(item, dict)}
    counts = {status: sum(str(item.get("vuln", "")).upper() == status for item in findings)
              for status in VERDICT_MEANINGS}
    severities = Counter(str(item.get("severity", "UNKNOWN")).upper() for item in findings
                         if str(item.get("vuln", "")).upper() == "VULNERABLE")
    high_risk = severities["HIGH"] + severities["CRITICAL"]
    rows, vulnerable_number = [], 0
    covered = set()
    for number, finding in enumerate(findings, 1):
        verdict = str(finding.get("vuln", "REVIEW")).upper()
        if verdict not in VERDICT_MEANINGS:
            verdict = "REVIEW"
        if verdict == "VULNERABLE":
            vulnerable_number += 1
        finding_id = f"F{vulnerable_number:03d}" if verdict == "VULNERABLE" else f"C{number:03d}"
        ai = ai_findings.get(_finding_key(finding), {}) if verdict == "VULNERABLE" else {}
        topics = _finding_topics(finding)
        # 포트 스캔은 웹 장 기준에 직접 연결하지 않는다.
        refs = retrieve_guide(guide_index, " ".join(topics) + " " + str(finding.get("name", "")) + " "
                              + str(finding.get("result", "")), topics=topics) if topics else []
        covered.update(ref["code"] for ref in refs)
        remediation = ai.get("recommendation") or (finding.get("details") or {}).get("remediation")
        if not remediation and refs:
            remediation = refs[0].get("remediation")
        rows.append({"finding_id": finding_id, "scanner_id": finding.get("scanner_id", ""),
                     "name": finding.get("name", ""), "url": finding.get("url", ""),
                     "method": finding.get("method", ""), "parameters": finding.get("parameters", []),
                     "verdict": verdict, "severity": finding.get("severity", "UNKNOWN"),
                     "meaning": VERDICT_MEANINGS[verdict], "evidence": finding.get("result", ""),
                     "details": finding.get("details", {}), "summary": ai.get("summary", ""),
                     "impact": ai.get("impact", ""), "validation_note": ai.get("validation_note", ""),
                     "recommendation": remediation or "근거와 시스템 정책을 검토한 후 적절한 조치 방안을 결정해야 합니다.",
                     "recommendation_source": "analysis.json" if ai.get("recommendation") else "스캐너" if (finding.get("details") or {}).get("remediation") else "기준 문서" if remediation else "수동 검토",
                     "review_steps": _review_steps(finding) if verdict in {"REVIEW", "ERROR"} else [],
                     "guide_references": refs})
    target = str(scan_data.get("target") or scan_data.get("target_url") or "미제공")
    intro = (f"본 진단은 대상 웹 시스템({target})을 대상으로 ROOKIESCAN 프로그램에 의해 수행되었습니다. "
             f"자동 검사에서 취약 판정 {counts['VULNERABLE']}건이 확인되었으며, "
             f"이 중 HIGH 및 CRITICAL 등급은 {high_risk}건입니다.")
    return redact_sensitive({
        "report_version": REPORT_VERSION, "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target, "scan_time": scan_data.get("generated_at", "미제공"),
        "source_hash": _json_hash(scan_data), "analysis_current": analysis_current,
        "additional_ai_calls": 0, "retrieval_method": "local BM25 + deterministic templates",
        "guide": {key: guide_index[key] for key in ("source_file", "document_title", "pdf_sha256", "start_page", "end_page")},
        "summary": {"total_endpoints": len({(item.get('method'), item.get('url')) for item in findings}),
                    "total_scans": len({(item.get('method'), item.get('url'), item.get('scanner_id')) for item in findings}),
                    "total_findings": len(findings), "verdict_counts": counts,
                    "high_risk": high_risk, "severity_counts": dict(severities)},
        "assessment_intro": intro, "overall_assessment": analysis.get("overall_assessment") or intro,
        "overall_risk": next((level for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if severities[level]), "미확정"),
        "verdict_meanings": VERDICT_MEANINGS, "automation_notes": AUTOMATION_NOTES, "notes": notes,
        "findings": rows, "attack_scenarios": analysis.get("attack_scenarios", []),
        "priority_actions": analysis.get("priority_actions", []),
        "guide_coverage": [{"code": item["code"], "title": item["title"], "page": item["page"],
                            "status": "관련 자동 검사 결과 있음(공식 판정 아님)" if item["code"] in covered else "보고서에 연결된 검사 결과 없음(미점검 또는 미지원)"}
                           for item in guide_index["items"]],
    })


def _report_sections(report):
    """HTML/Markdown이 같은 내용을 출력하도록 보고서 본문을 한 번만 구성한다."""
    sections = []
    summary = report["summary"]
    sections.append(("진단 개요", [f"대상: {report['target']}", f"검사 시각: {report['scan_time']}",
        f"보고서 생성 시각: {report['generated_at']}",
        f"엔드포인트 {summary['total_endpoints']}개 · 스캐너 작업 {summary['total_scans']}회 · 판정 항목 {summary['total_findings']}건",
        " · ".join(f"{key} {value}건" for key, value in summary["verdict_counts"].items()),
        f"고위험 {summary['high_risk']}건 · 종합 위험도 {report['overall_risk']}",
        f"참고 문서: {report['guide']['document_title']} / PDF {report['guide']['start_page']}~{report['guide']['end_page']}페이지",
        "보고서 생성 시 추가 AI 호출: 0회. 기존 AI 분석을 재사용하고 로컬 문서 검색과 Python 템플릿으로 작성함."] + report["notes"]))
    sections.append(("종합 위험 평가", report["overall_assessment"].split("\n\n")))
    sections.append(("자동 검사 판정의 의미", [f"{key}: {value}" for key, value in report["verdict_meanings"].items()]))
    for row in report["findings"]:
        parameters = ", ".join(str(p.get("name", "")) for p in row["parameters"] if isinstance(p, dict)) or "경로 기반 검사"
        lines = [f"판정: {row['verdict']} · 위험도: {row['severity']} · 스캐너: {row['scanner_id']}",
                 f"위치: {row['method']} {row['url']}", f"입력 항목: {parameters}",
                 f"판정 의미: {row['meaning']}", f"탐지 근거: {row['evidence']}"]
        for key, label in (("summary", "분석 요약"), ("impact", "예상 영향"), ("validation_note", "추가 확인 조건")):
            if row[key]:
                lines.append(f"{label}: {row[key]}")
        lines.append(f"대응 방안 ({row['recommendation_source']}): {row['recommendation']}")
        lines.extend(f"수동 검토: {step}" for step in row["review_steps"])
        if not row["guide_references"]:
            lines.append("참고 기준: 웹 장에서 직접 연결할 항목이 없어 기준 적합성을 판정하지 않았습니다.")
        for ref in row["guide_references"]:
            lines.append(f"참고 기준: {ref['code']} {ref['title']} / 항목 중요도 {ref['importance']} / PDF {ref['page']}페이지")
            for key, label in (("purpose", "점검 목적"), ("threat", "보안 위협"), ("criteria", "가이드 판단 기준"), ("remediation", "가이드 조치 방법")):
                if ref.get(key):
                    lines.append(f"{label}: {ref[key]}")
            lines.append(f"검색 근거: PDF {ref['matched_page']}페이지, {ref['chunk_id']} (관련 내용 검색 결과이며 취약 판정의 추가 증거는 아님)")
        sections.append((f"{row['finding_id']} · {row['name']}", lines))
    review = [row for row in report["findings"] if row["verdict"] in {"REVIEW", "ERROR"}]
    sections.append(("수동 검토 및 재검사 목록", [f"{row['finding_id']} · {row['verdict']} · {row['method']} {row['url']} · {row['evidence']}" for row in review] or ["REVIEW 또는 ERROR 항목이 없습니다. PASS의 검사 범위 제한은 별도로 적용됩니다."]))
    for number, scenario in enumerate(report["attack_scenarios"], 1):
        lines = [f"상태: {scenario.get('scenario_status', 'possible')} · 신뢰도: {scenario.get('confidence', '미제공')}",
                 f"연결 근거: {', '.join(scenario.get('evidence_refs', []))}"]
        for key, label in (("scenario", "예상 공격 흐름"), ("potential_impact", "잠재적 영향"),
                           ("required_conditions", "추가 확인 조건")):
            lines.append(f"{label}: {scenario.get(key, '미제공')}")
        lines.extend(f"관련 엔드포인트: {url}" for url in scenario.get("related_endpoints", []))
        sections.append((f"공격 시나리오 {number} · {scenario.get('title', '')}", lines))
    if not report["attack_scenarios"]:
        sections.append(("공격 시나리오", ["현재 스캔에 연결된 공격 시나리오가 없습니다. 임의로 생성하지 않았습니다."]))
    sections.append(("개선 우선순위", [f"{item.get('priority', '')}. {item.get('title', '')}: {item.get('reason', '')} / 관련 근거: {', '.join(item.get('related_finding_ids', []))}" for item in report["priority_actions"]] or ["확정 취약점을 우선 조치하고 REVIEW·ERROR 항목을 재검증하십시오."]))
    sections.append(("자동화 도구의 주의사항", report["automation_notes"]))
    sections.append(("가이드 항목별 연결 범위", [f"{item['code']} · {item['title']} · PDF {item['page']}페이지: {item['status']}" for item in report["guide_coverage"]]))
    sections.append(("재현 및 출처 정보", [f"스캔 JSON SHA-256: {report['source_hash']}",
        f"기준 PDF SHA-256: {report['guide']['pdf_sha256']}",
        f"검색 방식: {report['retrieval_method']}", "PDF 페이지 번호는 인쇄본 페이지가 아닌 PDF 뷰어에서 1부터 세는 번호입니다."]))
    return sections


def render_report_markdown(report):
    lines = ["# ROOKIESCAN 웹 취약점 진단 보고서", ""]
    for title, paragraphs in _report_sections(report):
        lines.extend([f"## {title}", ""])
        for paragraph in paragraphs:
            lines.extend([str(paragraph), ""])
    return "\n".join(lines)


def render_report_html(report):
    sections = "".join("<section><h2>" + escape(title) + "</h2>" +
                       "".join("<p>" + escape(str(paragraph)).replace("\n", "<br>") + "</p>" for paragraph in paragraphs) +
                       "</section>" for title, paragraphs in _report_sections(report))
    return ('<!doctype html><html lang="ko"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>ROOKIESCAN 웹 취약점 진단 보고서</title><style>'
            'body{color:#172033;background:#f3f6fa;font:15px/1.8 "Malgun Gothic",sans-serif;margin:0}'
            'main{max-width:960px;margin:36px auto;background:white;padding:40px}h1{font-size:26px}'
            'h2{font-size:19px;border-bottom:1px solid #d9e1ed;padding-bottom:10px}'
            'section{margin:28px 0}p{white-space:normal;overflow-wrap:anywhere}'
            '@media print{body{background:white;font-size:11pt}main{margin:0;padding:0}h2{break-after:avoid}p{orphans:3;widows:3}}'
            '</style></head><body><main><h1>ROOKIESCAN 웹 취약점 진단 보고서</h1>' + sections + '</main></body></html>')


def _report_date(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(ZoneInfo("Asia/Seoul")).strftime("%Y.%m.%d %H:%M KST")
    except (ValueError, TypeError):
        return str(value or "미제공")


def render_report_pdf(report):
    """한글 글꼴을 포함한 A4 진단 보고서. 표지·목차·상세 결과·부록을 구성한다."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import (
            BaseDocTemplate, Frame, LongTable, NextPageTemplate,
            PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle,
        )
        from reportlab.platypus.tableofcontents import TableOfContents
    except ImportError as exc:
        raise RuntimeError("PDF 보고서를 생성하려면 requirements.txt의 reportlab을 설치하세요.") from exc

    fonts = _project_path("docs/fonts")
    for name, filename in (("RookiesSans", "NanumGothic.ttf"), ("RookiesSansBold", "NanumGothicBold.ttf")):
        path = fonts / filename
        if not path.is_file():
            raise FileNotFoundError(f"PDF 한글 글꼴 파일을 찾을 수 없습니다: {path}")
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(path)))
    pdfmetrics.registerFontFamily("RookiesSans", normal="RookiesSans", bold="RookiesSansBold",
                                  italic="RookiesSans", boldItalic="RookiesSansBold")

    navy = colors.HexColor("#172C48")
    teal = colors.HexColor("#087E8B")
    ink = colors.HexColor("#243247")
    muted = colors.HexColor("#637287")
    line = colors.HexColor("#DCE3EC")
    pale = colors.HexColor("#F3F6FA")
    width, height = A4
    margin = 20 * mm
    content_width = width - 2 * margin
    date = _report_date(report["generated_at"])
    report_id = "RS-" + date[:10].replace(".", "") + "-" + report["source_hash"][:8].upper()
    style = {
        "body": ParagraphStyle("Body", fontName="RookiesSans", fontSize=10, leading=15,
                               textColor=ink, wordWrap="CJK", spaceAfter=7, allowWidows=0, allowOrphans=0),
        "small": ParagraphStyle("Small", fontName="RookiesSans", fontSize=8.3, leading=12.5,
                                textColor=muted, wordWrap="CJK", spaceAfter=6),
        "h1": ParagraphStyle("Chapter", fontName="RookiesSansBold", fontSize=17, leading=25,
                             textColor=navy, spaceBefore=5, spaceAfter=17, keepWithNext=True, wordWrap="CJK"),
        "h2": ParagraphStyle("Finding", fontName="RookiesSansBold", fontSize=14, leading=21,
                             textColor=navy, spaceBefore=5, spaceAfter=13, keepWithNext=True, wordWrap="CJK"),
        "label": ParagraphStyle("Label", fontName="RookiesSansBold", fontSize=10.2, leading=16,
                                textColor=teal, spaceBefore=8, spaceAfter=4, keepWithNext=True),
        "cell": ParagraphStyle("Cell", fontName="RookiesSans", fontSize=8.5, leading=12.5,
                               textColor=ink, wordWrap="CJK"),
        "headcell": ParagraphStyle("HeadCell", fontName="RookiesSansBold", fontSize=8.5, leading=13,
                                   textColor=colors.white, wordWrap="CJK"),
        "evidence": ParagraphStyle("Evidence", fontName="RookiesSans", fontSize=9, leading=13.5,
                                   textColor=ink, backColor=pale, borderPadding=8, wordWrap="CJK",
                                   spaceBefore=5, spaceAfter=10, allowWidows=0, allowOrphans=0),
        "cover": ParagraphStyle("Cover", fontName="RookiesSansBold", fontSize=29, leading=44,
                                textColor=navy, wordWrap="CJK", spaceAfter=14),
    }

    def paragraph(value, kind="body"):
        text = escape(str(value or "미제공"), quote=False).replace("\r", "").replace("\n", "<br/>")
        return Paragraph(text, style[kind])

    def table(headers, rows, ratios):
        data = [[paragraph(value, "headcell") for value in headers]]
        data.extend([paragraph(value, "cell") for value in row] for row in rows)
        result = LongTable(data, colWidths=[content_width * value for value in ratios], repeatRows=1,
                           hAlign="LEFT")
        result.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), navy), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, pale]),
            ("LINEBELOW", (0, 0), (-1, 0), 0.7, navy),
            ("LINEBELOW", (0, 1), (-1, -1), 0.3, line),
            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        return result

    def metadata(rows):
        result = Table([[paragraph(label, "cell"), paragraph(value, "cell")] for label, value in rows],
                       colWidths=[content_width * 0.22, content_width * 0.78], hAlign="LEFT")
        result.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), pale), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOX", (0, 0), (-1, -1), 0.5, line), ("INNERGRID", (0, 0), (-1, -1), 0.3, line),
            ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ]))
        return result

    story = []

    def heading(title, level=0, bookmark=None):
        item = paragraph(title, "h1" if level == 0 else "h2")
        if bookmark:
            item._report_bookmark = (level, title, bookmark)
        story.append(item)

    def chapter(title, key):
        story.append(PageBreak())
        heading(title, bookmark=key)

    def block(label, value, *, evidence=False):
        if not value:
            return
        story.append(paragraph(label, "label"))
        for text in str(value).split("\n\n"):
            if text.strip():
                story.append(paragraph(text.strip(), "evidence" if evidence else "body"))

    def numbered(values):
        for number, value in enumerate(values, 1):
            story.append(paragraph(f"{number}. {value}"))

    def page_header(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(line)
        canvas.setLineWidth(0.5)
        canvas.line(margin, height - 17 * mm, width - margin, height - 17 * mm)
        canvas.setFont("RookiesSansBold", 8)
        canvas.setFillColor(navy)
        canvas.drawString(margin, height - 13 * mm, "ROOKIESCAN")
        canvas.setFont("RookiesSans", 7.3)
        canvas.setFillColor(muted)
        canvas.drawRightString(width - margin, height - 13 * mm, "웹 애플리케이션 모의해킹 진단 보고서")
        canvas.line(margin, 16 * mm, width - margin, 16 * mm)
        canvas.setFont("RookiesSans", 7)
        canvas.drawString(margin, 11 * mm, report_id + "  |  보안 진단자료 · 관계자 검토용")
        canvas.drawRightString(width - margin, 11 * mm, f"{doc.page:02d}")
        canvas.restoreState()

    def cover_background(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(navy)
        canvas.rect(0, height - 10 * mm, width, 10 * mm, fill=1, stroke=0)
        canvas.setFillColor(teal)
        canvas.rect(margin, height - 59 * mm, 18 * mm, 2 * mm, fill=1, stroke=0)
        canvas.setFont("RookiesSansBold", 13)
        canvas.setFillColor(navy)
        canvas.drawString(margin, height - 36 * mm, "ROOKIESCAN")
        canvas.setFont("RookiesSans", 8)
        canvas.setFillColor(muted)
        canvas.drawString(margin, height - 44 * mm, "WEB SECURITY ASSESSMENT REPORT")
        canvas.setFont("RookiesSans", 8)
        canvas.drawString(margin, 20 * mm, "보안 진단자료 · 관계자 검토용")
        canvas.drawRightString(width - margin, 20 * mm, f"REPORT VERSION {REPORT_VERSION}")
        canvas.restoreState()

    class ReportDocument(BaseDocTemplate):
        def afterFlowable(self, flowable):
            bookmark = getattr(flowable, "_report_bookmark", None)
            if bookmark:
                level, title, key = bookmark
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(title, key, level=level, closed=False)
                self.notify("TOCEntry", (level, title, self.page, key))

    buffer = BytesIO()
    document = ReportDocument(buffer, pagesize=A4, leftMargin=margin, rightMargin=margin,
                              topMargin=25 * mm, bottomMargin=22 * mm,
                              title="ROOKIESCAN 웹 애플리케이션 모의해킹 진단 보고서",
                              author="ROOKIESCAN", subject=report["target"])
    frame = Frame(margin, 22 * mm, content_width, height - 47 * mm, id="body",
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    document.addPageTemplates([PageTemplate(id="cover", frames=[frame], onPage=cover_background),
                               PageTemplate(id="body", frames=[frame], onPage=page_header)])

    story.extend([Spacer(1, 49 * mm), paragraph("웹 애플리케이션\n모의해킹 진단 보고서", "cover"),
                  paragraph("자동화 검사 결과 및 보안 개선 권고", "label"), Spacer(1, 18 * mm),
                  metadata([("진단 대상", report["target"]), ("진단 시각", _report_date(report["scan_time"])),
                            ("보고서 발행", date), ("문서 번호", report_id),
                            ("작성 도구", "ROOKIESCAN · 자동화 기반 웹 취약점 진단")]),
                  Spacer(1, 15 * mm), paragraph("본 보고서는 자동 검사 증거와 기존 분석 결과를 기반으로 작성되었습니다. "
                      "업무 영향과 최종 위험 평가는 담당자의 수동 검증을 통해 확정해야 합니다.", "small"),
                  NextPageTemplate("body"), PageBreak()])

    heading("문서 관리 및 이용 범위")
    story.append(metadata([("문서명", "웹 애플리케이션 모의해킹 진단 보고서"), ("문서 번호", report_id),
                           ("버전", REPORT_VERSION), ("작성", "ROOKIESCAN 자동 생성"),
                           ("검토자 / 승인자", "미기재 · 담당자 검토 필요"),
                           ("기준 문서", report["guide"]["document_title"]),
                           ("참조 범위", f"PDF {report['guide']['start_page']}~{report['guide']['end_page']}페이지")]))
    block("문서 목적", "자동 진단에서 수집한 증거를 정리하고 주요 위협, 대응 방안, 추가 검증 조건을 제시합니다. "
          "수동 모의해킹의 수행 범위나 공식 적합성 평가를 자동으로 대체하지 않습니다.")
    block("정보 취급", "대상 URL, 입력 지점 및 공격 재현 근거가 포함된 진단 자료입니다. "
          "공유 범위는 진단 대상 시스템의 관리 정책에 따라 결정하십시오.")
    block("작성 방식", "수치와 판정 설명은 Python으로 구성하고 기존 AI 분석을 재사용했습니다. "
          "기준 문서는 로컬 검색으로 연결하였으며 보고서 생성 과정의 추가 AI 호출은 없습니다.")

    story.append(PageBreak())
    heading("목차")
    toc = TableOfContents()
    toc.tableStyle = TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ])
    toc.levelStyles = [
        ParagraphStyle("TOCChapter", fontName="RookiesSansBold", fontSize=10.5, leading=16,
                       textColor=navy, spaceBefore=4, leftIndent=0, wordWrap="CJK"),
        ParagraphStyle("TOCFinding", fontName="RookiesSans", fontSize=9, leading=14.5,
                       textColor=ink, leftIndent=13, firstLineIndent=0, wordWrap="CJK"),
    ]
    story.append(toc)

    summary = report["summary"]
    vulnerable = [row for row in report["findings"] if row["verdict"] == "VULNERABLE"]
    review = [row for row in report["findings"] if row["verdict"] in {"REVIEW", "ERROR"}]
    chapter("1. 진단 개요 및 범위", "scope")
    story.append(metadata([("대상 시스템", report["target"]), ("검사 시각", _report_date(report["scan_time"])),
                           ("점검 방식", "탐색된 입력 지점에 대한 자동화 기반 웹 취약점 검사"),
                           ("범위 집계", f"엔드포인트 {summary['total_endpoints']}개 / 스캐너 작업 {summary['total_scans']}회 / 판정 항목 {summary['total_findings']}건"),
                           ("종합 위험도", report["overall_risk"])]))
    story.append(Spacer(1, 7 * mm))
    story.append(table(["판정", "항목 수", "해석"],
                       [(status, str(summary["verdict_counts"][status]), meaning)
                        for status, meaning in report["verdict_meanings"].items()], [0.17, 0.12, 0.71]))
    block("범위의 제한", "진단은 입력 JSON에 기록된 URL·메서드·계정 조건에서 수행한 검사에 한정됩니다. "
          "동적 화면, 미탐색 경로, 다른 역할 및 미지원 취약점은 별도 점검 대상입니다. "
          "고위험 건수는 HIGH와 CRITICAL 등급을 합산한 값이며, 해당 건수가 모두 RCE나 시스템 장악을 의미하지 않습니다.")
    for note in report["notes"]:
        block("입력 데이터 확인 사항", note)

    chapter("2. 종합 위험 평가", "assessment")
    for text in report["overall_assessment"].split("\n\n"):
        story.append(paragraph(text))
    block("위험도별 취약 판정", f"확정 취약 판정 {summary['verdict_counts']['VULNERABLE']}건 중 "
          f"고위험(HIGH·CRITICAL) {summary['high_risk']}건입니다. 자동 스캐너의 위험도는 업무 중요도와 "
          "접근 가능한 범위를 추가 검토하여 조정할 수 있습니다.")
    if summary["severity_counts"]:
        story.append(table(["위험도", "취약 판정 항목 수"],
                           [(level, str(summary["severity_counts"][level]))
                            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
                            if summary["severity_counts"].get(level)], [0.5, 0.5]))

    chapter("3. 주요 취약점 목록", "findings-summary")
    story.append(paragraph("취약 판정 항목을 요약한 목록입니다. 상세 근거와 조치 의견은 다음 장에서 확인할 수 있습니다."))
    if vulnerable:
        story.append(table(["근거 ID", "취약점 / 위험도", "대상 위치"],
                           [(row["finding_id"], row["name"] + "\n" + str(row["severity"]),
                             str(row["method"]) + " " + row["url"]) for row in vulnerable], [0.13, 0.36, 0.51]))
    else:
        story.append(paragraph("자동 검사에서 취약 판정 항목이 확인되지 않았습니다. 전체 안전성을 보증하는 의미는 아닙니다."))

    chapter("4. 취약점 상세 분석", "findings-detail")
    if not vulnerable:
        story.append(paragraph("상세 분석 대상인 취약 판정 항목이 없습니다."))
    for number, row in enumerate(vulnerable):
        if number:
            story.append(PageBreak())
        heading(f"{row['finding_id']}  {row['name']}", level=1, bookmark="finding-" + row["finding_id"])
        params = ", ".join(str(p.get("name", "")) for p in row["parameters"] if isinstance(p, dict)) or "경로 기반 검사"
        story.append(metadata([("판정 / 위험도", f"{row['verdict']} / {row['severity']}"),
                               ("대상 위치", f"{row['method']} {row['url']}"),
                               ("입력 항목 / 스캐너", f"{params} / {row['scanner_id']}")]))
        block("취약점 개요", row["summary"] or row["meaning"])
        block("탐지 근거", row["evidence"], evidence=True)
        details = row.get("details") or {}
        raw = details.get("raw_result")
        raw_items = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
        proofs = []
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            if item.get("payload"):
                proofs.append("검사 입력: " + str(item["payload"]))
            if item.get("evidence") and str(item["evidence"]) != str(row["evidence"]):
                proofs.append("응답 발췌: " + str(item["evidence"]))
        for key, label in (("payload", "검사 입력"), ("evidence_marker", "검증 지표"),
                           ("status_code", "HTTP 상태"), ("authenticated_status", "인증 요청 상태"),
                           ("anonymous_status", "비인증 요청 상태")):
            if details.get(key) is not None:
                proofs.append(f"{label}: {details[key]}")
        if proofs:
            block("재현 입력 및 응답 증거", "\n".join(dict.fromkeys(proofs)), evidence=True)
        block("예상 영향", row["impact"] or "자동 검사 근거가 확인된 범위에서 영향을 검토해야 합니다. "
              "추가 데이터 접근, 권한 획득 또는 코드 실행은 별도 검증 없이는 확정하지 않습니다.")
        block("개선 및 조치 의견", row["recommendation"])
        story.append(paragraph("조치 의견 출처: " + row["recommendation_source"], "small"))
        block("추가 확인 조건", row["validation_note"] or "원본 요청·응답을 재현하고, 적용된 보안 통제와 업무 정책을 "
              "함께 확인한 뒤 최종 위험도를 결정하십시오.")
        for ref in row["guide_references"]:
            block("기준 문서 연결", f"{ref['code']} · {ref['title']} / 중요도 {ref['importance']} / PDF {ref['page']}페이지")
            block("가이드 판단 기준", ref.get("criteria"))
            block("가이드 조치 방법", ref.get("remediation"))
            story.append(paragraph(f"검색 출처: PDF {ref['matched_page']}페이지 ({ref['chunk_id']}). "
                                   "기준 연결은 자동 판정의 참고 자료이며 공식 적합성 판정은 아닙니다.", "small"))
        if not row["guide_references"]:
            story.append(paragraph("웹 장에서 직접 연결할 기준이 없어 가이드 적합성을 판정하지 않았습니다.", "small"))

    chapter("5. 수동 검토 및 재검사 항목", "review")
    if not review:
        story.append(paragraph("REVIEW 또는 ERROR 항목이 없습니다. PASS 항목의 검사 범위 제한은 별도로 적용됩니다."))
    for row in review:
        heading(f"{row['finding_id']}  {row['name']}", level=1)
        story.append(metadata([("판정", row["verdict"]), ("대상 위치", f"{row['method']} {row['url']}")]))
        block("판정 의미", row["meaning"])
        block("확인된 근거 / 검사 제한", row["evidence"], evidence=True)
        block("검토 절차", "\n".join(f"{i}. {step}" for i, step in enumerate(row["review_steps"], 1)))

    chapter("6. 공격 시나리오 및 전제 조건", "scenarios")
    story.append(paragraph("아래 시나리오는 수집된 개별 증거에 근거한 연계 분석입니다. "
                           "실제 공격 체인의 성공 여부와 환경 조건은 별도로 확인해야 합니다."))
    statuses = {"possible": "연계 가능", "confirmed": "확인됨", "unlikely": "가능성 낮음"}
    confidences = {"high": "높음", "medium": "중간", "low": "낮음"}
    if not report["attack_scenarios"]:
        story.append(paragraph("현재 스캔에 연결된 공격 시나리오가 없습니다. 임의 시나리오는 생성하지 않았습니다."))
    for number, item in enumerate(report["attack_scenarios"], 1):
        if number > 1:
            story.append(PageBreak())
        heading(f"S{number:03d}  {item.get('title', '공격 시나리오')}", level=1)
        story.append(metadata([("상태 / 신뢰도", statuses.get(item.get("scenario_status"), "연계 가능") + " / " + confidences.get(item.get("confidence"), "미제공")),
                               ("연결 근거", ", ".join(item.get("evidence_refs", [])) or "미제공")]))
        block("예상 공격 흐름", item.get("scenario"))
        block("잠재적 영향", item.get("potential_impact"))
        block("추가 확인 조건", item.get("required_conditions"))
        block("관련 엔드포인트", "\n".join(item.get("related_endpoints", [])))

    chapter("7. 개선 우선순위 및 조치 검증", "remediation")
    for item in report["priority_actions"]:
        heading(f"우선순위 {item.get('priority', '')}  {item.get('title', '')}", level=1)
        block("조치 필요성", item.get("reason"))
        block("관련 근거", ", ".join(item.get("related_finding_ids", [])))
    if not report["priority_actions"]:
        story.append(paragraph("확정 취약점의 실제 영향 범위를 우선 검토하고 REVIEW·ERROR 항목을 재검증하십시오."))
    block("조치 관리", "조치 담당자와 완료 기한은 시스템 운영 조직이 업무 중요도와 변경 영향을 고려하여 지정해야 합니다. "
          "자동 보고서에서는 담당자·기한·조치 완료 상태를 임의로 기재하지 않습니다.")
    numbered(["취약점의 원본 요청·응답과 재현 조건을 보관합니다.",
              "서버 측 보안 통제를 적용한 뒤 정상 기능과 권한별 접근을 함께 검증합니다.",
              "동일 조건으로 재검사하여 증거가 재현되지 않는지 확인합니다.",
              "수동 확인 결과와 잔여 위험, 예외 승인 근거를 기록하고 담당자가 최종 판정을 검토합니다."])

    chapter("8. 자동화 검사 해석 및 주의사항", "limitations")
    numbered(report["automation_notes"])
    block("가이드 기준과 자동 판정의 구분", "기준 문서의 중요도는 항목의 일반적인 중요성을 나타내며 "
          "스캐너의 HIGH·MEDIUM 등급과 동일한 체계가 아닙니다. 자동 판정은 검사의 증거 수준을 나타내고, "
          "최종 양호·취약 판단은 실제 운영 정책과 보안 조치를 함께 검토해야 합니다.")

    chapter("부록 A. 전체 점검 결과", "appendix-results")
    story.append(paragraph("확정 취약점 외에 PASS·REVIEW·ERROR를 포함한 전체 검사 이력입니다. "
                           "동일 URL에서 서로 다른 스캐너 또는 판정 항목이 나올 수 있습니다.", "small"))
    def evidence_summary(row):
        value = re.sub(r"\s+", " ", str(row["evidence"])).strip()
        return value if len(value) <= 300 else value[:300] + "… (전체 근거는 상세 분석 또는 보관 JSON 참조)"
    story.append(table(["ID / 판정", "검사 항목", "대상 위치", "판정 근거"],
                       [(row["finding_id"] + "\n" + row["verdict"], row["name"] + "\n" + str(row["severity"]),
                         str(row["method"]) + " " + row["url"], evidence_summary(row))
                        for row in report["findings"]], [0.13, 0.24, 0.27, 0.36]))

    chapter("부록 B. 기준 문서 연결 및 점검 범위", "appendix-guide")
    story.append(paragraph(report["guide"]["document_title"] +
                           f" / PDF {report['guide']['start_page']}~{report['guide']['end_page']}페이지"))
    story.append(table(["항목 / 페이지", "기준 항목", "연결 범위"],
                       [(item["code"] + f"\nPDF {item['page']}", item["title"], item["status"])
                        for item in report["guide_coverage"]], [0.18, 0.35, 0.47]))
    block("출처 추적", f"스캔 JSON SHA-256: {report['source_hash']}\n기준 PDF SHA-256: {report['guide']['pdf_sha256']}")
    story.append(paragraph("페이지는 PDF 뷰어의 1부터 시작하는 번호입니다. "
                           "보고서에 연결되지 않은 기준은 양호로 판정하지 않습니다.", "small"))
    document.multiBuild(story)
    return buffer.getvalue()


def _write_text(path, content):
    """완성된 내용을 임시 파일에 기록한 후 교체한다."""
    temporary = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def generate_report(scan_path="output/scan-results.json", analysis_path="output/analysis.json",
                    guide_path=None, output_dir="output/reports", *, start_page=GUIDE_START_PAGE):
    """정식 PDF 보고서와 증적 보관용 JSON을 생성한다."""
    guide_path = guide_path or os.getenv("ROOKIESCAN_GUIDE_PDF") or "docs/reference/2026-guide.pdf"
    scan = json.loads(_project_path(scan_path).read_text(encoding="utf-8-sig"))
    analysis = json.loads(_project_path(analysis_path).read_text(encoding="utf-8-sig"))
    index = load_guide_index(guide_path, start_page=start_page)
    report = build_diagnostic_report(scan, analysis, index)
    output = _project_path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    stem = "rookiescan-report-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:8]
    paths = {extension: output / f"{stem}.{extension}" for extension in ("pdf", "json")}
    pdf = render_report_pdf(report)
    temporary = paths["pdf"].with_name(paths["pdf"].name + "." + uuid4().hex + ".tmp")
    try:
        temporary.write_bytes(pdf)
        temporary.replace(paths["pdf"])
    finally:
        temporary.unlink(missing_ok=True)
    _write_text(paths["json"], json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return paths


def run():
    """대시보드에서 호출 가능한 진입점. 보고서를 반환하고 다운로드 버튼을 제공한다."""
    import streamlit as st
    scan_path = st.session_state.get("scan_report_path") or "output/scan-results.json"
    analysis_path = st.session_state.get("analysis_report_path")
    if "analysis_report_path" in st.session_state and not analysis_path:
        raise ValueError("현재 스캔의 추가 분석 JSON이 준비되지 않았습니다.")
    paths = generate_report(scan_path, analysis_path or "output/analysis.json")
    path = paths["pdf"]
    st.download_button("PDF 보고서 다운로드", data=path.read_bytes(),
                       file_name=path.name, mime="application/pdf", key="report-pdf")
    return paths


def main():
    parser = argparse.ArgumentParser(description="ROOKIESCAN 문서 검색 기반 진단 보고서 생성 (추가 AI 호출 없음)")
    parser.add_argument("--scan", default="output/scan-results.json")
    parser.add_argument("--analysis", default="output/analysis.json")
    parser.add_argument("--guide", default=None)
    parser.add_argument("--start-page", type=int, default=GUIDE_START_PAGE)
    parser.add_argument("--output-dir", default="output/reports")
    arguments = parser.parse_args()
    try:
        paths = generate_report(arguments.scan, arguments.analysis, arguments.guide,
                                arguments.output_dir, start_page=arguments.start_page)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"보고서 생성 실패: {exc}\n")
    print(f"PDF: {paths['pdf']}")

if __name__ == "__main__":
    main()
