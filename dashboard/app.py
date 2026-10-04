import json
import importlib
import os
from collections import Counter
from html import escape
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any

import pandas as pd
import altair as alt
import streamlit as st
from openai import OpenAI

# 연동 파일 설정: 실제 파일명이 확정되면 아래 값만 변경하면 됩니다.
APP_DIR = Path(__file__).resolve().parent
SCANNER_RESULT_FILENAME = "demo_scan_result_varied.json"
ANALYSIS_RESULT_FILENAME = "analysis.json"
REPORT_MODULE_NAME = "report"
REPORT_FUNCTION_NAME = "run"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SENSITIVE_KEYS = {
    "session_cookie", "cookie", "cookies", "authorization", "token",
    "access_token", "refresh_token", "password", "passwd", "secret",
    "api_key", "apikey"
}


def load_scan_result(uploaded_file: Any) -> dict:
    if uploaded_file is None:
        raise ValueError("JSON 파일을 업로드해 주세요.")
    return json.load(uploaded_file)


def resolve_input_path(filename: str) -> Path:
    """상대 경로는 app.py가 있는 폴더를 기준으로 해석합니다."""
    configured_path = Path(filename)
    return configured_path if configured_path.is_absolute() else APP_DIR / configured_path


def load_configured_json(filename: str, required: bool = True) -> dict:
    """상단 설정에 지정된 JSON 파일을 UTF-8 형식으로 읽습니다."""
    file_path = resolve_input_path(filename)
    if not file_path.exists():
        if required:
            raise FileNotFoundError(f"설정된 JSON 파일을 찾을 수 없습니다: {file_path}")
        return {}
    with file_path.open(encoding="utf-8-sig") as json_file:
        return json.load(json_file)


def run_report_module() -> None:
    """설정된 보고서 모듈의 실행 함수를 호출합니다."""
    try:
        report_module = importlib.import_module(REPORT_MODULE_NAME)
        report_runner = getattr(report_module, REPORT_FUNCTION_NAME)
        report_runner()
    except ModuleNotFoundError as exc:
        if exc.name != REPORT_MODULE_NAME:
            st.error(f"보고서 모듈의 의존성을 불러오지 못했습니다: {exc.name}")
        else:
            st.warning(
                f"{REPORT_MODULE_NAME}.py가 아직 준비되지 않았습니다. "
                "파일을 app.py와 같은 폴더에 추가하면 보고서 기능이 연결됩니다."
            )
    except AttributeError:
        st.error(f"{REPORT_MODULE_NAME}.py에서 {REPORT_FUNCTION_NAME}() 함수를 찾을 수 없습니다.")
    except Exception as exc:
        st.error(f"보고서 생성 중 오류가 발생했습니다: {exc}")
    else:
        st.success("보고서 생성 모듈을 실행했습니다.")


def normalize_severity(value: Any) -> str:
    severity = str(value or "INFO").upper()
    return severity if severity in SEVERITY_ORDER else "INFO"


def flatten_findings(scan_data: dict) -> pd.DataFrame:
    rows: list[dict] = []

    for scan in scan_data.get("results", []):
        url = scan.get("url", "")
        method = scan.get("method", "")
        scanner = scan.get("scanner", "")
        status = scan.get("status", "completed")
        vulnerable = bool(scan.get("vulnerable", False))
        findings = scan.get("findings", []) or []

        if findings:
            for finding in findings:
                rows.append({
                    "url": url,
                    "method": method,
                    "scanner": scanner,
                    "status": status,
                    "vulnerable": vulnerable,
                    "type": finding.get("type", scanner),
                    "severity": normalize_severity(finding.get("severity")),
                    "parameter": finding.get("parameter", ""),
                    "payload": finding.get("payload", ""),
                    "evidence": finding.get("evidence", ""),
                    "description": finding.get("description", ""),
                    "recommendation": finding.get("recommendation", ""),
                    "verdict": finding.get("vuln") or ("VULNERABLE" if vulnerable else "REVIEW"),
                })
        else:
            rows.append({
                "url": url,
                "method": method,
                "scanner": scanner,
                "status": status,
                "vulnerable": vulnerable,
                "type": "",
                "severity": "INFO",
                "parameter": "",
                "payload": "",
                "evidence": "",
                "description": "",
                "recommendation": "",
            })

    return pd.DataFrame(rows)


def build_summary(scan_data: dict, findings_df: pd.DataFrame) -> dict:
    results = scan_data.get("results", [])
    endpoints = {(r.get("method", ""), r.get("url", "")) for r in results}
    vulnerable_scans = sum(bool(r.get("vulnerable", False)) for r in results)

    finding_rows = findings_df[findings_df["type"] != ""] if not findings_df.empty else findings_df
    severity_counts = Counter(finding_rows["severity"].tolist()) if not finding_rows.empty else Counter()

    return {
        "total_endpoints": len(endpoints),
        "total_scans": len(results),
        "vulnerable_scans": vulnerable_scans,
        "total_findings": len(finding_rows),
        "severity_counts": {severity: severity_counts.get(severity, 0) for severity in SEVERITY_ORDER},
    }


def redact_sensitive_data(value: Any) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if key.lower() in SENSITIVE_KEYS:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_sensitive_data(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    return value


def build_ai_payload(scan_data: dict) -> dict:
    safe_data = redact_sensitive_data(scan_data)
    return {
        "summary": safe_data.get("summary", {}),
        "results": safe_data.get("results", []),
    }


def analyze_with_ai(scan_data: dict, model: str, question: str = "") -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY 환경변수가 설정되어 있지 않습니다.")

    client = OpenAI(api_key=api_key)
    safe_payload = build_ai_payload(scan_data)

    instructions = (
        "당신은 웹 애플리케이션 보안 진단 결과를 분석하는 보안 분석가다. "
        "제공된 JSON 결과만 근거로 분석하고, 확인되지 않은 사실은 단정하지 않는다. "
        "한국어로 간결하게 답변한다. 다음 항목을 포함한다: "
        "1) 전체 위험 요약, 2) 우선 조치할 취약점, 3) 근거가 되는 엔드포인트/파라미터/증거, "
        "4) 권장 조치, 5) 오탐 가능성 또는 추가 확인 사항. "
        "세션 쿠키, 토큰, 비밀번호 같은 민감정보는 출력하지 않는다."
    )

    user_input = (
        "다음은 통합 취약점 스캐너 결과 JSON이다.\n\n"
        f"{json.dumps(safe_payload, ensure_ascii=False, indent=2)}"
    )
    if question.strip():
        user_input += f"\n\n추가 질문: {question.strip()}"

    response = client.responses.create(
        model=model,
        instructions=instructions,
        input=user_input,
    )
    return response.output_text


def render_metrics(summary: dict) -> None:
    cols = st.columns(5)
    cols[0].metric("엔드포인트", summary["total_endpoints"])
    cols[1].metric("스캐너 실행", summary["total_scans"])
    cols[2].metric("취약 판정", summary["vulnerable_scans"])
    cols[3].metric("총 Findings", summary["total_findings"])
    cols[4].metric("Critical + High", summary["severity_counts"]["CRITICAL"] + summary["severity_counts"]["HIGH"])


def get_check_rows(scan_data: dict) -> pd.DataFrame:
    # 최신 JSON의 전체 점검 목록을 사용하여 양호 항목도 집계합니다.
    rows = []
    if isinstance(scan_data.get("findings"), list) and scan_data["findings"]:
        for finding in scan_data["findings"]:
            details = finding.get("details") or {}
            parameters = finding.get("parameters") or []
            parameter_names = ", ".join(item.get("name", "") if isinstance(item, dict) else str(item) for item in parameters)
            raw_result = details.get("raw_result") or {}
            payload = raw_result.get("payload", "") if isinstance(raw_result, dict) else ""
            rows.append({"유형": finding.get("name", "미지정"), "판정": finding.get("vuln", "REVIEW"),
                         "위험도": normalize_severity(finding.get("severity")), "스캐너": finding.get("scanner_id", ""),
                         "위치": finding.get("url", ""), "메서드": finding.get("method", ""),
                         "파라미터": parameter_names, "근거": finding.get("result", ""),
                         "설명": finding.get("description") or finding.get("result", ""),
                         "대응방안": details.get("remediation", ""), "페이로드": payload})
    else:
        for scan in scan_data.get("results", []):
            for finding in scan.get("findings") or [{}]:
                verdict = finding.get("vuln") or ("VULNERABLE" if scan.get("vulnerable") else "REVIEW")
                rows.append({"유형": finding.get("type") or scan.get("scanner", "미지정"), "판정": verdict,
                             "위험도": normalize_severity(finding.get("severity")), "스캐너": scan.get("scanner", ""),
                             "위치": scan.get("url", ""), "메서드": scan.get("method", ""),
                             "파라미터": finding.get("parameter", ""), "근거": finding.get("evidence", ""),
                             "설명": finding.get("description", ""), "대응방안": finding.get("recommendation", ""),
                             "페이로드": finding.get("payload", "")})
    return pd.DataFrame(rows, columns=["유형", "판정", "위험도", "스캐너", "위치", "메서드", "파라미터", "근거", "설명", "대응방안", "페이로드"])


def render_overview(scan_data: dict) -> None:
    checks = get_check_rows(redact_sensitive_data(scan_data))
    vulnerable = checks[checks["판정"] == "VULNERABLE"]
    safe_count = int((checks["판정"] == "PASS").sum())
    review_count = int((checks["판정"] == "REVIEW").sum())
    error_count = int((checks["판정"] == "ERROR").sum())
    counts = [len(checks), len(vulnerable), safe_count, review_count, error_count]
    labels = [
        ("전체 점검", "전체 실행 범위", "blue"),
        ("취약점 확인", "취약점 증거 확인", "red"),
        ("정상 처리", "정상 차단 또는 미탐지", "green"),
        ("수동 검토", "사람 확인 필요", "gray"),
        ("실행 오류", "설정·통신·실행 오류", "orange"),
    ]
    for column, count, (label, subtitle, color) in zip(st.columns(5), counts, labels):
        with column:
            st.html(f'<div class="scan-stat {color}"><div>{label}</div><strong>{count}<small>건</small></strong><footer>{subtitle}</footer></div>')
    chart_left, chart_right = st.columns([1.45, 1], gap="medium")
    with chart_left.container(border=True, key="overview_types"):
        st.markdown("#### 유형별 취약점")
        st.caption("취약(VULNERABLE)으로 판정된 점검 수")
        if vulnerable.empty:
            st.info("취약 판정이 없습니다.")
        else:
            chart_data = vulnerable.groupby("유형").size().reset_index(name="건수")
            chart = alt.Chart(chart_data).mark_bar(color="#3d80b8", cornerRadiusTopLeft=5, cornerRadiusTopRight=5, size=42).encode(
                x=alt.X("유형:N", title=None, axis=alt.Axis(labelAngle=0, labelLimit=150)),
                y=alt.Y("건수:Q", title=None, axis=alt.Axis(tickMinStep=1)), tooltip=["유형", "건수"])
            st.altair_chart(chart.properties(height=220).configure_view(stroke=None).configure_axis(
                gridColor="#edf1f5", domainColor="#e1e7ee", labelColor="#6b8198"), width="stretch")
    with chart_right.container(border=True, key="overview_severity"):
        st.markdown("#### 위험도 분포")
        st.caption("전체 점검 기준 · 양호 / 추가 검토 포함")
        if checks.empty:
            st.info("집계할 점검 결과가 없습니다.")
        else:
            distribution = checks.groupby("위험도").size().reset_index(name="건수")
            chart = alt.Chart(distribution).mark_arc(innerRadius=65, outerRadius=94, stroke="white", strokeWidth=3).encode(
                theta=alt.Theta("건수:Q"), color=alt.Color("위험도:N", title=None,
                    scale=alt.Scale(domain=SEVERITY_ORDER, range=["#94324d", "#ca4353", "#eda94a", "#508fcc", "#bdcad6"]),
                    legend=alt.Legend(orient="right", labelColor="#26445e", symbolType="square")),
                tooltip=["위험도", "건수"])
            st.altair_chart(chart.properties(height=220).configure_view(stroke=None), width="stretch")


def render_critical_alert(scan_data: dict) -> None:
    """취약 판정 중 CRITICAL 항목이 있을 때만 상단 경고를 표시합니다."""
    checks = get_check_rows(redact_sensitive_data(scan_data))
    if checks.empty:
        return

    critical_count = int(
        ((checks["판정"] == "VULNERABLE") & (checks["위험도"] == "CRITICAL")).sum()
    )
    if critical_count == 0:
        return

    critical_rows = checks[
        (checks["판정"] == "VULNERABLE") & (checks["위험도"] == "CRITICAL")
    ]
    alert_signature = "|".join(
        sorted(f"{row['유형']}:{row['위치']}" for _, row in critical_rows.iterrows())
    )
    if st.session_state.get("dismissed_critical_alert") == alert_signature:
        return

    with st.container(key="critical_alert_banner"):
        st.html(
            '<div class="critical-alert-body" role="alert">'
            '<div class="critical-alert-icon">!</div>'
            '<div class="critical-alert-copy">'
            f'<strong>CRITICAL 취약점 {critical_count}건이 발견되었습니다.</strong>'
            '<span>즉시 확인하고 우선 조치가 필요한 항목입니다.</span>'
            '</div>'
            '<div class="critical-alert-guide">Findings에서 확인</div>'
            '</div>'
        )
        if st.button(
            "닫기",
            icon=":material/close:",
            help="경고 닫기",
            key="dismiss_critical_alert",
        ):
            st.session_state["dismissed_critical_alert"] = alert_signature
            st.rerun()


def render_severity_chart(summary: dict) -> None:
    chart_df = pd.DataFrame({
        "severity": SEVERITY_ORDER,
        "count": [summary["severity_counts"][s] for s in SEVERITY_ORDER],
    }).set_index("severity")
    st.bar_chart(chart_df)


def render_findings_table(scan_data: dict) -> None:
    checks = get_check_rows(redact_sensitive_data(scan_data))
    if checks.empty:
        st.info("표시할 결과가 없습니다.")
        return
    status_labels = {"취약점 확인": "VULNERABLE", "정상 처리": "PASS", "수동 검토": "REVIEW", "실행 오류": "ERROR"}
    scanner_options = sorted(item for item in checks["스캐너"].dropna().unique().tolist() if item)
    type_options = sorted(item for item in checks["유형"].dropna().unique().tolist() if item)

    # 필터를 한 줄짜리 도구 모음으로 구성해 결과 표에 시선이 바로 이어지게 합니다.
    with st.container(key="findings_filter_bar"):
        status_column, spacer_column, detail_column = st.columns(
            [3, 4, 1.25],
            vertical_alignment="center",
        )
        with status_column:
            selected_statuses = st.multiselect(
                "판정",
                list(status_labels),
                default=[],
                key="findings_status",
                label_visibility="collapsed",
                placeholder="전체 판정",
            )
        with detail_column:
            with st.popover("필터", icon=":material/tune:", width="stretch"):
                st.caption("선택하지 않은 항목은 전체 범위로 적용됩니다.")
                severity_filter = st.multiselect(
                    "위험도",
                    SEVERITY_ORDER,
                    default=[],
                    placeholder="전체 위험도",
                    key="findings_severity",
                )
                scanner_filter = st.multiselect(
                    "스캐너",
                    scanner_options,
                    default=[],
                    placeholder="전체 스캐너",
                    key="findings_scanner",
                )
                type_filter = st.multiselect(
                    "취약점 유형",
                    type_options,
                    default=[],
                    placeholder="전체 유형",
                    key="findings_type",
                )

    filtered = checks.copy()
    if severity_filter:
        filtered = filtered[filtered["위험도"].isin(severity_filter)]
    if type_filter:
        filtered = filtered[filtered["유형"].isin(type_filter)]
    if scanner_filter:
        filtered = filtered[filtered["스캐너"].isin(scanner_filter)]
    if selected_statuses:
        selected_verdicts = [status_labels[status] for status in selected_statuses]
        filtered = filtered[filtered["판정"].isin(selected_verdicts)]

    verdict_korean = {"VULNERABLE": "취약점 확인", "PASS": "정상 처리", "REVIEW": "수동 검토", "ERROR": "실행 오류"}
    display_df = filtered[["판정", "위험도", "유형", "스캐너", "메서드", "위치", "파라미터"]].copy()
    display_df["판정"] = display_df["판정"].map(verdict_korean).fillna(display_df["판정"])

    table_event = st.dataframe(
        display_df,
        width="stretch",
        hide_index=True,
        height=380,
        row_height=44,
        on_select="rerun",
        selection_mode="single-row",
        key="findings_table",
    )
    st.caption(f"행을 선택하면 아래 상세 항목이 바뀝니다. · {len(filtered)}개 표시 / 전체 {len(checks)}개 점검")

    if filtered.empty:
        st.info("선택한 조건에 해당하는 결과가 없습니다.")
        return

    detail_rows = filtered.reset_index(drop=True)
    selected_table_rows = table_event.selection.rows
    if selected_table_rows:
        # 표의 선택 행과 아래 상세 선택기를 같은 인덱스로 맞춥니다.
        st.session_state["finding_detail_selection"] = selected_table_rows[0]
    elif st.session_state.get("finding_detail_selection", 0) >= len(detail_rows):
        # 필터 변경으로 결과 수가 줄어든 경우 유효한 첫 항목으로 되돌립니다.
        st.session_state["finding_detail_selection"] = 0

    selected_index = st.selectbox(
        "상세 항목 선택", range(len(detail_rows)),
        format_func=lambda index: f"[{detail_rows.iloc[index]['위험도']}] {detail_rows.iloc[index]['유형']} · {detail_rows.iloc[index]['메서드']} {detail_rows.iloc[index]['위치']}",
        key="finding_detail_selection",
    )
    row = detail_rows.iloc[selected_index]
    with st.container(border=True, key="finding_detail"):
        detail_left, detail_right = st.columns(2)
        with detail_left:
            st.caption("점검 위치")
            st.code(f"{row['메서드']} {row['위치']}", language=None, wrap_lines=True)
            st.write(f"**스캐너:** {row['스캐너'] or '-'}")
            st.write(f"**파라미터:** {row['파라미터'] or '-'}")
        with detail_right:
            st.caption("판정 정보")
            st.write(f"**판정:** {verdict_korean.get(row['판정'], row['판정'])}")
            st.write(f"**위험도:** {row['위험도']}")
            st.write(f"**설명:** {row['설명'] or '-'}")
        if row["근거"]:
            st.caption("증거")
            st.code(str(row["근거"]), language="text", wrap_lines=True)
        if row["페이로드"]:
            st.caption("Payload")
            st.code(str(row["페이로드"]), language="text", wrap_lines=True)
        st.caption("대응방안")
        st.write(row["대응방안"] or "추가 검토 후 적절한 보안 통제를 적용하세요.")


def get_dummy_context(scan_data: dict) -> tuple[dict, pd.DataFrame, dict]:
    # 화면과 다운로드에 동일한 마스킹된 데이터를 사용합니다.
    safe_data = redact_sensitive_data(scan_data)
    findings_df = flatten_findings(safe_data)
    summary = build_summary(safe_data, findings_df)
    if not findings_df.empty:
        findings_df = findings_df[findings_df["type"] != ""].copy()
        findings_df["priority"] = findings_df["severity"].map(SEVERITY_ORDER.index)
        findings_df = findings_df.sort_values("priority", kind="stable")
    return safe_data, findings_df, summary


def get_confirmed_findings(findings: pd.DataFrame) -> pd.DataFrame:
    # 검토 필요 항목을 취약 판정과 분리합니다.
    if findings.empty:
        return findings
    return findings[findings["verdict"] == "VULNERABLE"]


def render_finding_card(row: dict, number: int) -> None:
    # 긴 원문은 접고, 위치와 핵심 대응을 먼저 보여 줍니다.
    with st.container(border=True):
        st.caption(f"FINDING {number:02d}")
        st.badge(row["severity"], color="red" if row["severity"] in ["CRITICAL", "HIGH"] else "orange")
        st.markdown("#### " + row["type"])
        st.code(f"{row['method']} {urlsplit(row['url']).path or '/'}", language=None, wrap_lines=True)
        st.caption("권장 조치")
        guidance = {
            "directory_indexing": "디렉터리 목록 비활성화 · 공개 파일 범위 제한",
            "admin_exposure": "관리자 경로 접근 제한 · 인증 및 권한 검사",
        }
        st.write(guidance.get(row["scanner"], "입력 검증 · 접근 통제 보완 · 재점검"))
        with st.expander("근거 및 상세 보기"):
            st.text(f"URL: {row['url']}")
            st.text(f"파라미터: {row['parameter'] or '경로 기반 점검'}")
            st.text(row["evidence"] or "근거 미제공")
            st.text(row["description"] or "설명 미제공")
            st.text(row["recommendation"] or "대응방안 미제공")


def render_analysis_dummy(scan_data: dict) -> None:
    # 여기에 실제 AI 호출 연결: 요약 데이터와 카드 내용을 교체합니다.
    _, findings, summary = get_dummy_context(scan_data)
    confirmed = get_confirmed_findings(findings)
    review_count = int((findings["verdict"] == "REVIEW").sum()) if not findings.empty else 0
    st.subheader("보안 상태 한눈에 보기")
    for column, label, value in zip(st.columns(4), ["취약 판정", "추가 검토", "점검 엔드포인트", "스캐너 실행"],
                                    [len(confirmed), review_count, summary["total_endpoints"], summary["total_scans"]]):
        with column:
            st.metric(label, value, border=True)
    st.caption("원본 results 기준 · 취약 판정과 검토 필요 항목을 구분합니다.")
    with st.container(border=True):
        st.markdown("**취약 판정 위험도 분포**")
        counts = Counter(confirmed["severity"]) if not confirmed.empty else Counter()
        for column, severity in zip(st.columns(5), SEVERITY_ORDER):
            column.metric(severity, counts.get(severity, 0))
    st.subheader("먼저 조치할 항목")
    if confirmed.empty:
        st.info("원본에서 취약으로 판정한 항목이 없습니다.")
        return
    for number, (column, row) in enumerate(zip(st.columns(min(3, len(confirmed))), confirmed.head(3).to_dict("records")), 1):
        with column:
            render_finding_card(row, number)
    if review_count:
        with st.expander(f"추가 검토 {review_count}건 · 인증 문제 등으로 확인 필요"):
            st.dataframe(findings[findings["verdict"] == "REVIEW"][["type", "method", "url", "evidence"]], hide_index=True, width="stretch")


def render_report_dummy(scan_data: dict) -> None:
    # 여기에 실제 AI 호출 연결: 문서 본문과 요약을 교체합니다.
    safe_data, findings, summary = get_dummy_context(scan_data)
    confirmed = get_confirmed_findings(findings)
    st.subheader("취약점 진단 보고서")
    st.caption("REPORT PREVIEW · 원본 판정 기반 / 해설은 더미")
    overview = [
        ("대상", safe_data.get("target") or safe_data.get("target_url") or "업로드 엔드포인트"),
        ("진단 일시", safe_data.get("generated_at") or safe_data.get("scan_time") or "미제공"),
        ("점검 범위", f"{summary['total_endpoints']}개 엔드포인트 · {summary['total_scans']}회 실행"),
        ("취약 판정", f"{len(confirmed)}건"),
    ]
    with st.container(border=True):
        for columns, pairs in [(st.columns(2), overview[:2]), (st.columns(2), overview[2:])]:
            for column, (label, value) in zip(columns, pairs):
                column.caption(label)
                column.text(value)
    report_lines = ["[더미 보고서 · 실제 AI 분석 아님]", "시연용 입력의 판정은 가상입니다." if safe_data.get("is_demo") else "원본 스캔 판정을 기준으로 작성했습니다."]
    report_lines.extend(f"{label}: {value}" for label, value in overview)
    st.markdown("### 취약점 상세")
    if confirmed.empty:
        st.info("취약 판정 항목이 없습니다.")
    for number, row in enumerate(confirmed.to_dict("records"), 1):
        with st.expander(f"{number:02d} · {row['severity']} · {row['type']} · {urlsplit(row['url']).path}", expanded=False):
            left, right = st.columns(2)
            with left:
                st.caption("위치 · 근거")
                st.code(f"{row['method']} {row['url']}", language=None, wrap_lines=True)
                st.text(row["evidence"] or "미제공")
            with right:
                st.caption("설명 · 대응방안")
                st.text(row["description"] or "미제공")
                st.text(row["recommendation"] or "미제공")
        report_lines.extend(["", f"{number}. {row['type']} [{row['severity']}]", f"{row['method']} {row['url']}",
                             f"파라미터: {row['parameter'] or '경로 기반'}", str(row["description"] or ""),
                             str(row["evidence"] or ""), str(row["recommendation"] or "")])
    st.markdown("### 조치 계획 · 예시")
    for column, title, detail in zip(st.columns(3), ["01 · 노출 차단", "02 · 통제 보완", "03 · 재점검"],
                                    ["공개 경로와 파일 범위 확인", "인증 및 권한 검사 적용", "동일 엔드포인트 재검증"]):
        with column.container(border=True):
            st.markdown(f"**{title}**")
            st.caption(detail)
            report_lines.append(f"{title}: {detail}")
    st.download_button("보고서 다운로드", "\n".join(report_lines).encode("utf-8-sig"),
                       file_name="scan_report_preview.txt", mime="text/plain", key="dummy_report_download", type="primary")


def render_compliance_dummy(scan_data: dict) -> None:
    # 여기에 실제 AI 호출 연결: 검증된 기준 매핑으로 교체합니다.
    _, findings, _ = get_dummy_context(scan_data)
    confirmed = get_confirmed_findings(findings)
    st.subheader("기준별 보완 현황")
    st.caption("예시 매핑 · 정식 조항 및 법적 준수 판정이 아닙니다.")
    if confirmed.empty:
        st.info("매핑할 취약 판정 항목이 없습니다.")
        return
    mapping = {
        "directory_indexing": ("디렉터리 인덱싱", "공개 자원 접근 통제"),
        "admin_exposure": ("관리자 페이지 노출", "관리자 접근 통제"),
        "sqli": ("SQL 삽입", "안전한 개발 / 입력 검증"),
        "xss": ("크로스사이트 스크립팅", "안전한 개발 / 출력 처리"),
        "authz": ("접근 통제", "접근 권한 관리"),
        "fileio": ("파일 접근 제한", "파일 및 자원 접근 통제"),
        "ssrf": ("서버 요청 검증", "네트워크 접근 통제"),
    }
    cols = st.columns(3)
    cols[0].metric("매핑 대상", len(confirmed), border=True)
    cols[1].metric("취약점 유형", confirmed["type"].nunique(), border=True)
    cols[2].metric("판정 상태", "검토 필요", border=True)
    rows = []
    for row in confirmed.to_dict("records"):
        technical, control = mapping.get(row["scanner"], ("기술적 취약점 점검", "보안 취약점 관리"))
        rows.append({"유형": row["type"], "위험도": row["severity"], "기술적 점검 기준 (예시)": technical,
                     "ISMS-P 영역 (예시)": control, "준수 여부": "보완 필요 (가상)", "위치": urlsplit(row["url"]).path})
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", row_height=52)
    st.caption("기술적 점검 기준: 주요정보통신기반시설 취약점 점검 영역을 참고한 UI 예시")
    with st.expander("조치 증적 체크리스트"):
        st.write("① 설정 변경 이력  ② 접근 통제 정책  ③ 재점검 결과  ④ 담당자 승인 기록")


def render_attack_scenario_dummy(scan_data: dict) -> None:
    # 여기에 실제 AI 호출 연결: 단계별 근거와 가정을 분리한 결과로 교체합니다.
    _, findings, _ = get_dummy_context(scan_data)
    confirmed = get_confirmed_findings(findings)
    st.subheader("Attack Scenario Preview")
    st.caption("가상의 연계 시나리오 · 공격을 실행하지 않으며, 단계 간 연결은 추가 가정입니다.")
    available = {row["scanner"]: row for row in reversed(confirmed.to_dict("records"))}
    scenarios = [
        ("공개 파일에서 관리자 경로로", ["directory_indexing", "admin_exposure"],
         ["파일 목록 노출", "관리자 경로 탐색"],
         ["공개 목록에서 운영 관련 파일명을 파악한다고 가정합니다.", "파일 정보가 관리자 경로 탐색에 도움을 준다고 가정합니다. 관리자 인증 우회는 확인되지 않았습니다."]),
        ("입력 결함에서 타인 정보로", ["sqli", "authz"], ["식별자 노출", "권한 경계 침범"],
         ["입력 처리 결함으로 리소스 식별자가 노출된다고 가정합니다.", "소유권 검사가 누락되어 타인 정보에 접근한다고 가정합니다."]),
        ("브라우저에서 내부 서비스로", ["xss", "ssrf"], ["브라우저 요청 유도", "내부 서비스 접근"],
         ["피해자가 입력 내용을 열람한다고 가정합니다.", "해당 사용자의 URL 요청 기능이 내부 목적지에 접근 가능하다고 가정합니다."]),
    ]
    shown = 0
    for title, scanners, labels, descriptions in scenarios:
        if not all(scanner in available for scanner in scanners):
            continue
        shown += 1
        st.markdown(f"### {shown:02d} · {title}")
        st.caption(" → ".join(labels))
        for step, (column, scanner, label, description) in enumerate(zip(st.columns(2), scanners, labels, descriptions), 1):
            row = available[scanner]
            with column.container(border=True):
                st.badge(f"STEP {step:02d}", color="blue")
                st.markdown(f"#### {label}")
                st.caption(row["type"])
                st.code(f"{row['method']} {urlsplit(row['url']).path}", language=None, wrap_lines=True)
                st.write(description)
                with st.expander("근거와 차단 조치"):
                    st.text(row["url"])
                    st.text(row["evidence"] or "미제공")
                    st.text(row["recommendation"] or "접근 통제 재점검")
    if not shown:
        st.info("확인된 유형 조합으로 구성할 연계 시나리오가 없습니다.")


def render_top_bar() -> None:
    """대시보드 전역 브랜드 상단바를 표시합니다."""
    st.html(
        """
        <style>
            [data-testid="stHeader"] {
                background: transparent;
            }
            [data-testid="stMainBlockContainer"] {
                padding-top: 0;
            }
            .rookiscan-topbar {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 1.5rem;
                position: relative;
                left: 50%;
                width: calc(100% + 12rem);
                margin: 0 0 2.25rem 0;
                padding: 0.85rem max(3.5rem, calc((100vw - 1450px) / 2));
                transform: translateX(-50%);
                box-sizing: border-box;
                background: #102b40;
                box-shadow: 0 1px 0 rgba(15, 23, 42, 0.16);
                color: #f8fafc;
            }
            .rookiscan-brand {
                display: flex;
                align-items: center;
                gap: 0.75rem;
                min-width: 0;
            }
            .rookiscan-mark {
                display: grid;
                place-items: center;
                width: 2.25rem;
                height: 2.25rem;
                flex: 0 0 2.25rem;
                border-radius: 9px;
                background: #62d8c8;
                color: #102b40;
                font-size: 1.15rem;
                font-weight: 900;
            }
            .rookiscan-name {
                margin: 0;
                color: #ffffff;
                font-size: 1.28rem;
                font-weight: 800;
                line-height: 1.1;
                letter-spacing: 0.06em;
            }
            .rookiscan-subtitle {
                margin: 0 0 0 0.85rem;
                padding-left: 0.85rem;
                border-left: 1px solid rgba(226, 232, 240, 0.42);
                color: #d3e1ec;
                font-size: 0.76rem;
                font-weight: 650;
            }
            .rookiscan-status {
                display: inline-flex;
                align-items: center;
                gap: 0.45rem;
                flex: 0 0 auto;
                padding: 0.4rem 0.72rem;
                border: 1px solid rgba(186, 230, 253, 0.28);
                border-radius: 999px;
                background: rgba(8, 26, 40, 0.45);
                color: #eef7fb;
                font-size: 0.7rem;
                font-weight: 650;
            }
            .rookiscan-status-dot {
                width: 0.48rem;
                height: 0.48rem;
                border-radius: 50%;
                background: #52dfca;
            }
            @media (max-width: 640px) {
                .rookiscan-topbar { width: calc(100% + 2rem); padding: 0.8rem 1rem; }
                .rookiscan-subtitle { display: none; }
                .rookiscan-status { padding: 0.4rem 0.55rem; }
                .rookiscan-status-label { display: none; }
            }
        </style>
        <header class="rookiscan-topbar">
            <div class="rookiscan-brand">
                <div class="rookiscan-mark" aria-hidden="true">R</div>
                <h1 class="rookiscan-name">ROOKIESCAN</h1>
                <p class="rookiscan-subtitle">취약점 통합 스캐너</p>
            </div>
            <div class="rookiscan-status">
                <span class="rookiscan-status-dot"></span>
                <span class="rookiscan-status-label">LOCAL DASHBOARD</span>
            </div>
        </header>
        """
    )


def build_scan_report(scan_data: dict) -> bytes:
    """현재 스캔 결과로 다운로드 가능한 간단한 보고서를 만듭니다."""
    safe_data, findings, summary = get_dummy_context(scan_data)
    confirmed = get_confirmed_findings(findings)
    target = safe_data.get("target") or safe_data.get("target_url") or "미제공"
    lines = [
        "ROOKIESCAN 취약점 진단 보고서",
        "=" * 40,
        f"대상: {target}",
        f"진단 일시: {safe_data.get('generated_at') or safe_data.get('scan_time') or '미제공'}",
        f"점검 엔드포인트: {summary['total_endpoints']}개",
        f"스캐너 실행: {summary['total_scans']}회",
        f"취약 판정: {len(confirmed)}건",
        "",
        "취약점 상세",
        "-" * 40,
    ]
    if confirmed.empty:
        lines.append("취약 판정 항목이 없습니다.")
    for number, row in enumerate(confirmed.to_dict("records"), 1):
        lines.extend([
            f"[{number}] {row['type']} ({row['severity']})",
            f"위치: {row['method']} {row['url']}",
            f"파라미터: {row['parameter'] or '경로 기반 점검'}",
            f"근거: {row['evidence'] or '미제공'}",
            f"대응방안: {row['recommendation'] or '미제공'}",
            "",
        ])
    if safe_data.get("is_demo"):
        lines.extend(["※ 이 파일은 UI 시연용 가짜 데이터를 기반으로 생성되었습니다."])
    return "\n".join(lines).encode("utf-8-sig")


def main() -> None:
    st.set_page_config(
        page_title="ROOKIESCAN",
        page_icon=":material/security:",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    render_top_bar()
    st.html(Path(__file__).with_name("dashboard.css"))

    with st.sidebar:
        st.html(
            '<div class="sidebar-heading">스캔 데이터</div>'
            '<p class="sidebar-description">JSON 결과를 불러와 보안 현황과 보고서를 확인하세요.</p>'
        )
        st.html('<div class="sidebar-section-label">DATA SOURCE</div>')
        uploaded_file = st.file_uploader("통합 결과 JSON", type=["json"], label_visibility="collapsed")
        uploaded_analysis_file = st.file_uploader(
            "분석 결과 JSON",
            type=["json"],
            help="업로드하지 않으면 상단의 ANALYSIS_RESULT_FILENAME에 지정된 파일을 사용합니다.",
        )
        with st.expander("AI 분석 설정", icon=":material/tune:"):
            model = st.text_input("OpenAI model", value=os.getenv("OPENAI_MODEL", "gpt-6-luna"))
            st.caption("현재 더미 모드에서는 API 키와 모델 설정을 사용하지 않습니다.")

    try:
        # 업로드 파일이 있으면 우선 사용하고, 없으면 상단에 지정된 파일을 자동으로 읽습니다.
        scan_data = load_scan_result(uploaded_file) if uploaded_file else load_configured_json(SCANNER_RESULT_FILENAME)
        _analysis_data = (
            load_scan_result(uploaded_analysis_file)
            if uploaded_analysis_file
            else load_configured_json(ANALYSIS_RESULT_FILENAME, required=False)
        )
        findings_df = flatten_findings(scan_data)
        summary = build_summary(scan_data, findings_df)
    except Exception as exc:
        st.error(f"JSON 처리 오류: {exc}")
        return

    with st.sidebar:
        source_name = uploaded_file.name if uploaded_file is not None else SCANNER_RESULT_FILENAME
        target_name = scan_data.get("target") or scan_data.get("target_url") or "대상 미제공"
        st.html(
            '<div class="sidebar-source-card">'
            '<div class="sidebar-source-icon">✓</div>'
            '<div><strong>데이터 준비 완료</strong>'
            f'<span>{escape(source_name)}</span><small>{escape(str(target_name))}</small></div>'
            '</div>'
        )
    heading_column, action_column = st.columns([4, 1], vertical_alignment="center")
    with heading_column:
        st.html('<div class="page-eyebrow">SECURITY OVERVIEW</div><div class="page-heading">취약점 진단 결과</div>')
    with action_column:
        with st.container(horizontal=True, horizontal_alignment="right"):
            report_requested = st.button(
                "보고서 생성",
                type="primary",
                icon=":material/description:",
                width="content",
                key="header_report",
            )
            if report_requested:
                run_report_module()

    render_critical_alert(scan_data)

    tab_overview, tab_findings, tab_attack = st.tabs([
        "Overview", "Findings", "Attack Scenario"
    ])

    with tab_overview:
        render_overview(scan_data)

    with tab_findings:
        with st.container(border=True):
            st.subheader("상세 진단 결과")
            st.caption("전체 점검 판정을 필터링하고 선택한 항목의 근거와 대응방안을 확인하세요.")
            render_findings_table(scan_data)

    with tab_attack:
        render_attack_scenario_dummy(scan_data)


if __name__ == "__main__":
    main()
