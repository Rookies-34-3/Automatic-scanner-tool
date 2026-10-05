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
SCANNER_RESULT_FILENAME = "output/scan-results.json"
ANALYSIS_RESULT_FILENAME = "output/analysis.json"
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
            if isinstance(raw_result, dict):
                payload = raw_result.get("payload", "")
            elif isinstance(raw_result, list) and raw_result and isinstance(raw_result[0], dict):
                payload = raw_result[0].get("payload", "")
            else:
                payload = details.get("payload", "")
            rows.append({"유형": finding.get("name", "미지정"), "판정": finding.get("vuln", "REVIEW"),
                         "위험도": normalize_severity(finding.get("severity")), "스캐너": finding.get("scanner_id", ""),
                         "위치": finding.get("url", ""), "메서드": finding.get("method", ""),
                         "파라미터": parameter_names, "근거": finding.get("result", ""),
                         "설명": finding.get("description", ""),
                         "대응방안": details.get("remediation", ""), "페이로드": payload,
                         "상세정보": details})
    else:
        for scan in scan_data.get("results", []):
            for finding in scan.get("findings") or [{}]:
                verdict = finding.get("vuln") or ("VULNERABLE" if scan.get("vulnerable") else "REVIEW")
                rows.append({"유형": finding.get("type") or scan.get("scanner", "미지정"), "판정": verdict,
                             "위험도": normalize_severity(finding.get("severity")), "스캐너": scan.get("scanner", ""),
                             "위치": scan.get("url", ""), "메서드": scan.get("method", ""),
                             "파라미터": finding.get("parameter", ""), "근거": finding.get("evidence", ""),
                             "설명": finding.get("description", ""), "대응방안": finding.get("recommendation", ""),
                             "페이로드": finding.get("payload", ""), "상세정보": finding.get("details") or {}})
    return pd.DataFrame(rows, columns=["유형", "판정", "위험도", "스캐너", "위치", "메서드", "파라미터", "근거", "설명", "대응방안", "페이로드", "상세정보"])


def get_analysis_section(analysis_data: dict) -> dict:
    """분석 JSON에서 대시보드가 사용하는 analysis 영역만 반환합니다."""
    analysis = analysis_data.get("analysis", {}) if isinstance(analysis_data, dict) else {}
    return analysis if isinstance(analysis, dict) else {}


def render_overall_assessment(analysis_data: dict) -> None:
    """분석 JSON의 전체 평가를 Overview 하단에 표시합니다."""
    analysis = get_analysis_section(analysis_data)
    assessment = str(analysis.get("overall_assessment") or "").strip()
    if not assessment:
        return

    risk = str(analysis.get("overall_risk") or "미지정").upper()
    risk_class = risk.lower() if risk in SEVERITY_ORDER else "unknown"
    st.html(
        '<section class="overall-assessment">'
        '<div class="overall-assessment-heading">'
        '<div><h3>종합 위험 평가</h3></div>'
        f'<strong class="assessment-risk {escape(risk_class)}">{escape(risk)}</strong>'
        '</div>'
        f'<p>{escape(assessment)}</p>'
        '</section>'
    )


def render_overview(scan_data: dict, analysis_data: dict) -> None:
    checks = get_check_rows(redact_sensitive_data(scan_data))
    vulnerable = checks[checks["판정"] == "VULNERABLE"]
    source_summary = scan_data.get("summary") or {}
    unique_endpoints = checks[["메서드", "위치"]].drop_duplicates().shape[0]
    cards = [
        ("점검 엔드포인트", source_summary.get("total_endpoints", unique_endpoints),
         "점검 대상으로 수집된 고유 엔드포인트 수", "blue"),
        ("전체 점검 횟수", source_summary.get("total_findings", len(checks)),
         "스캐너가 처리한 총 점검 횟수", "navy"),
        ("취약 판정", source_summary.get("vulnerable", int((checks["판정"] == "VULNERABLE").sum())),
         "응답에서 취약점 증거가 확인됨", "red"),
        ("양호 판정", source_summary.get("pass", int((checks["판정"] == "PASS").sum())),
         "공격이 차단되었거나 취약점이 탐지되지 않음", "green"),
        ("검토 필요", source_summary.get("review", int((checks["판정"] == "REVIEW").sum())),
         "취약 여부 판정에 증거가 불충분하여 직접 확인 필요", "gray"),
    ]
    for column, (label, count, subtitle, color) in zip(st.columns(len(cards)), cards):
        with column:
            st.html(f'<div class="scan-stat {color}"><div>{label}</div><strong>{count}<small>건</small></strong><footer>{subtitle}</footer></div>')
    chart_left, chart_right = st.columns([1.45, 1], gap="medium")
    with chart_left.container(border=True, key="overview_types"):
        st.markdown("#### 유형별 취약점")
        st.caption("취약(VULNERABLE)으로 판정된 점검 수")
        if vulnerable.empty:
            st.info("취약 판정이 없습니다.")
        else:
            chart_data = (
                vulnerable.groupby("유형").size().reset_index(name="건수")
                .sort_values(["건수", "유형"], ascending=[False, True])
            )
            type_order = chart_data["유형"].tolist()
            maximum_count = int(chart_data["건수"].max())
            x_limit = max(maximum_count * 1.16, maximum_count + 1)
            base_chart = alt.Chart(chart_data).encode(
                x=alt.X(
                    "건수:Q",
                    title=None,
                    scale=alt.Scale(domain=[0, x_limit]),
                    axis=alt.Axis(tickMinStep=1),
                ),
                y=alt.Y(
                    "유형:N",
                    title=None,
                    sort=type_order,
                    axis=alt.Axis(labelLimit=235),
                ),
                tooltip=[alt.Tooltip("유형:N"), alt.Tooltip("건수:Q")],
            )
            bars = base_chart.mark_bar(
                color="#3d80b8",
                cornerRadiusEnd=5,
                size=18,
            )
            count_labels = base_chart.mark_text(
                align="left",
                baseline="middle",
                dx=6,
                color="#365b77",
                fontSize=11,
                fontWeight=700,
            ).encode(text=alt.Text("건수:Q", format="d"))
            chart_height = max(245, len(chart_data) * 30)
            chart = (bars + count_labels).properties(height=chart_height)
            st.altair_chart(
                chart.configure_view(stroke=None).configure_axis(
                    gridColor="#edf1f5",
                    domainColor="#e1e7ee",
                    labelColor="#5f7589",
                ),
                width="stretch",
            )
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

    render_overall_assessment(analysis_data)


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


def format_evidence_value(value: Any) -> str:
    """기술 증거 값을 화면에서 읽기 쉬운 문자열로 변환합니다."""
    if isinstance(value, bool):
        return "예" if value else "아니요"
    if value in (None, ""):
        return "-"
    return str(value)


def has_display_value(value: Any) -> bool:
    """None, NaN, 빈 문자열처럼 화면에 표시할 필요가 없는 값을 걸러냅니다."""
    if value is None:
        return False
    if isinstance(value, float) and pd.isna(value):
        return False
    if isinstance(value, str) and not value.strip():
        return False
    if isinstance(value, (list, dict)) and not value:
        return False
    return True


def render_evidence_fields(fields: list[tuple[str, Any]], columns: int = 3) -> None:
    """라벨과 값을 작은 기술 정보 카드 형태로 표시합니다."""
    visible_fields = [(label, value) for label, value in fields if has_display_value(value)]
    for start in range(0, len(visible_fields), columns):
        for column, (label, value) in zip(st.columns(columns), visible_fields[start:start + columns]):
            with column:
                st.html(
                    '<div class="evidence-field">'
                    f'<span>{escape(label)}</span>'
                    f'<strong>{escape(format_evidence_value(value))}</strong>'
                    '</div>'
                )


def render_scanner_evidence(row: pd.Series) -> None:
    """선택한 스캐너에 맞춰 details의 핵심 기술 증거만 표시합니다."""
    details = row.get("상세정보")
    if not isinstance(details, dict) or not details:
        st.info("이 점검에는 추가 기술 정보가 제공되지 않았습니다.")
        return

    scanner = str(row.get("스캐너", ""))
    raw_result = details.get("raw_result")

    if scanner == "sqli" and isinstance(raw_result, dict):
        render_evidence_fields([
            ("응답 상태", raw_result.get("status_code")),
            ("검사 ID", details.get("scan_id")),
            ("분류", details.get("category")),
        ])
        if raw_result.get("payload"):
            st.caption("사용한 페이로드")
            st.code(str(raw_result["payload"]), language="text")
        checks = raw_result.get("checks") or []
        if checks:
            check_rows = [{
                "검사 방식": check.get("type", "-"),
                "확인 여부": "확인됨" if check.get("confirmed") else "미확인",
                "비고": check.get("reason", ""),
            } for check in checks]
            st.caption("검사 결과")
            st.dataframe(pd.DataFrame(check_rows), hide_index=True, width="stretch")

    elif scanner == "xss" and isinstance(raw_result, list):
        for index, evidence in enumerate(raw_result, 1):
            st.markdown(f"**반영 증거 {index}**")
            render_evidence_fields([
                ("파라미터", evidence.get("parameter")),
                ("반영 컨텍스트", evidence.get("context")),
                ("취약 확인", evidence.get("vulnerable")),
            ])
            if evidence.get("payload"):
                st.caption("사용한 페이로드")
                st.code(str(evidence["payload"]), language="text")
            if evidence.get("evidence"):
                st.caption("응답에서 확인된 HTML")
                st.code(str(evidence["evidence"]), language="html", wrap_lines=True)

    elif scanner == "authz":
        similarity = details.get("similarity")
        similarity_text = f"{similarity * 100:.1f}%" if isinstance(similarity, (int, float)) else similarity
        owner = details.get("owner") or {}
        attacker = details.get("attacker") or {}
        anonymous = details.get("anonymous") or {}
        render_evidence_fields([
            ("비교 방식", details.get("comparison")),
            ("응답 유사도", similarity_text),
            ("익명 접근", details.get("anonymous_blocked")),
            ("소유자 응답", owner.get("status")),
            ("다른 사용자 응답", attacker.get("status")),
            ("비로그인 응답", anonymous.get("status")),
        ])

    elif scanner == "directory_indexing":
        render_evidence_fields([
            ("응답 상태", details.get("status_code")),
            ("탐지 지표 수", len(details.get("matched_indicators") or [])),
        ])
        indicators = details.get("matched_indicators") or []
        if indicators:
            st.caption("확인된 디렉터리 목록 지표")
            st.code("\n".join(map(str, indicators)), language="text")

    elif scanner == "fileio":
        if "accessible_count" in details:
            render_evidence_fields([
                ("점검 ID 범위", details.get("scanned_window") or details.get("range")),
                ("접근 가능한 파일", details.get("accessible_count")),
                ("UI 미노출 파일", details.get("hidden_from_ui_count")),
                ("점검 사용자", details.get("as_user")),
                ("구조적 약점", details.get("structural_weakness")),
                ("검사 ID", details.get("scan_id")),
            ])
        else:
            render_evidence_fields([
                ("업로드 파일명", details.get("uploaded_filename")),
                ("저장 파일명", details.get("stored_filename")),
                ("업로드 허용", details.get("accepted")),
                ("응답 상태", details.get("status_code")),
                ("다운로드 경로", details.get("download_path")),
                ("내용 재조회", details.get("content_retrievable")),
                ("제공 콘텐츠 타입", details.get("served_content_type")),
                ("브라우저 내 표시", details.get("served_inline")),
                ("검사 설명", details.get("note")),
            ])
            rejection = details.get("rejection") or {}
            if rejection:
                st.caption("서버 차단 결과")
                st.write(rejection.get("inferred") or rejection.get("message") or rejection)

    elif scanner == "ssrf":
        render_evidence_fields([
            ("요청 대상", details.get("probe_url")),
            ("입력 파라미터", details.get("parameter")),
            ("수행 동작", details.get("action")),
            ("폼 응답", details.get("form_status")),
            ("대상 응답", details.get("target_status")),
            ("최종 URL", details.get("final_url")),
        ])
        if details.get("evidence_marker"):
            st.caption("내부 서비스 접근 식별 문구")
            st.code(str(details["evidence_marker"]), language="text")

    elif scanner == "admin_exposure":
        render_evidence_fields([
            ("응답 상태", details.get("status_code")),
            ("확인된 지표", details.get("indicator_count")),
            ("판정 필요 지표", details.get("required_indicator_count")),
        ])
        indicators = details.get("matched_indicators") or []
        if indicators:
            st.caption("관리자 페이지 식별 지표")
            st.code("\n".join(map(str, indicators)), language="text")

    else:
        # 아직 전용 레이아웃이 없는 스캐너는 원본 정보를 접힌 JSON으로 제공합니다.
        st.json(details, expanded=False)


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
        selection_mode="multi-row",
        key="findings_table",
    )
    st.caption(f"체크한 모든 행의 상세 정보가 아래에 표시됩니다. · {len(filtered)}개 표시 / 전체 {len(checks)}개 점검")

    if filtered.empty:
        st.info("선택한 조건에 해당하는 결과가 없습니다.")
        return

    detail_rows = filtered.reset_index(drop=True)
    selected_indices = [
        int(index) for index in table_event.selection.rows
        if 0 <= int(index) < len(detail_rows)
    ]
    if not selected_indices:
        st.info("상세 정보를 확인할 항목을 표에서 체크하세요.")
        return

    st.caption(f"선택한 항목 {len(selected_indices)}개")
    for order, selected_index in enumerate(selected_indices, start=1):
        row = detail_rows.iloc[selected_index]
        with st.container(border=True, key=f"finding_detail_{selected_index}"):
            verdict_label = verdict_korean.get(row["판정"], row["판정"])
            severity_class = str(row["위험도"]).lower()
            st.html(
                '<div class="finding-detail-header">'
                f'<div><span class="finding-detail-eyebrow">SELECTED FINDING {order:02d}</span>'
                f'<h3>{escape(str(row["유형"]))}</h3></div>'
                '<div class="finding-detail-badges">'
                f'<span class="detail-badge verdict">{escape(str(verdict_label))}</span>'
                f'<span class="detail-badge severity {escape(severity_class)}">{escape(str(row["위험도"]))}</span>'
                f'<span class="detail-badge scanner">{escape(str(row["스캐너"] or "미지정"))}</span>'
                '</div></div>'
            )

            endpoint_column, parameter_column = st.columns(2, gap="medium")
            with endpoint_column:
                st.html(
                    '<div class="detail-compact-card"><span>요청 엔드포인트</span>'
                    '<div class="finding-endpoint">'
                    f'<span>{escape(str(row["메서드"] or "-"))}</span>'
                    f'<code>{escape(str(row["위치"] or "-"))}</code>'
                    '</div></div>'
                )
            with parameter_column:
                st.html(
                    '<div class="detail-compact-card"><span>점검 파라미터</span>'
                    f'<strong>{escape(str(row["파라미터"] or "경로 기반 점검"))}</strong></div>'
                )

            description = row["설명"] if has_display_value(row["설명"]) else ""
            show_description = bool(description) and str(description).strip() != str(row["근거"]).strip()
            if show_description:
                st.html(
                    '<div class="detail-description-row"><span>판정 설명</span>'
                    f'<p>{escape(str(description))}</p></div>'
                )

            evidence_column, remediation_column = st.columns(2, gap="medium")
            with evidence_column:
                st.html('<div class="detail-section-title"><span>01</span> 탐지 근거</div>')
                st.html(
                    '<div class="detail-evidence-block">'
                    f'{escape(str(row["근거"] or "탐지 근거가 제공되지 않았습니다."))}'
                    '</div>'
                )
                if has_display_value(row["페이로드"]):
                    st.html('<div class="detail-sub-label">사용한 페이로드</div>')
                    st.code(str(row["페이로드"]), language="text", wrap_lines=True)
            with remediation_column:
                st.html('<div class="detail-section-title"><span>02</span> 대응 방안</div>')
                remediation = row["대응방안"] or "추가 검토 후 적절한 보안 통제를 적용하세요."
                st.html(f'<div class="detail-remediation-block">{escape(str(remediation))}</div>')

            st.html('<div class="detail-section-title technical-evidence-title"><span>03</span> 상세 기술 증거</div>')
            render_scanner_evidence(row)


def get_review_guidance(row: pd.Series) -> tuple[str, list[str]]:
    """REVIEW 판정의 원인과 사람이 확인할 항목을 스캐너별로 설명합니다."""
    scanner = str(row.get("스캐너", ""))
    method = str(row.get("메서드", "")).upper()
    details = row.get("상세정보") if isinstance(row.get("상세정보"), dict) else {}

    if scanner == "authn":
        return (
            "로그인 전후 요청이 모두 성공했지만 응답 차이만으로 보호 기능 노출 여부를 확정할 수 없습니다.",
            [
                "비로그인 응답에 관리자 전용 데이터나 기능이 실제 포함되는지 확인",
                "페이지 진입 이후의 중요 기능에도 인증 검사가 적용되는지 확인",
                "인증 세션 제거 후 동일 요청을 다시 실행해 결과 비교",
            ],
        )

    if scanner == "authz" and method in {"POST", "PUT", "PATCH", "DELETE"} and not details:
        return (
            "데이터를 변경하는 요청이라 자동 교차 계정 검사를 실행하지 않아 권한 통제 여부가 확정되지 않았습니다.",
            [
                "테스트 계정 두 개로 동일 요청을 안전한 환경에서 교차 실행",
                "다른 사용자의 객체 ID로 변경 요청이 거부되는지 확인",
                "서버가 세션 사용자와 대상 객체의 소유권을 비교하는지 확인",
            ],
        )

    if scanner == "authz":
        similarity = details.get("similarity")
        similarity_text = f"{similarity * 100:.1f}%" if isinstance(similarity, (int, float)) else "높은"
        return (
            f"다른 사용자의 요청도 성공했고 소유자 응답과 {similarity_text} 유사하지만, 해당 자원이 원래 공개 대상인지 판단이 필요합니다.",
            [
                "응답에 개인정보·비공개 파일 등 보호 대상 내용이 포함되는지 확인",
                "서비스 정책상 다른 사용자에게 공개되는 자원인지 확인",
                "객체 ID만 변경해 다른 비공개 자원에도 접근 가능한지 확인",
            ],
        )

    if scanner == "sqli":
        return (
            "HTTP 리다이렉트 또는 인증 문제로 SQL Injection 검사가 끝까지 수행되지 않아 안전 여부를 확정할 수 없습니다.",
            [
                "유효한 인증 세션과 CSRF 토큰으로 동일 입력 지점을 재점검",
                "302 이동 대상이 로그인 페이지인지 정상 처리 페이지인지 확인",
                "서버 로그에서 SQL 오류 및 비정상 쿼리 실행 흔적 확인",
            ],
        )

    return (
        "자동 검사 결과만으로 취약 여부를 확정하기에 증거가 충분하지 않습니다.",
        [
            "원본 요청과 응답을 재현해 판정 근거 확인",
            "해당 기능의 공개 범위와 접근 정책 확인",
            "필요한 인증·권한 조건을 갖춰 재점검",
        ],
    )


def render_review_queue(scan_data: dict) -> None:
    """수동 확인이 필요한 REVIEW 항목과 검토 이유를 한 화면에 표시합니다."""
    checks = get_check_rows(redact_sensitive_data(scan_data))
    reviews = checks[checks["판정"] == "REVIEW"].reset_index(drop=True)

    st.subheader("Review Queue")
    st.caption("자동 판정이 보류된 항목입니다. 근거와 확인 포인트를 검토한 뒤 최종 판정을 결정하세요.")
    if reviews.empty:
        st.success("현재 수동 검토가 필요한 항목이 없습니다.")
        return

    summary_columns = st.columns(3)
    summary_columns[0].metric("검토 항목", len(reviews), border=True)
    summary_columns[1].metric(
        "영향 엔드포인트",
        reviews[["메서드", "위치"]].drop_duplicates().shape[0],
        border=True,
    )
    summary_columns[2].metric("관련 스캐너", reviews["스캐너"].nunique(), border=True)

    scanner_counts = reviews["스캐너"].value_counts().to_dict()
    scanner_summary = " · ".join(f"{scanner} {count}건" for scanner, count in scanner_counts.items())
    st.html(f'<div class="review-summary-strip">{escape(scanner_summary)}</div>')

    for index, row in reviews.iterrows():
        reason, checklist = get_review_guidance(row)
        severity_class = str(row["위험도"]).lower()
        with st.container(border=True, key=f"review_item_{index}"):
            st.html(
                '<div class="review-card-header">'
                '<div class="review-card-number">'
                f'{index + 1:02d}</div><div class="review-card-title">'
                f'<strong>{escape(str(row["유형"]))}</strong>'
                f'<span>{escape(str(row["스캐너"]))}</span></div>'
                '<div class="finding-detail-badges">'
                '<span class="detail-badge verdict">REVIEW</span>'
                f'<span class="detail-badge severity {escape(severity_class)}">{escape(str(row["위험도"]))}</span>'
                '</div></div>'
            )
            st.html(
                '<div class="finding-endpoint review-endpoint">'
                f'<span>{escape(str(row["메서드"]))}</span>'
                f'<code>{escape(str(row["위치"]))}</code></div>'
            )
            st.html(
                '<div class="review-reason"><span>왜 검토가 필요한가요?</span>'
                f'<p>{escape(reason)}</p></div>'
            )
            evidence_column, checklist_column = st.columns([1, 1.15])
            with evidence_column:
                st.html(
                    '<div class="review-column-title">자동 검사 근거</div>'
                    f'<div class="review-evidence">{escape(str(row["근거"] or "근거 미제공"))}</div>'
                )
                if has_display_value(row["파라미터"]):
                    st.html(
                        '<div class="review-parameter"><span>확인 위치</span>'
                        f'{escape(str(row["파라미터"]))}</div>'
                    )
            with checklist_column:
                checklist_html = "".join(f"<li>{escape(item)}</li>" for item in checklist)
                st.html(
                    '<div class="review-column-title">직접 확인할 내용</div>'
                    f'<ul class="review-checklist">{checklist_html}</ul>'
                )


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


def render_attack_scenarios(analysis_data: dict) -> None:
    """분석 JSON에 생성된 공격 시나리오를 근거와 가정을 구분해 표시합니다."""
    analysis = get_analysis_section(analysis_data)
    scenarios = analysis.get("attack_scenarios") or []

    st.subheader("Attack Scenarios")
    st.caption("분석 결과에서 식별된 취약점 연계 가능성과 추가 확인 조건을 보여줍니다.")
    if not isinstance(scenarios, list) or not scenarios:
        st.info("분석 JSON에 표시할 공격 시나리오가 없습니다.")
        return

    valid_scenarios = [item for item in scenarios if isinstance(item, dict)]
    evidence_count = len({ref for item in valid_scenarios for ref in (item.get("evidence_refs") or [])})
    endpoint_count = len({url for item in valid_scenarios for url in (item.get("related_endpoints") or [])})
    st.html(
        '<div class="scenario-summary">'
        f'<div><span>시나리오</span><strong>{len(valid_scenarios)}</strong><small>건</small></div>'
        f'<div><span>연결된 근거</span><strong>{evidence_count}</strong><small>건</small></div>'
        f'<div><span>관련 엔드포인트</span><strong>{endpoint_count}</strong><small>개</small></div>'
        '</div>'
    )

    status_labels = {"possible": "연계 가능", "confirmed": "확인됨", "unlikely": "가능성 낮음"}
    confidence_labels = {"high": "높은 신뢰도", "medium": "중간 신뢰도", "low": "낮은 신뢰도"}
    for index, scenario in enumerate(scenarios, 1):
        if not isinstance(scenario, dict):
            continue
        title = escape(str(scenario.get("title") or f"시나리오 {index}"))
        candidate_ref = escape(str(scenario.get("candidate_ref") or f"S{index:03d}"))
        status = str(scenario.get("scenario_status") or "possible").lower()
        confidence = str(scenario.get("confidence") or "unknown").lower()
        evidence_refs = scenario.get("evidence_refs") or []
        vulnerability_types = scenario.get("related_vulnerability_types") or []
        endpoints = scenario.get("related_endpoints") or []

        evidence_tags = "".join(f'<span>{escape(str(ref))}</span>' for ref in evidence_refs)
        type_tags = "".join(f'<span>{escape(str(item).upper())}</span>' for item in vulnerability_types)
        endpoint_items = "".join(
            f'<li><code>{escape(str(endpoint))}</code></li>' for endpoint in endpoints
        ) or '<li class="empty">관련 엔드포인트 미제공</li>'

        st.html(
            '<article class="attack-scenario-card">'
            '<header class="scenario-card-header">'
            f'<div class="scenario-index">{index:02d}</div>'
            f'<div class="scenario-title"><span>{candidate_ref}</span><h3>{title}</h3></div>'
            '<div class="scenario-badges">'
            f'<strong class="scenario-status {escape(status)}">{escape(status_labels.get(status, status))}</strong>'
            f'<strong class="scenario-confidence {escape(confidence)}">{escape(confidence_labels.get(confidence, confidence))}</strong>'
            '</div></header>'
            '<div class="scenario-meta">'
            f'<div><label>관련 취약점</label><div class="scenario-tags type">{type_tags or "<span>미제공</span>"}</div></div>'
            f'<div><label>근거 ID</label><div class="scenario-tags evidence">{evidence_tags or "<span>미제공</span>"}</div></div>'
            '</div>'
            '<section class="scenario-narrative">'
            '<span>예상 공격 흐름</span>'
            f'<p>{escape(str(scenario.get("scenario") or "설명이 제공되지 않았습니다."))}</p>'
            '</section>'
            '<div class="scenario-detail-grid">'
            '<section><span>잠재적 영향</span>'
            f'<p>{escape(str(scenario.get("potential_impact") or "미제공"))}</p></section>'
            '<section><span>추가 확인 조건</span>'
            f'<p>{escape(str(scenario.get("required_conditions") or "미제공"))}</p></section>'
            '</div>'
            '<section class="scenario-endpoints"><span>관련 엔드포인트</span>'
            f'<ul>{endpoint_items}</ul></section>'
            '</article>'
        )


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
        result_path = st.session_state.get("scan_report_path") or SCANNER_RESULT_FILENAME
        scan_data = load_scan_result(uploaded_file) if uploaded_file else load_configured_json(result_path)
        if uploaded_analysis_file:
            analysis_data = load_scan_result(uploaded_analysis_file)
        elif "analysis_report_path" in st.session_state:
            # 이번 검사의 추가 분석이 실패하면 이전 파일을 대신 표시하지 않는다.
            analysis_path = st.session_state["analysis_report_path"]
            analysis_data = load_configured_json(analysis_path, required=False) if analysis_path else {}
        else:
            analysis_data = load_configured_json(ANALYSIS_RESULT_FILENAME, required=False)
        findings_df = flatten_findings(scan_data)
        summary = build_summary(scan_data, findings_df)
    except Exception as exc:
        st.error(f"JSON 처리 오류: {exc}")
        return

    with st.sidebar:
        source_name = uploaded_file.name if uploaded_file is not None else str(result_path)
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

    tab_overview, tab_findings, tab_review, tab_attack = st.tabs([
        "Overview", "Findings", "Review Queue", "Attack Scenario"
    ])

    with tab_overview:
        render_overview(scan_data, analysis_data)

    with tab_findings:
        with st.container(border=True):
            st.subheader("상세 진단 결과")
            st.caption("전체 점검 판정을 필터링하고 선택한 항목의 근거와 대응방안을 확인하세요.")
            render_findings_table(scan_data)

    with tab_review:
        render_review_queue(scan_data)

    with tab_attack:
        render_attack_scenarios(analysis_data)


if __name__ == "__main__":
    main()
