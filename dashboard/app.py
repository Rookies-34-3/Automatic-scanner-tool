import json
import os
from collections import Counter
from typing import Any

import pandas as pd
import streamlit as st
from openai import OpenAI

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


def render_severity_chart(summary: dict) -> None:
    chart_df = pd.DataFrame({
        "severity": SEVERITY_ORDER,
        "count": [summary["severity_counts"][s] for s in SEVERITY_ORDER],
    }).set_index("severity")
    st.bar_chart(chart_df)


def render_findings_table(findings_df: pd.DataFrame) -> None:
    finding_rows = findings_df[findings_df["type"] != ""].copy()
    if finding_rows.empty:
        st.success("탐지된 취약점이 없습니다.")
        return

    severity_filter = st.multiselect(
        "Severity 필터",
        SEVERITY_ORDER,
        default=SEVERITY_ORDER,
    )
    scanner_options = sorted(finding_rows["scanner"].dropna().unique().tolist())
    scanner_filter = st.multiselect("Scanner 필터", scanner_options, default=scanner_options)

    filtered = finding_rows[
        finding_rows["severity"].isin(severity_filter)
        & finding_rows["scanner"].isin(scanner_filter)
    ]

    st.dataframe(
        filtered[["severity", "type", "scanner", "method", "url", "parameter"]],
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("상세 Findings")
    for index, row in filtered.reset_index(drop=True).iterrows():
        title = f"[{row['severity']}] {row['type']} - {row['method']} {row['url']}"
        with st.expander(title):
            st.write(f"**Scanner:** {row['scanner']}")
            st.write(f"**Parameter:** {row['parameter'] or '-'}")
            st.write(f"**Description:** {row['description'] or '-'}")
            if row["payload"]:
                st.write("**Payload**")
                st.code(str(row["payload"]), language="text")
            if row["evidence"]:
                st.write("**Evidence**")
                st.code(str(row["evidence"]), language="text")
            st.write(f"**Recommendation:** {row['recommendation'] or '-'}")


def main() -> None:
    st.set_page_config(page_title="Vulnerability Scan Dashboard", layout="wide")
    st.title("Vulnerability Scan Dashboard")
    st.caption("통합 취약점 스캐너 결과 조회 및 AI 분석")

    with st.sidebar:
        st.header("입력")
        uploaded_file = st.file_uploader("통합 결과 JSON", type=["json"])
        model = st.text_input("OpenAI model", value=os.getenv("OPENAI_MODEL", "gpt-6-luna"))
        st.caption("OPENAI_API_KEY는 환경변수로 설정합니다.")

    if uploaded_file is None:
        st.info("왼쪽 사이드바에서 통합 스캔 결과 JSON을 업로드해 주세요.")
        return

    try:
        scan_data = load_scan_result(uploaded_file)
        findings_df = flatten_findings(scan_data)
        summary = build_summary(scan_data, findings_df)
    except Exception as exc:
        st.error(f"JSON 처리 오류: {exc}")
        return

    tab_overview, tab_findings, tab_ai, tab_raw = st.tabs([
        "Overview", "Findings", "AI Analysis", "Raw JSON"
    ])

    with tab_overview:
        render_metrics(summary)
        st.subheader("Severity 분포")
        render_severity_chart(summary)

        if not findings_df.empty:
            scanner_summary = (
                findings_df.groupby("scanner", dropna=False)
                .agg(
                    executions=("url", "count"),
                    vulnerable=("vulnerable", "sum"),
                )
                .reset_index()
            )
            st.subheader("Scanner별 요약")
            st.dataframe(scanner_summary, use_container_width=True, hide_index=True)

    with tab_findings:
        render_findings_table(findings_df)

    with tab_ai:
        st.subheader("AI 취약점 진단 결과 분석")
        question = st.text_area(
            "추가 질문 (선택)",
            placeholder="예: 가장 먼저 조치해야 할 취약점과 이유를 정리해줘.",
        )
        if st.button("AI 분석 실행", type="primary"):
            try:
                with st.spinner("분석 중..."):
                    analysis = analyze_with_ai(scan_data, model, question)
                st.markdown(analysis)
            except Exception as exc:
                st.error(f"AI 분석 오류: {exc}")

    with tab_raw:
        st.json(redact_sensitive_data(scan_data), expanded=False)


if __name__ == "__main__":
    main()
