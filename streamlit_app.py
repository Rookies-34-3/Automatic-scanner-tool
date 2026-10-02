'''
실행 : python.exe -m streamlit run streamlit_app.py
ROOKIESCAN 도구 실행 및 보고서 출력하는 streamlit 기반 웹
'''

from importlib import reload

import streamlit as st
from openai import OpenAIError
import sink_finder
import openai_module

# 제목이 화면 위쪽에 오도록 상단 여백을 조정
st.markdown("<style>.stMainBlockContainer {padding-top: 3rem;}</style>", unsafe_allow_html=True)

# target_url이랑 session_cookie받아오기
st.title("ROOKIESCAN")

# show_report와 show_analysis 값으로 입력·Sink 보고서·AI 보고서 화면을 전환
if not st.session_state.get("show_report", False):
    # 제목과 입력 폼 사이에 작은 간격
    st.space("small")

    # 뒤로 돌아왔을 때 이전 URL과 쿠키를 다시 표시
    saved_inputs = st.session_state.get("scan_inputs", ("", ""))

    # 입력 폼과 로딩 표시가 같은 자리를 사용하는 영역
    panel = st.empty()
    with panel.container():
        target_url = st.text_input("대상 URL", value=saved_inputs[0])
        session_cookie = st.text_input("세션 쿠키", value=saved_inputs[1], type="password")
        find_clicked = st.button("Sink 찾기")
        if "scan_error" in st.session_state:
            st.error(st.session_state.pop("scan_error"))

    #이제 sink 찾아야함 sink_finder
    if find_clicked:
        st.session_state["scan_inputs"] = (target_url, session_cookie)
        # 입력 폼을 지우고 탐색이 끝날 때까지 로딩 표시
        panel.empty()
        try:
            with panel.container(), st.spinner("입력 지점을 찾는 중입니다."):
                # 모듈을 새로 불러와 Sink를 수집하고 OpenAI 전달용 그룹으로 묶기
                sinks = reload(sink_finder).find_sinks(target_url, session_cookie)
                openai_sinks = reload(openai_module).prepare_sinks_for_openai(sinks)
        except ValueError as exc:
            st.session_state["scan_error"] = str(exc)
        else:
            # 원본과 요약을 세션에 저장하고 보고서 화면으로 전환
            st.session_state["sinks"] = sinks
            st.session_state["openai_sinks"] = openai_sinks
            st.session_state["scan_target_url"] = target_url.strip()
            st.session_state.pop("analysis_result", None)
            st.session_state.pop("analysis_error", None)
            st.session_state.pop("analysis_pending", None)
            st.session_state["show_analysis"] = False
            st.session_state["show_report"] = True
        st.rerun()
elif not st.session_state.get("show_analysis", False):
    sinks = st.session_state["sinks"]
    groups = st.session_state["openai_sinks"]["groups"]
    st.subheader("Sink 탐색 보고서")
    st.write("대상 URL:", st.session_state["scan_target_url"])
    st.caption(f"발견한 엔드포인트 {len(sinks)}개 → OpenAI 전달 그룹 {len(groups)}개")
    # OpenAI 전달 그룹을 한 행씩 보여주는 보고서 표
    rows = [{
        "메서드": group["method"],
        "경로": group["path_template"],
        "입력 필드": ", ".join(sorted({f"{p['name']} ({p['location']})"
                                    for variant in group["request_variants"] for p in variant["parameters"]})) or "-",
        "후보 tool": ", ".join(group["candidate_tools"]) or "-",
        "발견 수": group["discovered_count"],
        "대표 URL": "\n".join(dict.fromkeys(variant["sample_url"] for variant in group["request_variants"])),
    } for group in groups]
    st.dataframe(rows, hide_index=True)

    # 뒤로가기는 왼쪽, 취약점 분석하기는 오른쪽 끝에 배치
    with st.container(horizontal=True, horizontal_alignment="distribute"):
        if st.button("뒤로가기"):
            st.session_state["show_report"] = False
            st.rerun()
        if st.button("취약점 분석하기", disabled=not groups):
            st.session_state["show_analysis"] = True
            st.session_state["analysis_pending"] = "analysis_result" not in st.session_state
            st.rerun()

else:
    st.subheader("AI 분석 보고서")
    st.write("대상 URL:", st.session_state["scan_target_url"])
    # AI 요청과 임시 tool 처리의 진행 상태를 표시
    if st.session_state.pop("analysis_pending", False):
        with st.status("AI가 Sink 후보를 분석 중입니다…", expanded=True) as status:
            try:
                report = reload(openai_module).analyze_sinks(
                    st.session_state["openai_sinks"], on_progress=status.write,
                )
            except (ValueError, OpenAIError) as exc:
                status.update(label="AI 분석 실패", state="error")
                message = str(exc) if isinstance(exc, ValueError) else (
                    f"OpenAI 요청에 실패했습니다 ({type(exc).__name__}). "
                    "API 키, 모델 권한과 연결 상태를 확인하세요."
                )
                st.session_state["analysis_error"] = message
            else:
                st.session_state["analysis_result"] = report
                st.session_state.pop("analysis_error", None)
                status.update(label="AI 분석 완료", state="complete", expanded=False)

    if "analysis_error" in st.session_state:
        st.error(st.session_state["analysis_error"])
    # 저장된 결과를 보여주므로 화면을 다시 그려도 API를 재호출하지 않는다.
    if "analysis_result" in st.session_state:
        report = st.session_state["analysis_result"]
        st.caption(f"모델: {report['model']} · 분석 대상 {report['group_count']}개 그룹 "
                   f"· 임시 tool 호출 {len(report['tool_results'])}회 · 실제 검증 미수행")
        st.markdown(report["summary"])
        st.dataframe([{
            "메서드": result["method"], "URL": result["url"],
            "입력 필드": ", ".join(f"{p['name']} ({p['location']})" for p in result["parameters"]) or "-",
            "호출 함수": result["tool"], "처리 상태": result["message"], "검증 상태": "미검증",
        } for result in report["tool_results"]], hide_index=True)

    # AI 보고서에서 돌아가면 저장된 Sink 탐색 보고서를 보여준다.
    with st.container(horizontal=True, horizontal_alignment="distribute"):
        if st.button("뒤로가기"):
            st.session_state["show_analysis"] = False
            st.rerun()
        if "analysis_result" not in st.session_state and st.button("다시 시도"):
            st.session_state["analysis_pending"] = True
            st.rerun()
