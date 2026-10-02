'''
실행 : python.exe -m streamlit run streamlit_app.py
ROOKIESCAN 도구 실행 및 보고서 출력하는 streamlit 기반 웹
'''

from importlib import reload

import streamlit as st
import sink_finder
import openai_module

# 제목이 화면 위쪽에 오도록 상단 여백을 조정한다.
st.markdown("<style>.stMainBlockContainer {padding-top: 3rem;}</style>", unsafe_allow_html=True)

# target_url이랑 session_cookie받아오기
st.title("ROOKIESCAN")
# show_report 값으로 입력 화면과 보고서 화면을 전환한다.
if not st.session_state.get("show_report", False):
    # 제목과 입력 폼 사이에 작은 간격을 둔다.
    st.space("small")
    # 뒤로 돌아왔을 때 이전 URL과 쿠키를 다시 표시한다.
    saved_inputs = st.session_state.get("scan_inputs", ("", ""))
    # 입력 폼과 로딩 표시가 같은 자리를 사용하도록 영역을 만든다.
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
        # 입력 폼을 지우고 탐색이 끝날 때까지 로딩 표시를 띄운다.
        panel.empty()
        try:
            with panel.container(), st.spinner("입력 지점을 찾는 중입니다."):
                # 모듈을 새로 불러와 Sink를 수집하고 OpenAI 전달용 그룹으로 묶는다.
                sinks = reload(sink_finder).find_sinks(target_url, session_cookie)
                openai_sinks = reload(openai_module).prepare_sinks_for_openai(sinks)
        except ValueError as exc:
            st.session_state["scan_error"] = str(exc)
        else:
            # 원본과 요약을 세션에 저장하고 보고서 화면으로 전환한다.
            st.session_state["sinks"] = sinks
            st.session_state["openai_sinks"] = openai_sinks
            st.session_state["scan_target_url"] = target_url.strip()
            st.session_state["show_report"] = True
        st.rerun()
else:
    sinks = st.session_state["sinks"]
    groups = st.session_state["openai_sinks"]["groups"]
    st.subheader("Sink 탐색 보고서")
    st.write("대상 URL:", st.session_state["scan_target_url"])
    st.caption(f"발견한 엔드포인트 {len(sinks)}개 → OpenAI 전달 그룹 {len(groups)}개")
    # OpenAI 전달 그룹을 한 행씩 보여주는 보고서 표를 만든다.
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

    # 뒤로가기는 왼쪽, 취약점 분석하기는 오른쪽 끝에 배치한다.
    with st.container(horizontal=True, horizontal_alignment="distribute"):
        if st.button("뒤로가기"):
            st.session_state["show_report"] = False
            st.rerun()
        analyze_clicked = st.button("취약점 분석하기")
    # 실제 취약점 분석 기능을 연결하기 전까지 안내 메시지를 표시한다.
    if analyze_clicked:
        st.info("취약점 분석 기능은 준비 중입니다.")
