'''
실행 : python.exe -m streamlit run streamlit_app.py
ROOKIESCAN 도구 실행 및 보고서 출력하는 streamlit 기반 웹
'''

import runpy
from importlib import reload
from pathlib import Path
import json

import streamlit as st
from openai import OpenAIError
import sink_finder
import openai_module
import report_writer

# 실행 중 pull한 경우에도 보고서 작성 함수가 있는 버전을 사용한다.
if not hasattr(report_writer, "build_scan_report"):
    reload(report_writer)

# 제목이 화면 위쪽에 오도록 상단 여백을 조정
st.markdown("<style>.stMainBlockContainer {padding-top: 3rem;}</style>", unsafe_allow_html=True)

# target_url이랑 session_cookie받아오기
st.title("ROOKIESCAN")

# 실행 중 결과 스키마가 바뀌었으면 오래된 세션 결과를 재사용하지 않는다.
if "analysis_result" in st.session_state and "tool_results" not in st.session_state["analysis_result"]:
    st.session_state.pop("analysis_result")

# show_report와 show_analysis 값으로 입력·Sink 보고서·대시보드 화면을 전환
if not st.session_state.get("show_report", False):
    # 제목과 입력 폼 사이에 작은 간격
    st.space("small")

    # 뒤로 돌아왔을 때 이전 URL과 쿠키를 다시 표시
    saved_inputs = tuple(st.session_state.get("scan_inputs", ("", "")))
    saved_inputs += ("",) * (3 - len(saved_inputs))

    # 입력 폼과 로딩 표시가 같은 자리를 사용하는 영역
    panel = st.empty()
    with panel.container():
        target_url = st.text_input("대상 URL", value=saved_inputs[0])
        session_cookie = st.text_input("사용자 A 세션 쿠키", value=saved_inputs[1], type="password")
        authz_attacker_cookie = st.text_input(
            "사용자 B 세션 쿠키", value=saved_inputs[2], type="password",
            help="교차 계정 및 파일 접근 검사에 사용하며 AI와 결과 JSON에는 전달하지 않습니다.",
        )
        find_clicked = st.button("Sink 찾기")
        if "scan_error" in st.session_state:
            st.error(st.session_state.pop("scan_error"))

    #이제 sink 찾아야함 sink_finder
    if find_clicked:
        if not target_url.strip() or not session_cookie.strip() or not authz_attacker_cookie.strip():
            st.session_state["scan_error"] = "대상 URL과 사용자 A·B 세션 쿠키를 모두 입력하세요."
            st.rerun()
        st.session_state["scan_inputs"] = (target_url, session_cookie, authz_attacker_cookie)
        st.session_state["authz_attacker_cookie"] = authz_attacker_cookie
        st.session_state.pop("lab_password", None)
        # 입력 폼을 지우고 탐색이 끝날 때까지 로딩 표시
        panel.empty()
        try:
            with panel.container(), st.spinner("입력 지점을 찾는 중입니다."):
                # 모듈을 새로 불러와 Sink를 수집하고 OpenAI 전달용 그룹으로 묶기
                sinks = reload(sink_finder).find_sinks(target_url, session_cookie)
                openai_sinks = reload(openai_module).prepare_sinks_for_openai(sinks)
                json_path = report_writer.save_sink_summary(openai_sinks, target_url.strip())
        except (ValueError, OSError) as exc:
            st.session_state["scan_error"] = str(exc)
        else:
            # 원본과 요약을 세션에 저장하고 보고서 화면으로 전환
            st.session_state["sinks"] = sinks
            st.session_state["openai_sinks"] = openai_sinks
            st.session_state["sink_json_path"] = str(json_path)
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
    report_panel = st.empty()
    with report_panel.container():
        st.subheader("Sink 탐색 보고서")
        st.write("대상 URL:", st.session_state["scan_target_url"])
        st.caption(f"발견한 엔드포인트 {len(sinks)}개 → OpenAI 전달 그룹 {len(groups)}개")
        if "sink_json_path" in st.session_state:
            st.caption(f"JSON 파일: output/{Path(st.session_state['sink_json_path']).name}")
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
                report_panel.empty()
                st.rerun()
            if st.button("취약점 분석하기", disabled=not groups):
                st.session_state["show_analysis"] = True
                st.session_state["analysis_pending"] = "analysis_result" not in st.session_state
                report_panel.empty()
                st.rerun()

else:
    analysis_title = st.empty()
    analysis_title.subheader("대시보드" if "analysis_result" in st.session_state else "취약점 분석 중")
    st.write("대상 URL:", st.session_state["scan_target_url"])
    # AI 요청과 임시 tool 처리의 진행 상태를 표시
    if st.session_state.pop("analysis_pending", False):
        with st.status("AI가 Sink 후보를 분석 중입니다…", expanded=True) as status:
            try:
                json_path = st.session_state.get("sink_json_path")
                if json_path:
                    with open(json_path, encoding="utf-8") as source:
                        openai_sinks = json.load(source)
                else:
                    openai_sinks = st.session_state["openai_sinks"]
                report = reload(openai_module).analyze_sinks(
                    openai_sinks,
                    session_cookie=st.session_state.get("scan_inputs", ("", ""))[1],
                    scanner_options={
                        "authz_attacker_cookie": st.session_state.get("authz_attacker_cookie", ""),
                    },
                    on_progress=lambda message: status.update(label=message),
                )
                final_report = report_writer.build_scan_report(
                    st.session_state["scan_target_url"], report,
                )
                report["json_path"] = str(report_writer.save_scan_report(
                    final_report, st.session_state["scan_target_url"],
                ))
            except (ValueError, OSError, OpenAIError) as exc:
                status.update(label="AI 분석 실패", state="error")
                if isinstance(exc, ValueError):
                    message = str(exc)
                elif isinstance(exc, OSError):
                    message = "JSON 파일을 읽거나 저장할 수 없습니다. output 폴더와 파일을 확인하세요."
                else:
                    message = (f"OpenAI 요청에 실패했습니다 ({type(exc).__name__}). "
                               "API 키, 모델 권한과 연결 상태를 확인하세요.")
                st.session_state["analysis_error"] = message
            else:
                st.session_state["analysis_result"] = report
                st.session_state.pop("analysis_error", None)
                label = (
                    "스캐너 분석 완료 · AI 요약 재시도 가능"
                    if report.get("summary_status") == "fallback"
                    else "AI 분석 완료"
                )
                status.update(label=label, state="complete", expanded=False)

    if "analysis_error" in st.session_state:
        analysis_title.subheader("취약점 분석 실패")
        st.error(st.session_state["analysis_error"])
    # 저장된 분석 결과를 재사용하고, 같은 디렉터리에 병합될 대시보드를 실행한다.
    if "analysis_result" in st.session_state:
        analysis_title.empty()
        report = st.session_state["analysis_result"]
        # app.py에서 이 경로를 읽으면 방금 저장한 최종 JSON을 사용할 수 있다.
        st.session_state["scan_report_path"] = report.get("json_path")
        dashboard_path = Path(__file__).with_name("app.py")
        if dashboard_path.is_file():
            runpy.run_path(str(dashboard_path), run_name="__main__")
        else:
            st.info("분석이 완료되었습니다. 같은 디렉터리에 app.py를 추가하면 대시보드가 표시됩니다.")

    # 대시보드에서 돌아가면 저장된 Sink 탐색 보고서를 보여준다.
    with st.container(horizontal=True, horizontal_alignment="distribute"):
        if st.button("뒤로가기"):
            st.session_state["show_analysis"] = False
            st.rerun()
        if "analysis_result" not in st.session_state and st.button("다시 시도"):
            st.session_state["analysis_pending"] = True
            st.rerun()
