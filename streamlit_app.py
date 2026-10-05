'''
실행 : python.exe -m streamlit run streamlit_app.py
ROOKIESCAN 도구 실행 및 보고서 출력하는 streamlit 기반 웹
'''

import runpy
from importlib import reload
from html import escape
from pathlib import Path
import json

import streamlit as st
from openai import OpenAIError
import sink_finder
import openai_module
import report_writer

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


def render_analysis_loading(target, message: str) -> None:
    """분석 단계의 현재 진행 문구를 단순한 애니메이션 카드로 표시합니다."""
    target.html(
        '<div class="analysis-loading-card" role="status" aria-live="polite">'
        '<h2>AI가 Sink 후보를 분석 중입니다</h2>'
        '<i class="fa-solid fa-magnifying-glass fa-beat-fade analysis-loading-icon" aria-hidden="true"></i>'
        f'<p class="analysis-progress-message">{escape(str(message))}</p>'
        '<p class="analysis-loading-caption">분석이 완료되면 취약점 진단 대시보드로 자동 이동합니다.</p>'
        '</div>'
    )


def render_sink_loading(target) -> None:
    """Sink 탐색 중 기본 스피너 대신 고정된 전환 카드를 표시합니다."""
    target.html(
        '<div class="analysis-loading-card" role="status" aria-live="polite">'
        '<h2>입력 지점을 찾는 중입니다</h2>'
        '<i class="fa-solid fa-magnifying-glass fa-beat-fade analysis-loading-icon" aria-hidden="true"></i>'
        '<p class="analysis-progress-message">대상 페이지의 입력 지점을 탐색하고 있습니다…</p>'
        '<p class="analysis-loading-caption">탐색이 완료되면 Sink 탐색 보고서로 자동 이동합니다.</p>'
        '</div>'
    )


def queue_sink_scan() -> None:
    """입력 검증을 마친 뒤 다음 rerun이 즉시 탐색 화면으로 진입하게 합니다."""
    values = (
        st.session_state.get("scan_target_input", ""),
        st.session_state.get("scan_cookie_a_input", ""),
        st.session_state.get("scan_cookie_b_input", ""),
    )
    if not all(str(value).strip() for value in values):
        st.session_state["scan_error"] = "대상 URL과 사용자 A·B 세션 쿠키를 모두 입력하세요."
        st.session_state["sink_scan_pending"] = False
        return
    st.session_state["scan_inputs"] = values
    st.session_state["authz_attacker_cookie"] = values[2]
    st.session_state["sink_scan_pending"] = True


def show_setup_screen() -> None:
    st.session_state["show_report"] = False
    st.session_state["show_analysis"] = False
    st.session_state["sink_scan_pending"] = False


def start_analysis_screen() -> None:
    st.session_state["show_analysis"] = True
    st.session_state["analysis_pending"] = "analysis_result" not in st.session_state


def show_sink_report_screen() -> None:
    st.session_state["show_analysis"] = False


def retry_analysis() -> None:
    st.session_state["analysis_pending"] = True


# 실행 중 pull한 경우에도 보고서 작성 함수가 있는 버전을 사용한다.
if not hasattr(report_writer, "build_scan_report"):
    reload(report_writer)

st.set_page_config(
    page_title="ROOKIESCAN",
    page_icon=":material/security:",
    layout="wide",
    initial_sidebar_state="expanded",
)
st.html(Path(__file__).with_name("dashboard.css"))

# 실행 중 결과 스키마가 바뀌었으면 오래된 세션 결과를 재사용하지 않는다.
if "analysis_result" in st.session_state and "tool_results" not in st.session_state["analysis_result"]:
    st.session_state.pop("analysis_result")

# 완료 화면은 app.py가 상단바와 사이드바를 직접 표시한다.
if not (st.session_state.get("show_analysis") and "analysis_result" in st.session_state):
    render_top_bar()
    with st.sidebar:
        st.html(
            '<div class="sidebar-heading">보안 점검</div>'
            '<p class="sidebar-description">대상을 탐색하고 취약점을 분석한 뒤 대시보드에서 결과를 확인하세요.</p>'
            '<div class="sidebar-section-label">SCAN WORKFLOW</div>'
        )
        stage = 3 if st.session_state.get("show_analysis") else 2 if st.session_state.get("show_report") else 1
        for index, label in enumerate(("대상 설정", "입력 지점 탐색", "취약점 분석"), 1):
            state = "active" if index == stage else "complete" if index < stage else ""
            st.html(f'<div class="scan-step {state}"><span>{index:02d}</span>{label}</div>')

# show_report와 show_analysis 값으로 입력·Sink 보고서·대시보드 화면을 전환
if not st.session_state.get("show_report", False):
    st.html('<div class="scan-setup-heading"><div class="page-eyebrow">SCAN SETUP</div>'
            '<div class="page-heading">검사 대상 설정</div></div>')

    # 뒤로 돌아왔을 때 이전 URL과 쿠키를 다시 표시
    saved_inputs = tuple(st.session_state.get("scan_inputs", ("", "")))
    saved_inputs += ("",) * (3 - len(saved_inputs))
    for key, value in zip(
        ("scan_target_input", "scan_cookie_a_input", "scan_cookie_b_input"),
        saved_inputs,
    ):
        if key not in st.session_state:
            st.session_state[key] = value

    # 입력 폼과 로딩 표시가 같은 자리를 사용하는 영역
    panel = st.empty()
    if not st.session_state.get("sink_scan_pending", False):
        with panel.container(border=True, key="scan_setup"):
            st.html('<div class="scan-card-heading">대상 및 인증 정보</div>')
            st.text_input("대상 URL", placeholder="https://example.com", key="scan_target_input")
            st.text_input("사용자 A 세션 쿠키", type="password", key="scan_cookie_a_input")
            st.text_input(
                "사용자 B 세션 쿠키", type="password", key="scan_cookie_b_input",
                help="교차 계정 및 파일 접근 검사에 사용하며 AI와 결과 JSON에는 전달하지 않습니다.",
            )
            st.button(
                "Sink 찾기", type="primary", icon=":material/search:", width="stretch",
                on_click=queue_sink_scan,
            )
            if "scan_error" in st.session_state:
                st.error(st.session_state.pop("scan_error"))
    else:
        target_url, session_cookie, authz_attacker_cookie = st.session_state["scan_inputs"]
        st.session_state.pop("lab_password", None)
        render_sink_loading(panel)
        try:
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
        st.session_state["sink_scan_pending"] = False
        st.rerun()
elif not st.session_state.get("show_analysis", False):
    sinks = st.session_state["sinks"]
    groups = st.session_state["openai_sinks"]["groups"]
    report_panel = st.empty()
    with report_panel.container(key="sink_report"):
        st.html('<div class="page-eyebrow">ENDPOINT DISCOVERY</div>')
        st.subheader("Sink 탐색 보고서")
        st.html(f'<p class="report-target"><strong>대상 URL</strong>'
                f'{escape(str(st.session_state["scan_target_url"]))}</p>')
        st.caption(f"발견한 엔드포인트 {len(sinks)}개 → OpenAI 전달 그룹 {len(groups)}개")
        if "sink_json_path" in st.session_state:
            st.caption(f"JSON 파일: output/{Path(st.session_state['sink_json_path']).name}")
        tool_count = len({tool for group in groups for tool in group["candidate_tools"]})
        for column, label, count, color in zip(
            st.columns(3), ("발견한 엔드포인트", "검사 대상 그룹", "검사 유형"),
            (len(sinks), len(groups), tool_count), ("blue", "green", "gray"),
        ):
            with column:
                st.html(f'<div class="scan-stat {color}"><div>{label}</div><strong>{count}<small>개</small></strong></div>')
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
        with st.container(border=True, key="sink_results"):
            st.html('<div class="scan-card-heading">발견한 입력 지점</div>')
            st.dataframe(rows, hide_index=True, width="stretch")

        # 뒤로가기는 왼쪽, 취약점 분석하기는 오른쪽 끝에 배치
        with st.container(horizontal=True, horizontal_alignment="distribute"):
            st.button("뒤로가기", on_click=show_setup_screen)
            st.button(
                "취약점 분석하기", disabled=not groups, type="primary",
                icon=":material/security:", on_click=start_analysis_screen,
            )

else:
    analysis_title = st.empty()
    if "analysis_result" not in st.session_state:
        st.html('<div class="analysis-page-heading"><div class="page-eyebrow">SECURITY ANALYSIS</div>'
                '<div class="page-heading">취약점 분석 중</div>'
                f'<p class="report-target"><strong>대상 URL</strong>{escape(str(st.session_state["scan_target_url"]))}</p></div>')
    # AI 요청과 임시 tool 처리의 진행 상태를 표시
    if st.session_state.pop("analysis_pending", False):
        loading_panel = st.empty()
        render_analysis_loading(loading_panel, "발견한 입력 지점을 분류하고 있습니다…")
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
                on_progress=lambda message: render_analysis_loading(loading_panel, message),
            )
            final_report = report_writer.build_scan_report(
                st.session_state["scan_target_url"], report,
            )
            report["json_path"] = str(report_writer.save_scan_report(
                final_report, st.session_state["scan_target_url"],
            ))
        except (ValueError, OSError, OpenAIError) as exc:
            loading_panel.empty()
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
            st.session_state["dashboard_pending"] = True

    if "analysis_error" in st.session_state:
        analysis_title.subheader("취약점 분석 실패")
        st.error(st.session_state["analysis_error"])
    # 저장된 분석 결과를 재사용하고, 같은 디렉터리에 병합될 대시보드를 실행한다.
    if "analysis_result" in st.session_state:
        analysis_title.empty()
        if st.session_state.get("dashboard_pending", False):
            st.session_state.pop("dashboard_pending")
            st.rerun()
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
        st.button("뒤로가기", on_click=show_sink_report_screen)
        if "analysis_result" not in st.session_state:
            st.button("다시 시도", on_click=retry_analysis)
