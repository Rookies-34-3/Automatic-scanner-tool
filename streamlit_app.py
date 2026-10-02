'''
실행 : python.exe -m streamlit run streamlit_app.py
ROOKIESCAN 도구 실행 및 보고서 출력하는 streamlit 기반 웹
'''

import streamlit as st
from sink_finder import find_sinks

# target_url이랑 session_cookie받아오기
st.title("ROOKIESCAN")
target_url = st.text_input("대상 URL")
session_cookie = st.text_input("세션 쿠키", type="password")


#이제 sink 찾아야함 sink_finder
if st.button("Sink 찾기"):
    with st.spinner("입력 지점을 찾는 중입니다."):
        sinks = find_sinks(target_url, session_cookie)

    st.session_state["sinks"] = sinks

