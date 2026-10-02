import streamlit as st

st.title("ROOKIESCAN")
target_url = st.text_input("대상 URL")
session_cookie = st.text_input("세션 쿠키", type="password")
