"""Optional Streamlit dashboard compatibility entrypoint.

Primary HTML dashboard:
    python run_web.py

Optional Streamlit dashboard:
    streamlit run app/dashboard/streamlit_app.py
"""
from pathlib import Path

import pandas as pd
import streamlit as st

REPORT_PATH = Path("reports/q_risk_results.csv")

st.set_page_config(page_title="Q-Shield AI", layout="wide")
st.title("Q-Shield AI Dashboard")
st.caption("Q-Day 대비 암호자산 위험평가 및 PQC 전환 권고")

if not REPORT_PATH.exists():
    st.warning("먼저 `python -m app.main --mode offline` 명령을 실행해 reports/q_risk_results.csv를 생성하세요.")
    st.stop()

df = pd.read_csv(REPORT_PATH)

col1, col2, col3, col4 = st.columns(4)
col1.metric("전체 자산", len(df))
col2.metric("Critical/High", int(df["risk_level"].isin(["Critical", "High"]).sum()))
col3.metric("평균 Q-Risk", round(float(df["q_risk_score"].mean()), 2))
col4.metric("최고 위험 자산", df.sort_values("q_risk_score", ascending=False).iloc[0]["hostname"])

left, right = st.columns(2)
with left:
    st.subheader("위험등급 분포")
    st.bar_chart(df["risk_level"].value_counts())
with right:
    st.subheader("알고리즘 분포")
    st.bar_chart(df["public_key_algorithm"].fillna("unknown").value_counts())

st.subheader("Top Risk Assets")
st.dataframe(df.sort_values("q_risk_score", ascending=False), use_container_width=True)

st.download_button(
    "CSV 다운로드",
    data=REPORT_PATH.read_bytes(),
    file_name="q_risk_results.csv",
    mime="text/csv",
)
