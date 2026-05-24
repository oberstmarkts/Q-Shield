from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from app.ai.recommendation_engine import add_recommendations
from app.risk.q_risk_score import score_records

st.set_page_config(page_title="Q-Shield AI", layout="wide")
st.title("Q-Shield AI: Q-Day Readiness Dashboard")
st.caption("AI 기반 암호자산 탐지 · Q-Risk Score · PQC 전환 우선순위")

sample_path = Path("data/offline_scan_results.json")
uploaded = st.file_uploader("scan_results.json 업로드", type=["json"])

if uploaded:
    records = json.loads(uploaded.read().decode("utf-8"))
else:
    records = json.loads(sample_path.read_text(encoding="utf-8"))

records = add_recommendations(score_records(records))
df = pd.DataFrame(records)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Assets", len(df))
col2.metric("Critical", int((df["risk_level"] == "Critical").sum()))
col3.metric("High", int((df["risk_level"] == "High").sum()))
col4.metric("Avg Q-Risk", f"{df['q_risk_score'].mean():.2f}")

st.divider()

left, right = st.columns([1, 2])
with left:
    level_filter = st.multiselect("Risk Level", options=["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
    exposure_filter = st.multiselect("Exposure", options=sorted(df["exposure"].dropna().unique()), default=sorted(df["exposure"].dropna().unique()))
    filtered = df[df["risk_level"].isin(level_filter) & df["exposure"].isin(exposure_filter)]
    st.subheader("Risk Level Distribution")
    st.bar_chart(filtered["risk_level"].value_counts())
    st.subheader("Algorithm Distribution")
    st.bar_chart(filtered["public_key_algorithm"].fillna("UNKNOWN").value_counts())

with right:
    st.subheader("Top Risk Assets")
    show_cols = ["asset_id", "hostname", "exposure", "public_key_algorithm", "days_to_expiry", "q_risk_score", "risk_level", "remediation_sla"]
    st.dataframe(filtered[show_cols].sort_values("q_risk_score", ascending=False), use_container_width=True)

st.subheader("AI Recommendations")
for _, row in filtered.sort_values("q_risk_score", ascending=False).head(10).iterrows():
    with st.expander(f"{row['hostname']} / {row['q_risk_score']} / {row['risk_level']}"):
        st.write(row["recommendation"])

csv = filtered.to_csv(index=False, encoding="utf-8-sig")
st.download_button("Download Q-Risk CSV", data=csv, file_name="q_risk_results.csv", mime="text/csv")
