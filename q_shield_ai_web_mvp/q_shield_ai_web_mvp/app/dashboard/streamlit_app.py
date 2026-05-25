"""Streamlit 대시보드 — Flask 웹 대시보드(app/web)와 동일 기능.

Primary HTML dashboard:
    python run_web.py

Optional Streamlit dashboard:
    streamlit run app/dashboard/streamlit_app.py

Flask 대시보드와 동일하게 KPI 4개, 색상 구분 차트 2개, 위험 자산 테이블,
자산 선택 시 상세 권고 패널(위험 코드 태그, 권고문, DoD), CSV/Markdown 다운로드를
제공한다. 데이터 소스는 동일한 오프라인 샘플 분석 파이프라인을 사용한다.
"""
from __future__ import annotations

import html
import sys
from pathlib import Path

# `streamlit run app/dashboard/streamlit_app.py` 로 실행해도 app 패키지를
# 임포트할 수 있도록 프로젝트 루트를 sys.path 에 추가한다.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import altair as alt
import pandas as pd
import streamlit as st

from app.core.analyzer import RiskDriftLockError, results_to_rows, run_offline
from app.core.report import generate_markdown_report

DATA_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "reports"
CSV_PATH = REPORTS_DIR / "q_risk_results.csv"
REPORT_PATH = REPORTS_DIR / "q_shield_report.md"

# Flask 대시보드(app.js / styles.css)와 동일한 위험등급 레이블·색상 체계
LEVEL_ORDER = ["Critical", "High", "Medium", "Low"]
LEVEL_LABELS = {"Critical": "심각", "High": "높음", "Medium": "보통", "Low": "낮음"}
LEVEL_COLORS = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#d97706", "Low": "#16a34a"}
PRIMARY = "#2563eb"

DETAIL_CSS = """
<style>
.qs-detail-head { display:flex; align-items:center; gap:.75rem; flex-wrap:wrap;
  padding-bottom:.6rem; border-bottom:1px solid #e5e7eb; margin-bottom:.8rem; }
.qs-host { font-family:ui-monospace, monospace; font-size:1.05rem; font-weight:700; color:#1a1f36; }
.qs-badge { display:inline-block; padding:.28rem .6rem; border-radius:999px;
  font-weight:700; font-size:.8rem; border:1px solid transparent; }
.qs-badge.Critical { background:#fef2f2; color:#dc2626; border-color:#fecaca; }
.qs-badge.High { background:#fff7ed; color:#ea580c; border-color:#fed7aa; }
.qs-badge.Medium { background:#fffbeb; color:#d97706; border-color:#fde68a; }
.qs-badge.Low { background:#f0fdf4; color:#16a34a; border-color:#bbf7d0; }
.qs-metric-grid { display:grid; grid-template-columns:repeat(3, minmax(0,1fr));
  gap:.6rem; margin:.2rem 0 1rem; }
.qs-metric { background:#ffffff; border:1px solid #e5e7eb; border-radius:.6rem; padding:.7rem .85rem; }
.qs-metric .label { color:#6b7280; font-size:.72rem; font-weight:700; display:block; margin-bottom:.25rem; }
.qs-metric .value { font-family:ui-monospace, monospace; font-size:.95rem; font-weight:600;
  color:#1a1f36; word-break:break-word; }
.qs-block-title { font-size:.95rem; font-weight:700; color:#1a1f36; margin:.6rem 0 .4rem; }
.qs-chip { display:inline-flex; align-items:center; margin:0 .4rem .4rem 0; padding:.3rem .65rem;
  border-radius:999px; background:#eff6ff; border:1px solid #bfdbfe; color:#1d4ed8;
  font-family:ui-monospace, monospace; font-size:.78rem; font-weight:500; }
.qs-rec { background:#ffffff; border:1px solid #e5e7eb; border-left:3px solid #2563eb;
  border-radius:.5rem; padding:.7rem .9rem; color:#1a1f36; font-size:.9rem; line-height:1.6;
  word-break:break-word; }
.qs-rec.dod { border-left-color:#16a34a; }
.qs-muted { color:#6b7280; }
</style>
"""


@st.cache_data(show_spinner=False)
def load_analysis() -> list[dict]:
    """오프라인 샘플 분석을 실행해 CSV·Markdown 리포트를 생성하고 행 목록을 반환한다.

    Flask `/api/sample` 와 동일하게 q_risk_results.csv 와 q_shield_report.md 를 갱신한다.
    위험점수 내림차순으로 정렬된 dict 목록을 반환한다(reason_codes 는 ';' 결합 문자열).
    """
    results = run_offline(
        DATA_DIR / "sample_assets.csv",
        DATA_DIR / "offline_scan_results.json",
        REPORTS_DIR,
    )
    generate_markdown_report(results, REPORT_PATH)
    return results_to_rows(results)


def level_label(level: str) -> str:
    return LEVEL_LABELS.get(level, level or "낮음")


def split_reason_codes(raw: object) -> list[str]:
    return [token.strip() for token in str(raw or "").split(";") if token.strip()]


def render_level_chart(df: pd.DataFrame) -> None:
    """위험등급 분포 — 등급별 색상으로 구분한 막대 차트(0건 등급도 표시)."""
    counts = df["risk_level"].value_counts().to_dict()
    chart_df = pd.DataFrame(
        {
            "등급": [level_label(level) for level in LEVEL_ORDER],
            "level": LEVEL_ORDER,
            "건수": [int(counts.get(level, 0)) for level in LEVEL_ORDER],
        }
    ).reset_index(drop=True)
    max_count = max(int(chart_df["건수"].max()), 1)
    chart = (
        alt.Chart(chart_df)
        .mark_bar(cornerRadiusEnd=4, height=22)
        .encode(
            x=alt.X(
                "건수:Q",
                title=None,
                axis=alt.Axis(tickCount=max_count, format="d"),
            ),
            y=alt.Y("등급:N", sort=[level_label(l) for l in LEVEL_ORDER], title=None),
            color=alt.Color(
                "level:N",
                scale=alt.Scale(domain=LEVEL_ORDER, range=[LEVEL_COLORS[l] for l in LEVEL_ORDER]),
                legend=None,
            ),
            tooltip=[alt.Tooltip("등급:N"), alt.Tooltip("건수:Q")],
        )
        .properties(height=220)
    )
    st.altair_chart(chart, use_container_width=True)


def render_algorithm_chart(df: pd.DataFrame) -> None:
    """공개키 알고리즘 분포 — 단일 색상(프라이머리) 막대 차트."""
    series = df["public_key_algorithm"].fillna("unknown").replace("", "unknown")
    chart_df = (
        series.value_counts().rename_axis("알고리즘").reset_index(name="건수").reset_index(drop=True)
    )
    max_count = max(int(chart_df["건수"].max()), 1)
    chart = (
        alt.Chart(chart_df)
        .mark_bar(color=PRIMARY, cornerRadiusEnd=4, height=22)
        .encode(
            x=alt.X(
                "건수:Q",
                title=None,
                axis=alt.Axis(tickCount=max_count, format="d"),
            ),
            y=alt.Y("알고리즘:N", sort="-x", title=None),
            tooltip=[alt.Tooltip("알고리즘:N"), alt.Tooltip("건수:Q")],
        )
        .properties(height=220)
    )
    st.altair_chart(chart, use_container_width=True)


def render_detail(row: dict) -> None:
    """선택 자산 상세 권고 패널 — 위험 코드 태그, 권고문, DoD (Flask 상세 패널과 동일)."""
    level = row.get("risk_level", "")
    badge_class = level if level in LEVEL_LABELS else "Low"

    def days_text() -> str:
        value = row.get("days_to_expiry")
        if value is None or (isinstance(value, float) and pd.isna(value)):
            return "unknown"
        return f"{int(value)}일"

    metrics = [
        ("Q-Risk 점수", row.get("q_risk_score", "")),
        ("위험 등급", f"{level_label(level)} ({level})"),
        ("공개키 알고리즘", row.get("public_key_algorithm") or "unknown"),
        ("TLS 버전", row.get("tls_version") or "n/a"),
        ("인증서 만료", days_text()),
        ("Evidence ID", row.get("evidence_id") or "-"),
    ]
    metric_html = "".join(
        f'<div class="qs-metric"><span class="label">{html.escape(label)}</span>'
        f'<span class="value">{html.escape(str(value))}</span></div>'
        for label, value in metrics
    )

    codes = split_reason_codes(row.get("reason_codes"))
    if codes:
        chips_html = "".join(f'<span class="qs-chip">{html.escape(code)}</span>' for code in codes)
    else:
        chips_html = '<span class="qs-muted">식별된 위험 코드가 없습니다.</span>'

    recommendation = html.escape(row.get("recommendation") or "권고 사항이 없습니다.")
    dod = html.escape(row.get("dod") or "정의된 완료 기준이 없습니다.")
    header = f"{html.escape(str(row.get('asset_id', '')))} · {html.escape(str(row.get('hostname', '')))}"

    st.markdown(
        DETAIL_CSS
        + f"""
<div class="qs-detail-head">
  <span class="qs-host">{header}</span>
  <span class="qs-badge {badge_class}">{html.escape(level_label(level))}</span>
</div>
<div class="qs-metric-grid">{metric_html}</div>
<div class="qs-block-title">위험 코드</div>
<div>{chips_html}</div>
<div class="qs-block-title">권고 사항</div>
<div class="qs-rec">{recommendation}</div>
<div class="qs-block-title">완료 정의 (DoD)</div>
<div class="qs-rec dod">{dod}</div>
""",
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(page_title="Q-Shield AI", layout="wide")
    st.title("Q-Shield AI Dashboard")
    st.caption(
        "Q-Day 대비 암호자산 위험평가 및 PQC 전환 권고 · "
        "운영 원칙: 허가된 자산만 스캔 · 민감정보 저장 금지 · Fail-Closed 기본 동작 · 소유자 token_24"
    )

    if st.button("샘플 분석 실행", type="primary"):
        load_analysis.clear()
        st.rerun()

    try:
        rows = load_analysis()
    except RiskDriftLockError as exc:  # ±5% 드리프트 → 임시잠금: 리포트 생성 중단
        st.error("⚠️ 위험 지표 급변 감지 — 리포트 생성이 임시 잠금되었습니다.")
        for b in exc.breaches:
            st.warning(
                f"{b['label']}: {b['previous']} → {b['current']} "
                f"({b['delta_pct']}% 변화, 임계값 ±{b['threshold_pct']}%)"
            )
        st.info("reports/q_risk_snapshot.json 의 RCA 항목을 검토한 뒤, 조치 후 해당 파일을 삭제하면 기준선이 초기화됩니다.")
        st.stop()
    except Exception as exc:  # 데이터 소스 누락 등은 사용자에게 안내 후 중단
        st.error(f"분석을 실행할 수 없습니다: {exc.__class__.__name__}")
        st.info("data/sample_assets.csv 와 data/offline_scan_results.json 이 존재하는지 확인하세요.")
        st.stop()

    if not rows:
        st.warning("분석 결과가 없습니다.")
        st.stop()

    df = pd.DataFrame(rows)

    # ---------- KPI 4개 ----------
    total = len(df)
    critical_high = int(df["risk_level"].isin(["Critical", "High"]).sum())
    avg_score = round(float(df["q_risk_score"].mean()), 2)
    top_asset = df.iloc[0]["hostname"]  # run_offline 결과는 위험점수 내림차순 정렬

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("전체 자산", total, help="분석 대상 암호자산 수")
    k2.metric("Critical / High", critical_high, help="즉시 대응 필요 자산")
    k3.metric("평균 Q-Risk 점수", avg_score, help="전체 자산 평균 위험점수")
    k4.metric("최고 위험 자산", top_asset, help="위험점수 최상위 호스트")

    # ---------- 색상 구분 차트 2개 ----------
    c_left, c_right = st.columns(2)
    with c_left:
        st.subheader("위험등급 분포")
        render_level_chart(df)
    with c_right:
        st.subheader("공개키 알고리즘 분포")
        render_algorithm_chart(df)

    # ---------- 위험 자산 목록(테이블) ----------
    st.subheader("위험 자산 목록")
    st.caption("위험점수 상위 자산부터 정렬됩니다. 행을 선택하면 하단에서 상세 권고를 확인할 수 있습니다.")

    table_df = pd.DataFrame(
        {
            "자산 ID": df["asset_id"],
            "호스트명": df["hostname"],
            "점수": df["q_risk_score"],
            "등급": df["risk_level"].map(level_label),
            "알고리즘": df["public_key_algorithm"].fillna("unknown").replace("", "unknown"),
            "노출": df["exposure"].fillna(""),
            "조치 기한": df["action_due"],
        }
    )
    event = st.dataframe(
        table_df,
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
    )

    # 선택이 없으면 Flask 대시보드처럼 최상위(최고 위험) 자산을 기본 선택
    selected = list(getattr(event.selection, "rows", []) or []) if event else []
    selected_index = selected[0] if selected else 0

    # ---------- 선택 자산 상세 권고 패널 ----------
    st.subheader("선택 자산 상세 권고")
    render_detail(rows[selected_index])

    # ---------- 다운로드 버튼 (CSV / Markdown) ----------
    st.subheader("결과 다운로드")
    d_csv, d_md = st.columns(2)
    if CSV_PATH.exists():
        d_csv.download_button(
            "CSV 다운로드",
            data=CSV_PATH.read_bytes(),
            file_name="q_risk_results.csv",
            mime="text/csv",
            use_container_width=True,
        )
    else:
        d_csv.button("CSV 다운로드", disabled=True, use_container_width=True)

    if REPORT_PATH.exists():
        d_md.download_button(
            "Markdown 리포트 다운로드",
            data=REPORT_PATH.read_bytes(),
            file_name="q_shield_report.md",
            mime="text/markdown",
            use_container_width=True,
        )
    else:
        d_md.button("Markdown 리포트 다운로드", disabled=True, use_container_width=True)


main()
