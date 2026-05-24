from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from app.ai.recommendation_engine import add_recommendations
from app.risk.q_risk_score import load_json, score_records


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def generate_markdown(records: List[Dict[str, Any]]) -> str:
    records = add_recommendations(score_records(records))
    df = pd.DataFrame(records)
    total = len(df)
    crit = int((df["risk_level"] == "Critical").sum()) if total else 0
    high = int((df["risk_level"] == "High").sum()) if total else 0
    avg = float(df["q_risk_score"].mean()) if total else 0.0
    top_cols = ["asset_id", "hostname", "exposure", "public_key_algorithm", "days_to_expiry", "q_risk_score", "risk_level"]
    top_md = df[top_cols].head(10).to_markdown(index=False) if total else "데이터 없음"

    rec_md = "\n".join([f"- **{r.get('hostname')}**: {r.get('recommendation')}" for r in records[:10]])

    body = f"""# Q-Shield AI Report

## Executive Summary

🧭 총 {total}개 암호자산 중 Critical {crit}개, High {high}개입니다.  
🎯 평균 Q-Risk Score는 {avg:.2f}점입니다.  
♻️ 우선순위는 외부 노출·민감도·RSA/ECC 사용 기준으로 산정했습니다.  

기준시각: {utc_stamp()} = KST 기준 09:00 스냅샷 운영 원칙 적용

## 1. 위험자산 Top 10

{top_md}

## 2. 자동 권고

{rec_md}

## 3. 조치 기준

- Critical: 즉시 임시잠금 또는 변경통제 등록 후 7일 내 전환계획 확정
- High: 30일 내 PQC 전환 영향도 분석 및 교체 일정 확정
- Medium: 90일 내 암호자산 인벤토리 보강 및 벤더 호환성 확인
- Low: 정기 점검 주기에 포함하고 만료일 기준 재평가

## 4. Evidence

- EvidenceID: EVID-QSHIELD-RPT-001
- Owner: token_24
- TTL: 90d
"""
    return body + f"\n- Hash: {_hash_text(body)}\n"


def generate_report_from_json(scan_json: str | Path, output_md: str | Path) -> None:
    records = load_json(scan_json)
    md = generate_markdown(records)
    Path(output_md).parent.mkdir(parents=True, exist_ok=True)
    Path(output_md).write_text(md, encoding="utf-8")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Q-Shield AI report generator")
    parser.add_argument("--scan", default="data/offline_scan_results.json")
    parser.add_argument("--out", default="reports/q_shield_report.md")
    args = parser.parse_args()
    generate_report_from_json(args.scan, args.out)
    print(f"Saved report to {args.out}")


if __name__ == "__main__":
    main()
