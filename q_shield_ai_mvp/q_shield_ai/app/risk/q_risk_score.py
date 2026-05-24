from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

import pandas as pd


def _norm(value: Any) -> str:
    return str(value).strip().lower()


def _bool(value: Any) -> bool:
    return _norm(value) in {"true", "1", "yes", "y"}


def risk_score(record: Dict[str, Any]) -> int:
    score = 0
    algo = _norm(record.get("public_key_algorithm", ""))
    q_vulnerable = record.get("q_vulnerable")
    if q_vulnerable is True or _bool(q_vulnerable) or algo in {"rsa", "ecdsa", "dsa"}:
        score += 30
    if _norm(record.get("exposure")) == "external":
        score += 20

    sensitivity = _norm(record.get("data_sensitivity"))
    score += {"high": 20, "medium": 12, "low": 5}.get(sensitivity, 8)

    try:
        days = int(float(record.get("days_to_expiry", 9999)))
    except Exception:
        days = 9999
    if days <= 30:
        score += 10
    elif days <= 90:
        score += 6
    elif days >= 365 and (algo in {"rsa", "ecdsa", "dsa"}):
        score += 4

    criticality = _norm(record.get("business_criticality"))
    score += {"high": 10, "medium": 6, "low": 3}.get(criticality, 5)

    if _bool(record.get("legacy_flag", False)):
        score += 10

    if "WEAK_SIGNATURE_SHA1" in record.get("reason_codes", []):
        score += 8

    if record.get("scan_status") == "failed":
        score += 5

    return max(0, min(100, int(score)))


def risk_level(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def remediation_sla(level: str) -> str:
    return {
        "Critical": "즉시 임시잠금 또는 변경통제 등록 후 7일 내 전환계획 확정",
        "High": "30일 내 PQC 전환 영향도 분석 및 교체 일정 확정",
        "Medium": "90일 내 암호자산 인벤토리 보강 및 벤더 호환성 확인",
        "Low": "정기 점검 주기에 포함하고 만료일 기준 재평가",
    }.get(level, "재평가 필요")


def score_records(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for rec in records:
        scored = dict(rec)
        s = risk_score(scored)
        lvl = risk_level(s)
        scored["q_risk_score"] = s
        scored["risk_level"] = lvl
        scored["remediation_sla"] = remediation_sla(lvl)
        output.append(scored)
    output.sort(key=lambda r: (r["q_risk_score"], _norm(r.get("exposure")) == "external"), reverse=True)
    return output


def load_json(path: str | Path) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("scan result JSON must be a list")
    return data


def save_csv(records: List[Dict[str, Any]], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(records).to_csv(path, index=False, encoding="utf-8-sig")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Q-Shield AI Q-Risk score engine")
    parser.add_argument("--scan", default="data/offline_scan_results.json")
    parser.add_argument("--out", default="reports/q_risk_results.csv")
    args = parser.parse_args()
    records = load_json(args.scan)
    scored = score_records(records)
    save_csv(scored, args.out)
    print(f"Saved {len(scored)} scored records to {args.out}")


if __name__ == "__main__":
    main()
