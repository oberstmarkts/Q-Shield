from __future__ import annotations

import argparse
from pathlib import Path

from app.scanner.tls_scanner import scan_assets_csv, save_json
from app.risk.q_risk_score import load_json, save_csv, score_records
from app.ai.recommendation_engine import add_recommendations
from app.report.report_generator import generate_report_from_json


def run_offline() -> None:
    scan_path = Path("data/offline_scan_results.json")
    scored_path = Path("reports/q_risk_results.csv")
    report_path = Path("reports/q_shield_report.md")
    records = add_recommendations(score_records(load_json(scan_path)))
    save_csv(records, scored_path)
    generate_report_from_json(scan_path, report_path)
    print(f"Offline MVP complete: {scored_path}, {report_path}")


def run_scan(assets: str, timeout: float) -> None:
    scan_path = Path("reports/scan_results.json")
    scored_path = Path("reports/q_risk_results.csv")
    report_path = Path("reports/q_shield_report.md")
    records = scan_assets_csv(assets, timeout=timeout)
    save_json(records, scan_path)
    scored = add_recommendations(score_records(records))
    save_csv(scored, scored_path)
    generate_report_from_json(scan_path, report_path)
    print(f"Scan MVP complete: {scan_path}, {scored_path}, {report_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Q-Shield AI working MVP")
    parser.add_argument("--mode", choices=["offline", "scan"], default="offline")
    parser.add_argument("--assets", default="data/sample_assets.csv")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    if args.mode == "offline":
        run_offline()
    else:
        run_scan(args.assets, args.timeout)


if __name__ == "__main__":
    main()
