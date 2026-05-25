from __future__ import annotations

import argparse
from pathlib import Path

from app.core.analyzer import RiskDriftLockError, run_offline, run_scan
from app.core.report import generate_evidence_manifest, generate_markdown_report, write_json_summary
from app.core.security_report import generate_security_audit_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Q-Shield AI crypto asset risk analyzer")
    parser.add_argument("--mode", choices=["offline", "scan"], default="offline")
    parser.add_argument("--assets", default="data/sample_assets.csv")
    parser.add_argument("--offline-results", default="data/offline_scan_results.json")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--allow-scan", action="store_true", help="Enable TLS scan for asset rows with allowed_to_scan=true.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    try:
        if args.mode == "offline":
            results = run_offline(args.assets, args.offline_results, reports_dir)
        else:
            if not args.allow_scan:
                print("Scan mode is fail-closed. Add --allow-scan and set allowed_to_scan=true for authorized assets only.")
            results = run_scan(args.assets, reports_dir, timeout=args.timeout, allow_scan=args.allow_scan)
    except RiskDriftLockError as exc:
        print(f"Q-Shield AI halted (temporary lock): {exc}")
        print(f"Review RCA entries in {reports_dir / 'q_risk_snapshot.json'}, then delete that file to reset the baseline after remediation.")
        return 2

    csv_path = reports_dir / "q_risk_results.csv"
    md_path = generate_markdown_report(results, reports_dir / "q_shield_report.md")
    summary_path = write_json_summary(results, reports_dir / "q_risk_summary.json")
    security_report_path = generate_security_audit_report(reports_dir / "security_audit_report.md", reports_dir / "security_audit_log.jsonl")
    manifest_path = generate_evidence_manifest([csv_path, md_path, summary_path, security_report_path], reports_dir / "evidence_manifest.csv")

    print(f"Q-Shield AI completed. Assets={len(results)}")
    print(f"CSV: {csv_path}")
    print(f"Report: {md_path}")
    print(f"Summary: {summary_path}")
    print(f"Security audit report: {security_report_path}")
    print(f"Evidence manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
