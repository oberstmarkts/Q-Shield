from __future__ import annotations

import io
from pathlib import Path
import tempfile

from flask import Flask, Response, jsonify, render_template, request, send_file

from app.core.analyzer import analyze_assets, results_to_rows, run_offline
from app.core.io_utils import load_assets_csv, load_scan_results_json, write_csv_rows
from app.core.report import generate_evidence_manifest, generate_markdown_report, write_json_summary


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "reports"


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    REPORTS_DIR.mkdir(exist_ok=True)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/sample")
    def api_sample():
        results = run_offline(DATA_DIR / "sample_assets.csv", DATA_DIR / "offline_scan_results.json", REPORTS_DIR)
        md_path = generate_markdown_report(results, REPORTS_DIR / "q_shield_report.md")
        summary_path = write_json_summary(results, REPORTS_DIR / "q_risk_summary.json")
        generate_evidence_manifest([REPORTS_DIR / "q_risk_results.csv", md_path, summary_path], REPORTS_DIR / "evidence_manifest.csv")
        return jsonify(payload_from_results(results))

    @app.post("/api/analyze")
    def api_analyze():
        if "asset_csv" not in request.files:
            return jsonify({"error": "asset_csv file is required"}), 400

        uploaded = request.files["asset_csv"]
        if not uploaded.filename.lower().endswith(".csv"):
            return jsonify({"error": "CSV file is required"}), 400

        with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".csv") as tmp:
            uploaded.save(tmp.name)
            tmp_path = Path(tmp.name)

        try:
            assets = load_assets_csv(tmp_path)
            scans = load_scan_results_json(DATA_DIR / "offline_scan_results.json")
            results = analyze_assets(assets, scans, scan_mode=False)
            write_csv_rows(REPORTS_DIR / "q_risk_results.csv", results_to_rows(results))
            md_path = generate_markdown_report(results, REPORTS_DIR / "q_shield_report.md")
            summary_path = write_json_summary(results, REPORTS_DIR / "q_risk_summary.json")
            generate_evidence_manifest([REPORTS_DIR / "q_risk_results.csv", md_path, summary_path], REPORTS_DIR / "evidence_manifest.csv")
            return jsonify(payload_from_results(results))
        finally:
            tmp_path.unlink(missing_ok=True)

    @app.get("/download/<kind>")
    def download(kind: str):
        mapping = {
            "csv": REPORTS_DIR / "q_risk_results.csv",
            "report": REPORTS_DIR / "q_shield_report.md",
            "manifest": REPORTS_DIR / "evidence_manifest.csv",
        }
        path = mapping.get(kind)
        if path is None or not path.exists():
            return jsonify({"error": "Run analysis first."}), 404
        return send_file(path, as_attachment=True)

    return app


def payload_from_results(results):
    rows = results_to_rows(results)
    total = len(rows)
    avg = round(sum(r["q_risk_score"] for r in rows) / total, 2) if total else 0
    levels = {level: 0 for level in ["Critical", "High", "Medium", "Low"]}
    algorithms = {}
    for row in rows:
        levels[row["risk_level"]] = levels.get(row["risk_level"], 0) + 1
        alg = row.get("public_key_algorithm") or "unknown"
        algorithms[alg] = algorithms.get(alg, 0) + 1

    return {
        "summary": {
            "total_assets": total,
            "average_score": avg,
            "critical_high": levels.get("Critical", 0) + levels.get("High", 0),
            "top_asset": rows[0]["hostname"] if rows else "",
        },
        "levels": levels,
        "algorithms": algorithms,
        "rows": rows,
    }
