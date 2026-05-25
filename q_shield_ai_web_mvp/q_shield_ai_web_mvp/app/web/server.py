from __future__ import annotations

from pathlib import Path
import tempfile

from flask import Flask, jsonify, render_template, request, send_file

from app.core.analyzer import RiskDriftLockError, analyze_assets, results_to_rows, run_offline
from app.core.dlp import DLPViolation
from app.core.io_utils import load_assets_csv, load_scan_results_json, write_csv_rows
from app.core.report import generate_evidence_manifest, generate_markdown_report, write_json_summary
from app.core.security import (
    DEFAULT_MAX_ASSETS,
    DEFAULT_MAX_UPLOAD_BYTES,
    SecurityValidationError,
    append_audit_event,
    sanitize_error,
    validate_and_write_upload,
)
from app.core.security_report import generate_security_audit_report


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "reports"


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["MAX_CONTENT_LENGTH"] = DEFAULT_MAX_UPLOAD_BYTES
    app.config["JSON_AS_ASCII"] = False
    REPORTS_DIR.mkdir(exist_ok=True)

    @app.after_request
    def apply_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify({"error": f"Upload blocked. Cause=file_too_large; DoD=CSV must be <= {DEFAULT_MAX_UPLOAD_BYTES} bytes."}), 413

    @app.errorhandler(SecurityValidationError)
    def security_validation(error):
        append_audit_event({"event": "request_blocked", "reason": sanitize_error(error)})
        return jsonify({"error": sanitize_error(error)}), 400

    @app.errorhandler(DLPViolation)
    def dlp_violation(error):
        append_audit_event({"event": "dlp_blocked", "reason": sanitize_error(error)})
        return jsonify({"error": sanitize_error(error)}), 400

    @app.errorhandler(RiskDriftLockError)
    def drift_locked(error):
        breaches = getattr(error, "breaches", [])
        append_audit_event({"event": "drift_lock", "breach_count": len(breaches)})
        return jsonify({"error": str(error), "breaches": breaches, "status": "locked"}), 423

    @app.errorhandler(Exception)
    def unhandled_error(error):
        append_audit_event({"event": "server_error", "reason": error.__class__.__name__})
        return jsonify({"error": "Request failed. Cause=server_error; Action=check reports/security_audit_log.jsonl; DoD=rerun after remediation."}), 500

    @app.get("/")
    def index():
        return render_template("index.html", max_upload_mb=DEFAULT_MAX_UPLOAD_BYTES // 1024 // 1024, max_assets=DEFAULT_MAX_ASSETS)

    @app.get("/api/sample")
    def api_sample():
        results = run_offline(DATA_DIR / "sample_assets.csv", DATA_DIR / "offline_scan_results.json", REPORTS_DIR)
        md_path = generate_markdown_report(results, REPORTS_DIR / "q_shield_report.md")
        summary_path = write_json_summary(results, REPORTS_DIR / "q_risk_summary.json")
        security_report_path = generate_security_audit_report(REPORTS_DIR / "security_audit_report.md", REPORTS_DIR / "security_audit_log.jsonl")
        generate_evidence_manifest([REPORTS_DIR / "q_risk_results.csv", md_path, summary_path, security_report_path], REPORTS_DIR / "evidence_manifest.csv")
        append_audit_event({"event": "sample_analysis", "asset_count": len(results)})
        return jsonify(payload_from_results(results))

    @app.post("/api/analyze")
    def api_analyze():
        if "asset_csv" not in request.files:
            return jsonify({"error": "asset_csv file is required"}), 400

        uploaded = request.files["asset_csv"]
        filename = uploaded.filename or ""
        if not filename.lower().endswith(".csv"):
            return jsonify({"error": "CSV file is required"}), 400

        data = uploaded.read()
        with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".csv") as tmp:
            tmp_path = Path(tmp.name)

        try:
            meta = validate_and_write_upload(data, tmp_path)
            assets = load_assets_csv(tmp_path)
            scans = load_scan_results_json(DATA_DIR / "offline_scan_results.json")
            results = analyze_assets(assets, scans, scan_mode=False)
            write_csv_rows(REPORTS_DIR / "q_risk_results.csv", results_to_rows(results))
            md_path = generate_markdown_report(results, REPORTS_DIR / "q_shield_report.md")
            summary_path = write_json_summary(results, REPORTS_DIR / "q_risk_summary.json")
            security_report_path = generate_security_audit_report(REPORTS_DIR / "security_audit_report.md", REPORTS_DIR / "security_audit_log.jsonl")
            generate_evidence_manifest([REPORTS_DIR / "q_risk_results.csv", md_path, summary_path, security_report_path], REPORTS_DIR / "evidence_manifest.csv")
            append_audit_event({"event": "csv_upload_analysis", "sha256": meta["sha256"], "size_bytes": meta["size_bytes"], "asset_count": meta["asset_count"]})
            return jsonify(payload_from_results(results))
        finally:
            tmp_path.unlink(missing_ok=True)

    @app.get("/download/<kind>")
    def download(kind: str):
        mapping = {
            "csv": REPORTS_DIR / "q_risk_results.csv",
            "report": REPORTS_DIR / "q_shield_report.md",
            "manifest": REPORTS_DIR / "evidence_manifest.csv",
            "security": REPORTS_DIR / "security_audit_report.md",
        }
        path = mapping.get(kind)
        if path is None or not path.exists():
            return jsonify({"error": "Run analysis first."}), 404
        append_audit_event({"event": "download", "kind": kind})
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
