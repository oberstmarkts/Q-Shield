from pathlib import Path
from app.core.analyzer import run_offline
from app.core.report import generate_markdown_report, generate_evidence_manifest


def test_offline_generates_results(tmp_path):
    results = run_offline("data/sample_assets.csv", "data/offline_scan_results.json", tmp_path)
    assert len(results) == 4
    assert (tmp_path / "q_risk_results.csv").exists()
    md = generate_markdown_report(results, tmp_path / "q_shield_report.md")
    manifest = generate_evidence_manifest([tmp_path / "q_risk_results.csv", md], tmp_path / "evidence_manifest.csv")
    assert md.exists()
    assert manifest.exists()
    assert "Q-Shield AI Q-Risk Report" in md.read_text(encoding="utf-8")
