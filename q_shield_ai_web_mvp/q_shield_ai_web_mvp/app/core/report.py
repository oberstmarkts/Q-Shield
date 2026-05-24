from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

from .dlp import assert_no_sensitive_text
from .models import RiskResult


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_markdown_report(results: list[RiskResult], output_path: str | Path = "reports/q_shield_report.md") -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    counts = Counter(r.risk_level for r in results)
    total = len(results)
    avg = sum(r.q_risk_score for r in results) / total if total else 0.0

    lines = [
        "# Q-Shield AI Q-Risk Report",
        "",
        f"Snapshot: {now}",
        "Owner: token_24",
        "TTL: 90d",
        "EvidenceID: EVID-QSHIELD-MVP-001",
        "",
        "## Executive Summary",
        "",
        f"- Total assets analyzed: {total}",
        f"- Critical/High assets: {counts.get('Critical', 0) + counts.get('High', 0)}",
        f"- Average Q-Risk Score: {avg:.2f}",
        "",
        "## Risk Distribution",
        "",
        "| Level | Count |",
        "|---|---:|",
    ]
    for level in ["Critical", "High", "Medium", "Low"]:
        lines.append(f"| {level} | {counts.get(level, 0)} |")

    lines.extend([
        "",
        "## Top Risk Assets",
        "",
        "| Rank | Asset | Hostname | Score | Level | Algorithm | Due |",
        "|---:|---|---|---:|---|---|---|",
    ])
    for idx, r in enumerate(results[:10], start=1):
        alg = r.extra.get("public_key_algorithm", "unknown")
        lines.append(
            f"| {idx} | {r.asset_id} | `{r.hostname}` | {r.q_risk_score} | {r.risk_level} | {alg} | {r.action_due} |"
        )

    lines.extend(["", "## Asset Recommendations", ""])
    for r in results:
        lines.extend([
            f"### {r.asset_id} - {r.hostname}",
            "",
            f"- Score: {r.q_risk_score}",
            f"- Level: {r.risk_level}",
            f"- Reason codes: `{', '.join(r.reason_codes)}`",
            f"- Recommendation: {r.recommendation}",
            f"- DoD: {r.dod}",
            "",
        ])

    lines.extend([
        "## 운영 원칙",
        "",
        "- 소유하거나 명시적으로 승인된 자산만 스캔합니다.",
        "- 실제 비밀값, API 키, 개인 키, 개인정보를 저장하지 않습니다.",
        "- 안정적인 시연을 위해 오프라인 샘플 데이터를 사용합니다.",
        "- 민감 데이터가 발견되면 보고서 게시를 중단하고 조치 후 다시 실행합니다.",
        "",
    ])

    content = "\n".join(lines)
    assert_no_sensitive_text(content)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def generate_evidence_manifest(paths: list[str | Path], output_path: str | Path = "reports/evidence_manifest.csv") -> Path:
    import csv

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for path in paths:
        path = Path(path)
        if not path.exists():
            continue
        rows.append({
            "EvidenceID": f"EVID-QSHIELD-{path.stem.upper()}",
            "PointerID": "SRC-05",
            "File": str(path).replace("\\", "/"),
            "Hash": "sha256:" + sha256_file(path),
            "Owner": "token_24",
            "TTL": "90d",
            "DoD": "file exists and hash calculated",
        })
    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["EvidenceID","PointerID","File","Hash","Owner","TTL","DoD"])
        w.writeheader()
        w.writerows(rows)
    return output_path


def write_json_summary(results: list[RiskResult], output_path: str | Path = "reports/q_risk_summary.json") -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "total_assets": len(results),
        "average_score": round(sum(r.q_risk_score for r in results) / len(results), 2) if results else 0,
        "risk_distribution": dict(Counter(r.risk_level for r in results)),
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return output_path
