from __future__ import annotations

import json
from pathlib import Path

from .security import sha256_bytes, utc_now_iso


def generate_security_audit_report(
    output_path: str | Path = "reports/security_audit_report.md",
    audit_log_path: str | Path = "reports/security_audit_log.jsonl",
) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    audit_log_path = Path(audit_log_path)
    events = []
    if audit_log_path.exists():
        for line in audit_log_path.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    lines = [
        "# Q-Shield AI Security Audit Report",
        "",
        f"Snapshot: {utc_now_iso()}",
        "Owner: token_24",
        "TTL: 90d",
        "",
        "## Applied Security Controls",
        "",
        "| Control | Status | Evidence |",
        "|---|---|---|",
        "| DLP fail-closed | Enabled | app/core/dlp.py |",
        "| CSV upload size limit | Enabled | app/core/security.py |",
        "| Asset count limit | Enabled | app/core/security.py |",
        "| Asset field validation | Enabled | app/core/security.py |",
        "| Scan authorization gate | Enabled | --allow-scan + allowed_to_scan=true |",
        "| Private/loopback scan guard | Enabled | QSHIELD_ALLOW_PRIVATE_SCAN required |",
        "| CSV formula injection mitigation | Enabled | app/core/io_utils.py |",
        "| Web security headers | Enabled | app/web/server.py |",
        "| DOM XSS mitigation | Enabled | app/web/static/app.js textContent rendering |",
        "| Download path allowlist | Enabled | /download/<kind> mapping only |",
        "| Audit log | Enabled | reports/security_audit_log.jsonl |",
        "",
        "## Audit Events",
        "",
    ]
    if events:
        lines.extend(["| Time | Event | Asset | Status/Reason |", "|---|---|---|---|"])
        for event in events[-50:]:
            lines.append(
                f"| {event.get('timestamp_utc', '')} | {event.get('event', '')} | "
                f"{event.get('asset_id', '')} | {event.get('scan_status') or event.get('reason') or event.get('sha256','')} |"
            )
    else:
        lines.append("No scan/upload audit events recorded yet.")

    content = "\n".join(lines) + "\n"
    digest = sha256_bytes(content.encode("utf-8"))
    content += f"\nHash: sha256:{digest}\n"
    output_path.write_text(content, encoding="utf-8")
    return output_path
