# Q-Shield AI Security Audit Report

Snapshot: 2026-05-25T13:16:03Z
Owner: token_24
TTL: 90d

## Applied Security Controls

| Control | Status | Evidence |
|---|---|---|
| DLP fail-closed | Enabled | app/core/dlp.py |
| CSV upload size limit | Enabled | app/core/security.py |
| Asset count limit | Enabled | app/core/security.py |
| Asset field validation | Enabled | app/core/security.py |
| Scan authorization gate | Enabled | --allow-scan + allowed_to_scan=true |
| Private/loopback scan guard | Enabled | QSHIELD_ALLOW_PRIVATE_SCAN required |
| CSV formula injection mitigation | Enabled | app/core/io_utils.py |
| Web security headers | Enabled | app/web/server.py |
| DOM XSS mitigation | Enabled | app/web/static/app.js textContent rendering |
| Download path allowlist | Enabled | /download/<kind> mapping only |
| Audit log | Enabled | reports/security_audit_log.jsonl |

## Audit Events

| Time | Event | Asset | Status/Reason |
|---|---|---|---|
| 2026-05-25T05:23:46Z | dlp_blocked |  | DLP check blocked publication. Cause=email; Impact=report or upload analysis not generated; Scope=current data; Action=remove or mask sensitive data; DoD=rerun with zero DLP findings. |
| 2026-05-25T05:30:49Z | dlp_blocked |  | DLP check blocked publication. Cause=email; Impact=report or upload analysis not generated; Scope=current data; Action=remove or mask sensitive data; DoD=rerun with zero DLP findings. |
| 2026-05-25T06:17:32Z | dlp_blocked |  | DLP check blocked publication. Cause=email; Impact=report or upload analysis not generated; Scope=current data; Action=remove or mask sensitive data; DoD=rerun with zero DLP findings. |
| 2026-05-25T13:06:56Z | sample_analysis |  |  |
| 2026-05-25T13:06:56Z | server_error |  | NotFound |

Hash: sha256:700d19224e0b7210e3c7b9e60cf028e84be2cb5fe24847f8232a52271eb5b725
