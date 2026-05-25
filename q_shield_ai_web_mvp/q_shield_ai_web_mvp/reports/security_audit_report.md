# Q-Shield AI Security Audit Report

Snapshot: 2026-05-25T06:17:31Z
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

Hash: sha256:25f3c192010dd09d29287c275ca06f7bf21d82482e93d6ce35edabecce137ddd
