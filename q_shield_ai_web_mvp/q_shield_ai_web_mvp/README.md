# Q-Shield AI Security Upgrade MVP

**Q-Shield AI** is a Python-based final project MVP for identifying Q-Day-exposed cryptographic assets, calculating a Q-Risk Score, and generating PQC transition recommendations.

This upgraded package merges the original CLI MVP and the HTML Web MVP, then adds security-focused controls for safer local demonstration and team collaboration.

> Safety rule: scan only assets you own or have explicit permission to test. The default demo mode uses offline sample data.

---

## 1. Quick Start

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m app.main --mode offline
python run_web.py
```

Open:

```text
http://127.0.0.1:8000
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app.main --mode offline
python run_web.py
```

---

## 2. CLI Commands

Run the offline demo:

```bash
python -m app.main --mode offline
```

Run authorized TLS scan mode:

```bash
python -m app.main --mode scan --assets data/sample_assets.csv --timeout 5 --allow-scan
```

Private, loopback, and `.local` targets are blocked by default even with `allowed_to_scan=true`.
For an authorized lab only, set:

```bash
set QSHIELD_ALLOW_PRIVATE_SCAN=1
```

Run tests:

```bash
pytest -q
```

---

## 3. Web Dashboard

Start the Flask HTML dashboard:

```bash
python run_web.py
```

Optional Streamlit dashboard:

```bash
streamlit run app/dashboard/streamlit_app.py
```

### Access URLs

| Dashboard | Deployed (server) | Local |
|---|---|---|
| Flask web dashboard | http://54.180.104.65:8000 | http://127.0.0.1:8000 |
| Streamlit dashboard | http://54.180.104.65:8501 | http://localhost:8501 |

The deployed addresses point to the demo server; the local addresses apply when you run the commands above on your own machine.

Features:

- Use bundled sample data
- Upload an asset CSV
- View KPI cards
- View risk distribution
- View algorithm distribution
- Inspect asset-level reason codes and recommendations
- Download CSV, Markdown report, evidence manifest, and security audit report

---

## 4. Required CSV Columns

```csv
asset_id,hostname,port,exposure,data_sensitivity,business_criticality,legacy_flag,owner_token,allowed_to_scan
```

Recommended values:

- `exposure`: `external` or `internal`
- `data_sensitivity`: `high`, `medium`, `low`
- `business_criticality`: `high`, `medium`, `low`
- `legacy_flag`: `true` or `false`
- `owner_token`: `token_24` style pseudonymous owner token
- `allowed_to_scan`: `true` only for owned or explicitly authorized assets

---

## 5. Security Controls Added in This Upgrade

- DLP fail-closed upload and report checks
- CSV upload size limit and asset count limit
- Strict CSV field validation for asset ID, hostname, port, exposure, sensitivity, criticality, and owner token
- TLS scan authorization gate: `--allow-scan` + row-level `allowed_to_scan=true`
- Private, loopback, and `.local` scan guard unless `QSHIELD_ALLOW_PRIVATE_SCAN=1`
- CSV formula injection mitigation for exported reports
- Flask security headers: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, no-store
- DOM XSS mitigation in the HTML dashboard by using `textContent` rendering
- Download allowlist for report files
- Sanitized server errors
- Security audit log and security audit report generation

Generated files:

- `reports/q_risk_results.csv`
- `reports/q_shield_report.md`
- `reports/q_risk_summary.json`
- `reports/evidence_manifest.csv`
- `reports/security_audit_log.jsonl`
- `reports/security_audit_report.md`

---

## 6. Q-Risk Score

| Factor | Score |
|---|---:|
| RSA/ECC/DSA public key | 30 |
| External exposure | 20 |
| Data sensitivity | 5 to 20 |
| Certificate expiry | 0 to 10 |
| Business criticality | 3 to 10 |
| Legacy flag | 10 |
| SHA1 signature | 8 |
| Scan failure uncertainty | 5 |

Risk level:

| Score | Level |
|---:|---|
| 85-100 | Critical |
| 70-84 | High |
| 40-69 | Medium |
| 0-39 | Low |

---

## 7. Final Project Message

Q-Shield AI converts a future-facing Q-Day security topic into a working MVP: cryptographic asset inventory, risk scoring, PQC transition recommendation, HTML dashboard reporting, and evidence-first security governance.
