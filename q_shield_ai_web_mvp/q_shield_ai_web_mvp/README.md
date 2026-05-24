# Q-Shield AI Web MVP

**Q-Shield AI** is a Python-based final project MVP for identifying Q-Day-exposed cryptographic assets, calculating a Q-Risk Score, and generating PQC transition recommendations.

This package includes:

- Python CLI offline demo
- Flask HTML dashboard
- CSV and Markdown report generation
- Basic TLS scan module for authorized assets only
- Fail-closed DLP checks
- Evidence manifest with SHA-256 hashes
- Pytest test suite

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

Features:

- Use bundled sample data
- Upload an asset CSV
- View KPI cards
- View risk distribution
- View algorithm distribution
- Inspect asset-level reason codes and recommendations
- Download CSV and Markdown reports

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
- `allowed_to_scan`: `true` only for owned or explicitly authorized assets

---

## 5. Q-Risk Score

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

## 6. Project Structure

```text
q_shield_ai_web_mvp/
├─ app/
│  ├─ main.py
│  ├─ core/
│  ├─ scanner/
│  └─ web/
├─ data/
├─ docs/
├─ reports/
├─ tests/
├─ scripts/
├─ requirements.txt
└─ run_web.py
```

---

## 7. Security Controls

- Real secrets must not be committed.
- `.env` files are ignored.
- Sample values only.
- DLP checks stop report generation if obvious secrets or personal identifiers are detected.
- TLS scan mode requires the explicit `--allow-scan` flag and asset-level `allowed_to_scan=true`.
- Scan failures are recorded and do not stop the full batch.

---

## 8. Final Project Message

Q-Shield AI converts a future-facing Q-Day security topic into a working MVP: cryptographic asset inventory, risk scoring, PQC transition recommendation, and HTML dashboard reporting.
