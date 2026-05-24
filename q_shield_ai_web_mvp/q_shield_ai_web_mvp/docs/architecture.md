# Architecture

```text
[Asset CSV / Offline JSON]
        ↓
[Scanner Layer] tls_scanner.py, cert_parser.py
        ↓
[Analysis Layer] q_risk_score.py
        ↓
[Recommendation Layer] recommendation_engine.py
        ↓
[Output Layer] CSV, Markdown, HTML Dashboard
```

## Design Principles

- Offline demo must always work.
- Network scan is explicitly authorized only.
- Scan failure is recorded as data and does not stop the batch.
- Risk scoring must be explainable through reason codes.
- Reports fail closed when DLP findings appear.
