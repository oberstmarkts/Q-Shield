# Q-Shield AI Q-Risk Report

Snapshot: 2026-05-22 19:27:28 UTC
Owner: token_24
TTL: 90d
EvidenceID: EVID-QSHIELD-MVP-001

## Executive Summary

- Total assets analyzed: 4
- Critical/High assets: 2
- Average Q-Risk Score: 60.75

## Risk Distribution

| Level | Count |
|---|---:|
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| Low | 1 |

## Top Risk Assets

| Rank | Asset | Hostname | Score | Level | Algorithm | Due |
|---:|---|---|---:|---|---|---|
| 1 | A001 | `backup.example.local` | 90 | Critical | RSA | 7 days |
| 2 | A002 | `login.example.local` | 77 | High | ECDSA | 30 days |
| 3 | A003 | `api.example.local` | 48 | Medium | RSA | 90 days |
| 4 | A004 | `static.example.local` | 28 | Low | Ed25519 | Next regular review |

## Asset Recommendations

### A001 - backup.example.local

- Score: 90
- Level: Critical
- Reason codes: `QALG_PUBLIC_KEY_TRANSITION_REQUIRED, EXTERNAL_EXPOSURE_HNDL_PRIORITY, HIGH_DATA_SENSITIVITY, HIGH_BUSINESS_CRITICALITY, LEGACY_TRANSITION_COMPLEXITY`
- Recommendation: Register immediate change control and prepare a 7-day PQC transition plan. Current public key algorithm `RSA` is treated as Q-Day transition target; review ML-KEM, ML-DSA, and hybrid TLS readiness. External exposure increases HNDL priority; reduce exposure where possible and prioritize certificate lifecycle control. High data sensitivity raises migration priority because long-retention data may require earlier protection. Legacy dependency is present; add compatibility testing and rollback planning before certificate or TLS stack migration.
- DoD: Impact table, change ticket, test plan, and PQC transition schedule are registered.

### A002 - login.example.local

- Score: 77
- Level: High
- Reason codes: `QALG_PUBLIC_KEY_TRANSITION_REQUIRED, EXTERNAL_EXPOSURE_HNDL_PRIORITY, MEDIUM_DATA_SENSITIVITY, CERT_EXPIRES_WITHIN_90D, HIGH_BUSINESS_CRITICALITY`
- Recommendation: Confirm migration priority and vendor PQC roadmap within 30 days. Current public key algorithm `ECDSA` is treated as Q-Day transition target; review ML-KEM, ML-DSA, and hybrid TLS readiness. External exposure increases HNDL priority; reduce exposure where possible and prioritize certificate lifecycle control. Certificate expires in 39 days; align renewal with cryptographic transition planning.
- DoD: Vendor PQC support status, certificate renewal plan, and migration priority are documented.

### A003 - api.example.local

- Score: 48
- Level: Medium
- Reason codes: `QALG_PUBLIC_KEY_TRANSITION_REQUIRED, MEDIUM_DATA_SENSITIVITY, MEDIUM_BUSINESS_CRITICALITY`
- Recommendation: Complete asset inventory metadata and schedule a 90-day review. Current public key algorithm `RSA` is treated as Q-Day transition target; review ML-KEM, ML-DSA, and hybrid TLS readiness.
- DoD: Asset metadata is completed and reviewed in the next inventory cycle.

### A004 - static.example.local

- Score: 28
- Level: Low
- Reason codes: `EXTERNAL_EXPOSURE_HNDL_PRIORITY, LOW_DATA_SENSITIVITY, LOW_BUSINESS_CRITICALITY`
- Recommendation: Keep the asset in routine monitoring and reassess at the next snapshot. External exposure increases HNDL priority; reduce exposure where possible and prioritize certificate lifecycle control.
- DoD: Asset remains in routine monitoring and is reassessed in the next snapshot.

## Operating Guardrails

- Scan only owned or explicitly authorized assets.
- Do not store real secrets, API keys, private keys, or personal data.
- Use offline sample data for stable presentations.
- If sensitive data is found, stop report publication and rerun after remediation.
