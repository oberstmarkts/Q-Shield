# Final Project Definition

## Title

Q-Shield AI: 양자컴퓨터 Q-Day 대비를 위한 AI 기반 암호자산 탐지 및 PQC 전환 자동최적화 시스템

## Objective

RSA/ECC 기반 공개키 암호 사용 자산을 탐지하고 Q-Risk Score를 산정한 뒤, PQC 전환 우선순위와 대응 권고를 자동 생성합니다.

## Working MVP Scope

- Offline demo data execution
- TLS scanner for authorized assets
- Certificate parser
- Q-Risk scoring engine
- Recommendation generator
- Markdown report generator
- Streamlit dashboard
- Unit tests

## DoD

- `python -m app.main --mode offline` 성공
- `pytest -q` 성공
- `reports/q_risk_results.csv` 생성
- `reports/q_shield_report.md` 생성
- `streamlit run app/dashboard/streamlit_app.py` 실행 가능
