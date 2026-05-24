# Demo Script

1. 프로젝트 개요를 설명합니다.
2. `data/offline_scan_results.json` 샘플을 보여줍니다.
3. `python -m app.main --mode offline`을 실행합니다.
4. `reports/q_risk_results.csv` 생성 여부를 확인합니다.
5. `reports/q_shield_report.md`에서 자동 권고문을 확인합니다.
6. `streamlit run app/dashboard/streamlit_app.py`로 대시보드를 실행합니다.
7. Critical/High 자산을 필터링합니다.
8. AI Recommendations 영역에서 PQC 전환 권고를 설명합니다.
9. 실제 스캔 모드는 허가된 자산에만 사용한다고 고지합니다.
10. 향후 확장으로 Zeek/Suricata/OQS Provider 연동을 설명합니다.
