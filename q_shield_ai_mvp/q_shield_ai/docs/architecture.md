# Q-Shield AI Architecture

```text
[Asset CSV / TLS Endpoint / Offline Sample]
        ↓
[Scanner Layer]
  - tls_scanner.py
  - cert_parser.py
        ↓
[Analysis Layer]
  - q_risk_score.py
        ↓
[AI Recommendation Layer]
  - recommendation_engine.py
        ↓
[Output Layer]
  - report_generator.py
  - streamlit_app.py
  - CSV / Markdown Report
```

## Data Flow

1. `data/sample_assets.csv`에서 자산을 읽습니다.
2. `tls_scanner.py`가 TLS 연결 및 인증서를 수집합니다.
3. `cert_parser.py`가 공개키 알고리즘, 서명 알고리즘, 만료일을 추출합니다.
4. `q_risk_score.py`가 Q-Risk Score와 위험등급을 계산합니다.
5. `recommendation_engine.py`가 PQC 전환 권고문을 생성합니다.
6. `report_generator.py`와 Streamlit 대시보드가 결과를 제공합니다.
