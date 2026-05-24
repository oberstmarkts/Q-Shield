# Q-Shield AI

Q-Shield AI는 Q-Day 대비를 위한 작동형 보안 MVP입니다. TLS 인증서와 공개키 알고리즘을 수집·분석하고, RSA/ECDSA 등 양자 취약 공개키 사용 여부를 기반으로 Q-Risk Score와 PQC 전환 권고를 생성합니다.

## 주요 기능

- TLS endpoint scanner: 도메인·포트 기반 TLS/인증서 수집
- Certificate parser: 공개키 알고리즘, 키 길이, 서명 알고리즘, 만료일 분석
- Q-Risk Score: 외부 노출, 민감도, 중요도, 만료일, 레거시 여부 기반 0~100점 산정
- AI-style recommendation: ML-KEM, ML-DSA, 하이브리드 TLS 전환 권고문 생성
- Streamlit dashboard: 위험자산 Top N, 등급 분포, 알고리즘 분포, CSV 다운로드
- Offline demo mode: 인터넷 없이 샘플데이터로 즉시 시연 가능

## 설치

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
pip install -r requirements.txt
```

## 즉시 실행: 오프라인 데모

```bash
python -m app.main --mode offline
```

생성 결과:

- `reports/q_risk_results.csv`
- `reports/q_shield_report.md`

## 실제 TLS 스캔 실행

본인 또는 조직이 소유·허가한 자산만 스캔하십시오.

```bash
python -m app.main --mode scan --assets data/sample_assets.csv --timeout 5
```

## 대시보드 실행

```bash
streamlit run app/dashboard/streamlit_app.py
```

## 테스트

```bash
pytest -q
```

## 프로젝트 구조

```text
q_shield_ai/
├─ app/
│  ├─ main.py
│  ├─ scanner/
│  ├─ risk/
│  ├─ ai/
│  ├─ report/
│  └─ dashboard/
├─ data/
├─ docs/
├─ reports/
├─ tests/
└─ requirements.txt
```

## 안전 원칙

- 무단 스캔 금지
- 민감정보 저장 금지
- Owner는 token_24로 표기
- 결과물은 로컬 파일 중심으로 생성
