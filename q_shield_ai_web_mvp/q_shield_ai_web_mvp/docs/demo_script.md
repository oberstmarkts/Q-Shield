# 5분 시연 스크립트

오프라인 실행 → CSV → Markdown 리포트 → 웹 대시보드 → Streamlit 순서로,
네트워크 없이 전체 파이프라인을 재현하는 5분 시연 가이드다.
모든 단계는 기본 오프라인 모드(샘플 데이터)로 동작하므로 외부 자산을 스캔하지 않는다.

> **사전 준비 (시연 전, 측정 시간에 미포함)**
> ```bash
> python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
> pip install -r requirements.txt
> ```
> 깨끗한 첫 실행을 위해 직전 스냅샷이 남아 있다면 제거: `rm -f reports/q_risk_snapshot.json`
> (드리프트 잠금이 첫 실행을 막지 않도록 기준선을 초기화)

---

## 타임라인 개요

| 구간 | 시간 | 내용 |
|---|---|---|
| 0 | 0:00–0:30 | 도입 — 무엇을, 왜 |
| 1 | 0:30–1:30 | 오프라인 실행 (CLI) |
| 2 | 1:30–2:15 | CSV 결과 확인 |
| 3 | 2:15–3:00 | Markdown 리포트 확인 |
| 4 | 3:00–4:15 | Flask 웹 대시보드 |
| 5 | 4:15–4:45 | Streamlit 대시보드 |
| 6 | 4:45–5:00 | 마무리 — 보안 통제 & 확장 로드맵 |

---

## 0. 도입 (0:00–0:30)

- 한 문장 소개: **"Q-Shield AI는 Q-Day에 취약한 암호자산을 식별해 0~100점 Q-Risk Score로 환산하고,
  PQC 전환 권고와 증거 기반 리포트를 생성하는 MVP입니다."**
- 프로젝트 폴더와 `README.md`를 잠깐 보여주고, **기본 동작은 오프라인 샘플 데이터**라 안전하게 시연된다고 언급.

## 1. 오프라인 실행 — CLI (0:30–1:30)

```bash
python -m app.main --mode offline
```

- 콘솔 출력에서 다음을 짚는다:
  - `Q-Shield AI completed. Assets=4` — 샘플 자산 4건 분석.
  - 생성된 산출물 경로: `reports/q_risk_results.csv`, `q_shield_report.md`, `q_risk_summary.json`,
    `security_audit_report.md`, `evidence_manifest.csv`.
- 메시지 포인트: **네트워크 요청 없이** JSON 샘플 스캔 결과만으로 입력→스캔→점수→권고→출력 전 과정이 돌았다.

## 2. CSV 결과 확인 (1:30–2:15)

```bash
open reports/q_risk_results.csv     # Windows: start reports\q_risk_results.csv
```

- 점수 내림차순 정렬을 확인하고, 샘플 4건의 등급 분포를 짚는다:

| 자산 | 점수 | 등급 |
|---|---:|---|
| A001 backup | 90 | Critical |
| A002 login | 77 | High |
| A003 api | 48 | Medium |
| A004 static | 28 | Low |

- `reason_codes` 컬럼을 가리키며 **점수가 어떻게 나왔는지 설명 가능**하다는 점을 강조
  (예: A001 = `QALG_PUBLIC_KEY_TRANSITION_REQUIRED` + `EXTERNAL_EXPOSURE_HNDL_PRIORITY` + …).
- A004(`Ed25519`)는 양자취약 알고리즘이 아니라 외부 노출에도 Low로 분류된다는 점이 좋은 대비 사례.

## 3. Markdown 리포트 확인 (2:15–3:00)

```bash
open reports/q_shield_report.md     # Windows: start reports\q_shield_report.md
```

- **Executive Summary** — 총 자산 4건, Critical/High 2건, 평균 Q-Risk Score 60.75.
- **Risk Distribution / Top Risk Assets** 표와 **자산별 권고·DoD**를 보여준다.
- 메시지 포인트: 이 리포트는 작성 직후 **DLP 검사(fail-closed)** 를 통과해야만 저장된다 —
  개인키·API 키·주민번호 등이 섞이면 게시가 차단된다.

## 4. Flask 웹 대시보드 (3:00–4:15)

```bash
python run_web.py
```

- 브라우저에서 `http://127.0.0.1:8000` 접속.
- 시연 동선:
  1. **"샘플 데이터 사용"** 클릭 → KPI 카드 4종(전체 자산·Critical/High·평균 점수·최고 위험 자산) 확인.
  2. **위험 등급 분포 / 알고리즘 분포** 차트 확인.
  3. 위험 자산 표에서 **A001(Critical)** 행 선택 → 우측 상세 패널에서 reason code 태그·권고문·DoD 확인.
  4. 하단 **다운로드** 버튼으로 CSV·Markdown 리포트·증거 매니페스트·보안 감사 리포트 내려받기 시연.
- 보안 포인트(짧게): 응답 헤더에 CSP·X-Frame-Options 등이 적용되고, 다운로드는 허용 목록(allowlist)으로만 제공된다.

## 5. Streamlit 대시보드 (4:15–4:45)

```bash
streamlit run app/dashboard/streamlit_app.py
```

- 브라우저에서 `http://localhost:8501` 접속 (별도 터미널에서 실행).
- 메시지 포인트: **Flask 대시보드와 동일한 오프라인 파이프라인·데이터**를 사용하며,
  KPI 4종 + 색상 구분 차트 2종 + 위험 자산 표 + 행 선택 시 상세 권고 패널 + CSV/Markdown 다운로드를 동일하게 제공.
- 행을 하나 선택해 한국어 권고문과 DoD가 그대로 표시됨을 보여주고, 같은 결과를 두 가지 UI로 낼 수 있음을 강조.

## 6. 마무리 (4:45–5:00)

- **적용된 보안 통제** 한 줄 요약: 스캔 인가 게이트, 사설망 가드, DLP fail-closed, CSV 수식 인젝션 방어,
  웹 보안 헤더, 감사 로그·보안 감사 리포트, 증거 매니페스트, ±5% 드리프트 임시 잠금.
- **확장 로드맵**으로 마무리: Zeek/Suricata 로그 연동, OQS(오픈 양자내성암호) 실험 랩, CBOM(암호 BOM) 생성.

---

## 부록: 인가된 스캔 모드 (선택 시연, 오프라인 대체 아님)

소유하거나 명시적으로 인가받은 자산에 한해서만 시연한다. 사설·루프백·`.local` 대상은 기본 차단된다.

```bash
python -m app.main --mode scan --assets data/sample_assets.csv --timeout 5 --allow-scan
```

- `--allow-scan`(전역)과 행 단위 `allowed_to_scan=true`가 **둘 다** 있어야 실제 요청이 나간다.
- 미인가/차단 시도는 `reports/security_audit_log.jsonl`에 감사 이벤트로 기록되며 배치는 멈추지 않는다.

## 부록: 문제 해결

- **`Q-Shield AI halted (temporary lock)` 메시지** → 직전 실행 대비 ±5% 위험 급변으로 드리프트 잠금 발동.
  `reports/q_risk_snapshot.json`의 RCA를 검토한 뒤 해당 파일을 삭제하면 기준선이 초기화된다.
- **포트 충돌(8000/8501)** → 이미 실행 중인 프로세스를 종료하거나 다른 포트로 재실행.
