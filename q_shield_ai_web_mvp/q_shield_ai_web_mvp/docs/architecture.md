# 아키텍처

Q-Shield AI는 암호자산 인벤토리를 입력받아 Q-Risk Score를 산출하고, PQC 전환 권고와
증거 기반 리포트를 생성하는 파이프라인이다. 모든 단계는 **입력 → 스캔 → 점수 → 권고 → 출력**의
단방향 흐름을 따르며, CLI(`app/main.py`)·Flask 웹(`app/web`)·Streamlit(`app/dashboard`)이
동일한 코어 파이프라인(`app/core`)을 공유한다.

---

## 1. 데이터 흐름 한눈에 보기

```text
                         [입력 INPUT]
   data/sample_assets.csv ───────────────┐
   (자산 메타데이터)                       │  load_assets_csv()      ← 필드 검증 / DLP
                                          ▼
                                  list[AssetRecord]
                                          │
              ┌───────────────────────────┴───────────────────────────┐
              │ 오프라인 모드 (기본/시연)            │ 스캔 모드 (--allow-scan)        │
              ▼                                    ▼
   data/offline_scan_results.json          app/scanner/tls_scanner.py
   load_scan_results_json()                실제 TLS 핸드셰이크 + 인증서 파싱
              │                                    │  ← 인가 게이트 / 사설망 가드
              └───────────────┬────────────────────┘
                              ▼
                       dict[asset_id → ScanResult]
                              │
                         [스캔 SCAN]
                              ▼
              app/core/analyzer.py  analyze_assets()
                              │
                         [점수 SCORE]
              app/core/risk.py  calculate_q_risk()
              → (q_risk_score, risk_level, reason_codes)
                              │
                       evaluate_drift_lock()  ← ±5% 급변 시 fail-closed 임시잠금
                              │
                       [권고 RECOMMENDATION]
              app/core/recommendation.py
              → recommendation / action_due / DoD
                              │
                       list[RiskResult]  (점수 내림차순 정렬)
                              ▼
                         [출력 OUTPUT]
   ┌────────────────────────────────────────────────────────────────┐
   │ reports/q_risk_results.csv      (CSV 수식 인젝션 무력화)            │
   │ reports/q_shield_report.md      (DLP fail-closed 검사)            │
   │ reports/q_risk_summary.json     (집계 요약)                       │
   │ reports/security_audit_report.md / security_audit_log.jsonl      │
   │ reports/evidence_manifest.csv   (SHA-256 증거 매니페스트)          │
   │ Flask 웹 대시보드 / Streamlit 대시보드 (KPI·차트·다운로드)          │
   └────────────────────────────────────────────────────────────────┘
```

---

## 2. 단계별 상세

### 2-1. 입력 (Input)
- **자산 메타데이터 CSV** — `app/core/io_utils.py::load_assets_csv()`가 읽어 `AssetRecord` 목록으로 변환.
  필수 컬럼(`asset_id, hostname, port, exposure, data_sensitivity, business_criticality, legacy_flag, owner_token`)을
  검사하고, 행마다 `assert_safe_asset_fields()`로 형식을 검증(자산 ID·호스트명·포트·노출·민감도·중요도·소유자 토큰).
- **오프라인 스캔 결과 JSON** — `load_scan_results_json()`이 `data/offline_scan_results.json`을 읽어
  `asset_id → ScanResult` 매핑을 만든다. 네트워크 접근 없이 동작하는 기본 시연 경로다.
- **웹 업로드 경로** — Flask `/api/analyze`는 업로드 CSV를 `validate_and_write_upload()`로 먼저 검사한다:
  업로드 크기 제한(1 MiB), 자산 수 제한(200), 제어문자 차단, **DLP fail-closed 검사**(개인키·API 키·주민번호 등 탐지 시 차단).

### 2-2. 스캔 (Scan)
- **오프라인 모드(기본)** — 위 JSON의 `ScanResult`를 그대로 사용. 네트워크 요청 없음.
- **스캔 모드(`--allow-scan`)** — `app/scanner/tls_scanner.py::scan_tls_asset()`가 단일 대상에 대해
  타임아웃이 걸린 TLS 핸드셰이크를 수행하고, `cert_parser.parse_der_certificate()`로 인증서에서
  공개키 알고리즘·키 길이·서명 알고리즘·만료일을 추출한다.
- **인가 게이트 (fail-closed)** — 스캔은 두 단계 인가를 모두 통과해야 실행된다.
  1. 전역 플래그 `--allow-scan` (CLI) / `allow_scan=true`
  2. 행 단위 `allowed_to_scan=true`
  추가로 `assert_scan_target_allowed()`가 사설·루프백·링크로컬·`.local` 대상을 차단한다
  (인가된 랩에서만 `QSHIELD_ALLOW_PRIVATE_SCAN=1`로 해제).
- **실패 격리** — 연결 실패·차단은 예외로 배치를 멈추지 않고 `ScanResult(scan_status="failed"|"blocked")`로
  데이터화되며, 시도/차단 이벤트는 `reports/security_audit_log.jsonl`에 감사 로그로 남는다.

### 2-3. 점수 (Score)
- `app/core/analyzer.py::analyze_assets()`가 자산마다 `calculate_q_risk(asset, scan)`을 호출해
  `(점수, 등급, reason code 목록)`을 얻는다. 산식·등급·코드 정의는 [q_risk_formula.md](q_risk_formula.md) 참고.
- 결과는 **Q-Risk Score 내림차순**으로 정렬되어 가장 위험한 자산이 상단에 온다.
- **드리프트 잠금** — `evaluate_drift_lock()`이 직전 스냅샷(`reports/q_risk_snapshot.json`)과 비교해
  평균 점수 또는 Critical 자산 수가 ±5% 이상 변하면 `RiskDriftLockError`를 발생시켜 **리포트 생성을 임시 잠금**한다.
  RCA 항목이 스냅샷에 기록되고, 검토 후 스냅샷 파일을 삭제하면 기준선이 초기화된다.

### 2-4. 권고 (Recommendation)
- `app/core/recommendation.py`가 등급·reason code·자산 속성을 바탕으로 한국어 권고문(`recommendation`),
  조치 기한(`action_due`), 완료 정의(`dod`)를 생성한다.
- 권고문은 등급별 기본 조치 + 알고리즘/외부노출/민감도/레거시/인증서 만료/스캔 불확실성에 대한 맥락 문장을 결합한다.
- 결과는 `RiskResult`로 묶이고, 각 자산에는 `evidence_id`(`EVID-QSHIELD-<asset_id>`)가 부여된다.

### 2-5. 출력 (Output)
- `reports/q_risk_results.csv` — `write_csv_rows()`가 셀별로 `csv_safe_cell()`을 적용해 **수식 인젝션을 무력화**.
- `reports/q_shield_report.md` — 경영진 요약·위험 분포·상위 위험 자산·자산별 권고. 작성 직후 `assert_no_sensitive_text()`로 **DLP fail-closed** 검사.
- `reports/q_risk_summary.json` — 총 자산 수·평균 점수·등급 분포 집계.
- `reports/security_audit_report.md` — 적용된 보안 통제 목록 + 감사 로그(`security_audit_log.jsonl`) 요약. 내용 해시를 끝에 첨부.
- `reports/evidence_manifest.csv` — 산출물별 SHA-256 해시·소유자·TTL을 담은 증거 매니페스트.
- **대시보드** — Flask(`app/web`)는 동일 파이프라인 결과를 JSON으로 제공하고 KPI 카드·위험 분포/알고리즘 분포 차트·자산별 권고·다운로드를 노출한다. Streamlit(`app/dashboard`)은 동일 데이터로 같은 화면을 제공한다.

---

## 3. 설계 원칙

- **오프라인 시연은 항상 동작한다.** 기본 모드는 네트워크 없이 샘플 데이터로 전체 파이프라인을 재현한다.
- **네트워크 스캔은 명시적 인가 시에만.** 전역 플래그 + 행 단위 플래그 + 사설망 가드의 다중 fail-closed 게이트를 통과해야 한다.
- **스캔 실패는 데이터로 기록되고 배치를 멈추지 않는다.** 실패도 점수(불확실성 +5)와 감사 로그에 반영된다.
- **점수는 reason code로 설명 가능해야 한다.** 모든 가산 항목은 대응하는 reason code를 남긴다.
- **민감정보가 발견되면 리포트는 fail-closed로 차단된다.** DLP 검사를 통과하지 못하면 게시하지 않는다.
- **증거 우선.** 모든 산출물은 해시·소유자·TTL과 함께 증거 매니페스트로 묶인다.
- **급격한 위험 변동은 임시 잠금으로 검토를 강제한다.** ±5% 드리프트 시 리포트 생성을 멈춘다.

---

## 4. 주요 모듈 맵

| 단계 | 모듈 | 역할 |
|---|---|---|
| 입력 | `app/core/io_utils.py` | CSV/JSON 로딩, 필드 검증, CSV 출력 |
| 입력/보안 | `app/core/security.py`, `app/core/dlp.py` | 업로드/스캔 인가, 입력 검증, DLP 탐지 |
| 스캔 | `app/scanner/tls_scanner.py`, `app/scanner/cert_parser.py` | TLS 핸드셰이크, 인증서 파싱 |
| 점수 | `app/core/risk.py` | Q-Risk Score·등급·reason code 산출 |
| 점수/거버넌스 | `app/core/analyzer.py` | 파이프라인 오케스트레이션, 드리프트 잠금 |
| 권고 | `app/core/recommendation.py` | 권고문·조치 기한·DoD 생성 |
| 출력 | `app/core/report.py`, `app/core/security_report.py` | Markdown/JSON/감사 리포트, 증거 매니페스트 |
| 출력 | `app/web/server.py`, `app/dashboard/streamlit_app.py` | 웹/Streamlit 대시보드 |
| 진입점 | `app/main.py`, `run_web.py` | CLI / 웹 서버 실행 |

> `app/risk/q_risk_score.py`는 문서화된 파일 레이아웃과의 호환을 위한 래퍼이며 실제 산식은 `app/core/risk.py`에 있다.
