# Q-Risk Score 산식

Q-Risk Score는 자산 1건이 Q-Day(양자컴퓨터로 인한 공개키 암호 붕괴) 상황에서
얼마나 시급하게 PQC(양자내성암호)로 전환되어야 하는지를 0~100 점으로 표현한 값이다.
구현은 `app/core/risk.py`의 `calculate_q_risk()`에 있으며, 자산 메타데이터(`AssetRecord`)와
스캔 결과(`ScanResult`)를 입력으로 받아 **점수 / 등급 / reason code 목록**을 반환한다.

> 동일 함수가 오프라인 모드와 스캔 모드 모두에서 쓰인다. 오프라인 모드는 샘플 스캔 결과(JSON)를,
> 스캔 모드는 실제 TLS 핸드셰이크 결과를 `ScanResult`로 넘긴다. 산식은 입력 출처와 무관하게 동일하다.

---

## 1. 점수 산식 (항목별 설명)

점수는 0에서 시작해 아래 항목을 누적 가산하고, 마지막에 **0~100 범위로 절단(clamp)** 한다.

| # | 항목 | 가산점 | 판정 기준 | 부여 reason code |
|---|---|---:|---|---|
| 1 | 양자취약 공개키 알고리즘 | **+30** | `public_key_algorithm`에 `RSA`/`ECDSA`/`ECDH`/`DSA`/`EC` 문자열 포함 | `QALG_PUBLIC_KEY_TRANSITION_REQUIRED` |
| 2 | 외부 노출 | **+20** | `exposure == external` | `EXTERNAL_EXPOSURE_HNDL_PRIORITY` |
| 3 | 데이터 민감도 | **+20 / +12 / +5** | `high` / `medium` / 그 외 | `HIGH_/MEDIUM_/LOW_DATA_SENSITIVITY` |
| 4 | 인증서 만료 임박 | **+10 / +5 / +5 / 0** | 30일 이내 / 90일 이내 / 만료정보 없음(`None`) / 그 외 | `CERT_EXPIRES_WITHIN_30D` 등 (아래 설명) |
| 5 | 업무 중요도 | **+10 / +6 / +3** | `high` / `medium` / 그 외 | `HIGH_/MEDIUM_/LOW_BUSINESS_CRITICALITY` |
| 6 | 레거시 의존성 | **+10** | `legacy_flag == true` | `LEGACY_TRANSITION_COMPLEXITY` |
| 7 | SHA-1 서명 | **+8** | `signature_algorithm`에 `sha1` 포함 | `SHA1_SIGNATURE_ADDITIONAL_RISK` |
| 8 | 스캔 실패/불확실성 | **+5** | `scan_status == failed` 또는 `error_message` 존재 | `SCAN_FAILURE_UNCERTAINTY` |

항목별 상세:

1. **양자취약 공개키 알고리즘 (+30)** — Q-Risk의 핵심 가중치. 알고리즘 이름을 대문자로 바꾼 뒤
   `{RSA, ECDSA, ECDH, DSA, EC}` 토큰을 부분 문자열로 검사한다. RSA·ECC 계열은 Shor 알고리즘으로
   복호화될 수 있으므로 PQC 전환 대상이다. 반면 `Ed25519`처럼 해당 토큰이 없는 알고리즘은 가산되지 않는다.
2. **외부 노출 (+20)** — 외부에 노출된 자산은 HNDL(Harvest Now, Decrypt Later) 공격 우선순위가 높다.
   지금 수집된 암호문이 미래에 복호화될 수 있어 전환을 앞당겨야 한다.
3. **데이터 민감도 (+20/+12/+5)** — 항상 셋 중 하나가 가산된다. 즉 모든 자산은 최소 +5를 받는다.
4. **인증서 만료 임박** — 만료 정보(`days_to_expiry`)에 따라 분기한다.
   - `None`(만료정보 없음/미스캔) → **+5**, `CERT_EXPIRY_UNKNOWN`
   - 30일 이내 → **+10**, `CERT_EXPIRES_WITHIN_30D`
   - 90일 이내(31~90일) → **+5**, `CERT_EXPIRES_WITHIN_90D`
   - 90일 초과 → **+0** (reason code 없음)
   갱신 시점이 가까울수록 PQC 인증서로 함께 전환할 기회가 생기므로 우선순위가 올라간다.
5. **업무 중요도 (+10/+6/+3)** — 항상 셋 중 하나가 가산된다. 즉 모든 자산은 최소 +3을 받는다.
6. **레거시 의존성 (+10)** — 레거시 스택은 전환 시 호환성 테스트·롤백 계획이 추가로 필요해 복잡도가 높다.
7. **SHA-1 서명 (+8)** — SHA-1 서명은 이미 충돌 공격에 취약한 구식 알고리즘으로, 추가 위험으로 가산한다.
8. **스캔 실패/불확실성 (+5)** — 스캔이 실패하거나 오류 메시지가 있으면 상태가 불확실하므로,
   안전 측면에서 가산해 검토 대상으로 끌어올린다.

> **최저/최고 점수**: 항목 3·5가 항상 가산되므로 최저 점수는 `5(민감도 low) + 3(중요도 low) = 8`점이다.
> 모든 항목을 만족하면 `30+20+20+10+10+10+8+5 = 113`점이지만, **상한 100점으로 절단**된다.

---

## 2. 등급 기준표

`level_from_score()`가 점수를 4단계 등급으로 매핑한다.

| 점수 | 등급 | 조치 기한(`action_due`) | 완료 정의(DoD) |
|---:|---|---|---|
| 85–100 | **Critical (심각)** | 7일 | 영향도 표, 변경 티켓, 테스트 계획, PQC 전환 일정 등록 |
| 70–84 | **High (높음)** | 30일 | 공급업체 PQC 지원 현황, 인증서 갱신 계획, 마이그레이션 우선순위 문서화 |
| 40–69 | **Medium (보통)** | 90일 | 자산 메타데이터 완성 후 다음 인벤토리 주기에 검토 |
| 0–39 | **Low (낮음)** | 다음 정기 검토 | 일상 모니터링 유지 후 다음 스냅샷에서 재평가 |

조치 기한과 DoD는 `app/core/recommendation.py`의 `action_due_for_level()` / `dod_for_level()`에서 부여된다.

---

## 3. Reason Code 목록

각 자산 결과에는 점수가 어떻게 산출됐는지 설명하는 reason code가 부여된다(`reason_codes`).
CSV에서는 `;`로 결합되어 출력되고, 웹/Streamlit 대시보드에서는 태그(칩)로 표시된다.

| Reason Code | 가산점 | 의미 |
|---|---:|---|
| `QALG_PUBLIC_KEY_TRANSITION_REQUIRED` | +30 | 공개키가 양자취약 알고리즘(RSA/ECC 계열) → PQC 전환 필요 |
| `EXTERNAL_EXPOSURE_HNDL_PRIORITY` | +20 | 외부 노출 자산 → HNDL 공격 우선순위 |
| `HIGH_DATA_SENSITIVITY` | +20 | 데이터 민감도 높음 |
| `MEDIUM_DATA_SENSITIVITY` | +12 | 데이터 민감도 보통 |
| `LOW_DATA_SENSITIVITY` | +5 | 데이터 민감도 낮음 |
| `CERT_EXPIRES_WITHIN_30D` | +10 | 인증서가 30일 이내 만료 |
| `CERT_EXPIRES_WITHIN_90D` | +5 | 인증서가 90일 이내 만료(31~90일) |
| `CERT_EXPIRY_UNKNOWN` | +5 | 인증서 만료 정보 없음/미스캔 |
| `HIGH_BUSINESS_CRITICALITY` | +10 | 업무 중요도 높음 |
| `MEDIUM_BUSINESS_CRITICALITY` | +6 | 업무 중요도 보통 |
| `LOW_BUSINESS_CRITICALITY` | +3 | 업무 중요도 낮음 |
| `LEGACY_TRANSITION_COMPLEXITY` | +10 | 레거시 의존성 → 전환 복잡도 가산 |
| `SHA1_SIGNATURE_ADDITIONAL_RISK` | +8 | SHA-1 서명 사용 → 추가 위험 |
| `SCAN_FAILURE_UNCERTAINTY` | +5 | 스캔 실패/오류 → 불확실성 가산 |

> 데이터 민감도 코드(3종)와 업무 중요도 코드(3종)는 자산마다 **각각 정확히 하나씩** 항상 부여된다.
> 인증서 만료 코드는 90일 초과 시 어떤 코드도 부여되지 않는다.

---

## 4. 샘플 데이터 산출 예시

`data/sample_assets.csv` + `data/offline_scan_results.json` 기준 오프라인 실행 결과(점수 내림차순):

| 자산 | 알고리즘 | 노출 | 민감도 | 만료 | 중요도 | 레거시 | 점수 계산 | 점수 | 등급 |
|---|---|---|---|---|---|---|---|---:|---|
| A001 backup | RSA | external | high | 343일 | high | true | 30+20+20+0+10+10 | **90** | Critical |
| A002 login | ECDSA | external | medium | 39일 | high | false | 30+20+12+5+10 | **77** | High |
| A003 api | RSA | internal | medium | 222일 | medium | false | 30+12+6 | **48** | Medium |
| A004 static | Ed25519 | external | low | 587일 | low | false | 20+5+3 | **28** | Low |

- 평균 Q-Risk Score = (90+77+48+28)/4 = **60.75**, Critical/High 자산 = **2건**.
- A004는 `Ed25519`라 양자취약 알고리즘(+30)에 해당하지 않아 외부 노출 자산임에도 Low로 분류된다.
- 이 분포는 등급 4단계가 모두 등장하도록 구성되어 시연에 적합하다.

---

## 5. 드리프트 잠금(Drift Lock)과의 관계

점수 산출 직후 `analyzer.evaluate_drift_lock()`이 직전 실행 스냅샷(`reports/q_risk_snapshot.json`)과
비교한다. **평균 점수** 또는 **Critical 자산 수**가 직전 대비 **±5% 이상** 변하면 `RiskDriftLockError`를
발생시켜 리포트 생성을 **임시 잠금(fail-closed)** 한다. 잠금 시 RCA 항목이 스냅샷에 기록되며,
검토 후 스냅샷 파일을 삭제하면 기준선이 초기화된다. 자세한 동작은 [architecture.md](architecture.md) 참고.
