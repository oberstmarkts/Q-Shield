# Q-Shield AI Test Result

Snapshot: 2026-05-25 UTC  
Owner: token_24  
TTL: 90d  
Environment: Python 3.13.9 · pytest 8.4.2 · platform darwin

## Command

```bash
pytest -q
```

## Result

```text
......................                                                   [100%]
22 passed
```

- Pytest: **22 passed**, 0 failed
- Test files: 5 (`test_dlp.py`, `test_offline.py`, `test_risk.py`, `test_score_boundaries.py`, `test_security_upgrade.py`)

## 테스트 항목별 설명

### tests/test_dlp.py — DLP 탐지 (2)

| 테스트 | 설명 |
|---|---|
| `test_dlp_allows_normal_report_text` | 정상 리포트 텍스트에서는 민감정보가 탐지되지 않음(`detect_sensitive_text` → 빈 리스트) |
| `test_dlp_blocks_private_key` | PRIVATE KEY 블록이 포함된 텍스트는 `DLPViolation`으로 차단 |

### tests/test_offline.py — 오프라인 분석 파이프라인 (1)

| 테스트 | 설명 |
|---|---|
| `test_offline_generates_results` | `run_offline`로 샘플 자산 4건을 분석하고 `q_risk_results.csv`·`q_shield_report.md`·`evidence_manifest.csv`를 생성, 리포트 제목 포함 확인 |

### tests/test_risk.py — 위험 점수 기본 검증 (3)

| 테스트 | 설명 |
|---|---|
| `test_level_boundaries` | `level_from_score` 함수의 등급 경계(85/84, 70/69, 40/39) 직접 검증 |
| `test_critical_score_for_external_high_rsa_legacy` | 외부 노출 + 고민감 + RSA + legacy + 고중요 자산이 90점 = Critical, Q-알고리즘 사유코드 포함 |
| `test_low_for_non_q_alg_low_business_external` | 비-Q 알고리즘(Ed25519) + 저민감 + 저중요 자산이 28점 = Low |

### tests/test_score_boundaries.py — 경계값 및 가산점 (10, 신규)

| 테스트 | 설명 |
|---|---|
| `test_score_to_level_boundaries[85-Critical]` | 전체 파이프라인으로 85점 구성 → Critical (Critical/High 경계 상한) |
| `test_score_to_level_boundaries[84-High]` | 84점 → High (Critical/High 경계 하한) |
| `test_score_to_level_boundaries[70-High]` | 70점 → High (High/Medium 경계 상한) |
| `test_score_to_level_boundaries[69-Medium]` | 69점 → Medium (High/Medium 경계 하한) |
| `test_score_to_level_boundaries[40-Medium]` | 40점 → Medium (Low/Medium 경계 상한) |
| `test_score_to_level_boundaries[39-Low]` | 39점 → Low (Low/Medium 경계 하한) |
| `test_sha1_signature_adds_8` | SHA1 서명 시 점수 +8, `SHA1_SIGNATURE_ADDITIONAL_RISK` 사유코드 추가 (델타 검증) |
| `test_legacy_flag_adds_10` | `legacy_flag` 활성 시 점수 +10, `LEGACY_TRANSITION_COMPLEXITY` 사유코드 추가 |
| `test_scan_failure_adds_5[kwargs0]` | `scan_status="failed"` 시 점수 +5, `SCAN_FAILURE_UNCERTAINTY` 사유코드 추가 |
| `test_scan_failure_adds_5[kwargs1]` | `error_message` 존재 시 점수 +5, `SCAN_FAILURE_UNCERTAINTY` 사유코드 추가 |

### tests/test_security_upgrade.py — 보안 통제 (6)

| 테스트 | 설명 |
|---|---|
| `test_dlp_blocks_email_and_github_token` | 이메일·GitHub 토큰 포함 텍스트가 `DLPViolation`으로 차단 |
| `test_csv_formula_injection_is_neutralized` | CSV 수식 인젝션(`=cmd...`) 값 앞에 `'`가 붙어 무력화됨 |
| `test_asset_csv_validation_blocks_bad_hostname` | 위험 hostname(`<script>`) 포함 CSV가 `SecurityValidationError`로 차단 |
| `test_private_scan_blocked_by_default` | 사설/루프백 대상(`127.0.0.1`) 스캔이 기본 차단(fail-closed) |
| `test_web_security_headers_present` | Flask 응답에 `X-Frame-Options`, `X-Content-Type-Options`, CSP `frame-ancestors 'none'` 헤더 존재 |
| `test_upload_dlp_fail_closed` | 이메일 포함 CSV 업로드가 **400** + DLP 메시지로 fail-closed 처리 |

## DoD

The MVP package executes the full test suite with 22 passing tests, covering offline analysis, Q-Risk scoring boundaries and additive factors, DLP fail-closed controls, CSV validation, scan authorization, and web security headers.
