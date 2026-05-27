# Q-Shield AI Q-Risk Report

Snapshot: 2026-05-25 13:16:03 UTC
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
| 1 | A001 | `backup.example.local` | 90 | Critical | RSA | 7일 |
| 2 | A002 | `login.example.local` | 77 | High | ECDSA | 30일 |
| 3 | A003 | `api.example.local` | 48 | Medium | RSA | 90일 |
| 4 | A004 | `static.example.local` | 28 | Low | Ed25519 | 다음 정기 검토 |

## Asset Recommendations

### A001 - backup.example.local

- Score: 90
- Level: Critical
- Reason codes: `QALG_PUBLIC_KEY_TRANSITION_REQUIRED, EXTERNAL_EXPOSURE_HNDL_PRIORITY, HIGH_DATA_SENSITIVITY, HIGH_BUSINESS_CRITICALITY, LEGACY_TRANSITION_COMPLEXITY`
- Recommendation: 즉시 변경 관리를 등록하고 7일 이내 PQC 전환 계획을 준비하세요. 현재 공개키 알고리즘 `RSA`은(는) Q-Day 전환 대상으로 간주됩니다. ML-KEM, ML-DSA 및 하이브리드 TLS 준비 상태를 검토하세요. 외부 노출은 HNDL 우선순위를 높입니다. 가능한 한 노출을 줄이고 인증서 수명 주기 관리를 우선하세요. 데이터 민감도가 높으면 장기 보존 데이터가 더 이른 보호를 필요로 할 수 있으므로 마이그레이션 우선순위가 올라갑니다. 레거시 의존성이 존재합니다. 인증서 또는 TLS 스택 마이그레이션 전에 호환성 테스트와 롤백 계획을 추가하세요.
- DoD: 영향도 표, 변경 티켓, 테스트 계획, PQC 전환 일정이 등록되어 있다.

### A002 - login.example.local

- Score: 77
- Level: High
- Reason codes: `QALG_PUBLIC_KEY_TRANSITION_REQUIRED, EXTERNAL_EXPOSURE_HNDL_PRIORITY, MEDIUM_DATA_SENSITIVITY, CERT_EXPIRES_WITHIN_90D, HIGH_BUSINESS_CRITICALITY`
- Recommendation: 30일 이내에 마이그레이션 우선순위와 공급업체 PQC 로드맵을 확인하세요. 현재 공개키 알고리즘 `ECDSA`은(는) Q-Day 전환 대상으로 간주됩니다. ML-KEM, ML-DSA 및 하이브리드 TLS 준비 상태를 검토하세요. 외부 노출은 HNDL 우선순위를 높입니다. 가능한 한 노출을 줄이고 인증서 수명 주기 관리를 우선하세요. 인증서가 39일 후 만료됩니다. 갱신을 암호 전환 계획과 일치시키세요.
- DoD: 공급업체 PQC 지원 현황, 인증서 갱신 계획, 마이그레이션 우선순위가 문서화되어 있다.

### A003 - api.example.local

- Score: 48
- Level: Medium
- Reason codes: `QALG_PUBLIC_KEY_TRANSITION_REQUIRED, MEDIUM_DATA_SENSITIVITY, MEDIUM_BUSINESS_CRITICALITY`
- Recommendation: 자산 인벤토리 메타데이터를 완성하고 90일 검토 일정을 잡으세요. 현재 공개키 알고리즘 `RSA`은(는) Q-Day 전환 대상으로 간주됩니다. ML-KEM, ML-DSA 및 하이브리드 TLS 준비 상태를 검토하세요.
- DoD: 자산 메타데이터가 완성되어 다음 인벤토리 주기에 검토된다.

### A004 - static.example.local

- Score: 28
- Level: Low
- Reason codes: `EXTERNAL_EXPOSURE_HNDL_PRIORITY, LOW_DATA_SENSITIVITY, LOW_BUSINESS_CRITICALITY`
- Recommendation: 자산을 일상 모니터링 대상으로 유지하고 다음 스냅샷에서 재평가하세요. 외부 노출은 HNDL 우선순위를 높입니다. 가능한 한 노출을 줄이고 인증서 수명 주기 관리를 우선하세요.
- DoD: 자산이 일상 모니터링 대상으로 유지되며 다음 스냅샷에서 재평가된다.

## 운영 원칙

- 소유하거나 명시적으로 승인된 자산만 스캔합니다.
- 실제 비밀값, API 키, 개인 키, 개인정보를 저장하지 않습니다.
- 안정적인 시연을 위해 오프라인 샘플 데이터를 사용합니다.
- 민감 데이터가 발견되면 보고서 게시를 중단하고 조치 후 다시 실행합니다.
