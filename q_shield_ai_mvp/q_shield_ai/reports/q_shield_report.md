# Q-Shield AI Report

## Executive Summary

🧭 총 3개 암호자산 중 Critical 1개, High 1개입니다.  
🎯 평균 Q-Risk Score는 76.00점입니다.  
♻️ 우선순위는 외부 노출·민감도·RSA/ECC 사용 기준으로 산정했습니다.  

기준시각: 2026-05-16 22:35 UTC = KST 기준 09:00 스냅샷 운영 원칙 적용

## 1. 위험자산 Top 10

| asset_id   | hostname             | exposure   | public_key_algorithm   |   days_to_expiry |   q_risk_score | risk_level   |
|:-----------|:---------------------|:-----------|:-----------------------|-----------------:|---------------:|:-------------|
| A003       | backup.example.local | external   | RSA                    |              746 |             90 | Critical     |
| A001       | login.example.local  | external   | RSA                    |              229 |             80 | High         |
| A002       | api.example.local    | internal   | ECDSA                  |               59 |             58 | Medium       |

## 2. 자동 권고

- **backup.example.local**: backup.example.local의 Q-Risk는 90점(Critical)입니다. RSA 공개키 기반 자산으로 Q-Day 대비 전환 대상입니다. 외부 노출 자산이므로 Harvest Now, Decrypt Later 위험이 큽니다. 민감 데이터 처리 가능성이 높아 우선순위를 상향합니다. 레거시 의존성이 표시되어 전환 난이도 검토가 필요합니다. 즉시 조치: ML-KEM 기반 키교환, ML-DSA 기반 서명, 하이브리드 TLS 적용 가능성을 우선 검토합니다. DRI=token_24, DoD=전환 영향도 표·테스트 결과·갱신 일정 등록 완료.
- **login.example.local**: login.example.local의 Q-Risk는 80점(High)입니다. RSA 공개키 기반 자산으로 Q-Day 대비 전환 대상입니다. 외부 노출 자산이므로 Harvest Now, Decrypt Later 위험이 큽니다. 민감 데이터 처리 가능성이 높아 우선순위를 상향합니다. 즉시 조치: ML-KEM 기반 키교환, ML-DSA 기반 서명, 하이브리드 TLS 적용 가능성을 우선 검토합니다. DRI=token_24, DoD=전환 영향도 표·테스트 결과·갱신 일정 등록 완료.
- **api.example.local**: api.example.local의 Q-Risk는 58점(Medium)입니다. ECC/ECDSA 기반 자산으로 Q-Day 대비 전환 대상입니다. 인증서 만료가 90일 이내로 갱신 계획이 필요합니다. 즉시 조치: 인증서·TLS 설정 인벤토리를 보강하고 벤더의 PQC 지원 일정을 확인합니다. DRI=token_24, DoD=전환 영향도 표·테스트 결과·갱신 일정 등록 완료.

## 3. 조치 기준

- Critical: 즉시 임시잠금 또는 변경통제 등록 후 7일 내 전환계획 확정
- High: 30일 내 PQC 전환 영향도 분석 및 교체 일정 확정
- Medium: 90일 내 암호자산 인벤토리 보강 및 벤더 호환성 확인
- Low: 정기 점검 주기에 포함하고 만료일 기준 재평가

## 4. Evidence

- EvidenceID: EVID-QSHIELD-RPT-001
- Owner: token_24
- TTL: 90d

- Hash: 27bdadd9b01b95b2b3a25f2abf58d329b736f527994980cbf326622ae633b5ac
