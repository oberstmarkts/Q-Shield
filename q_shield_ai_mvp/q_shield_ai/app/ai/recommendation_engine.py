from __future__ import annotations

from typing import Any, Dict, List

REASON_TEXT = {
    "Q_PUBLIC_KEY_RSA": "RSA 공개키 기반 자산으로 Q-Day 대비 전환 대상입니다.",
    "Q_PUBLIC_KEY_ECC": "ECC/ECDSA 기반 자산으로 Q-Day 대비 전환 대상입니다.",
    "Q_PUBLIC_KEY_DSA": "DSA 기반 자산으로 Q-Day 대비 전환 대상입니다.",
    "EXTERNAL_EXPOSURE": "외부 노출 자산이므로 Harvest Now, Decrypt Later 위험이 큽니다.",
    "HIGH_SENSITIVITY": "민감 데이터 처리 가능성이 높아 우선순위를 상향합니다.",
    "EXPIRY_30D": "인증서 만료가 30일 이내로 운영 위험이 큽니다.",
    "EXPIRY_90D": "인증서 만료가 90일 이내로 갱신 계획이 필요합니다.",
    "LEGACY_FLAG": "레거시 의존성이 표시되어 전환 난이도 검토가 필요합니다.",
    "WEAK_SIGNATURE_SHA1": "SHA-1 서명 사용 가능성이 있어 즉시 교체가 필요합니다.",
    "SCAN_FAILED": "스캔 실패 자산으로 실제 상태 확인이 필요합니다.",
}


def generate_recommendation(record: Dict[str, Any]) -> str:
    level = record.get("risk_level", "Unknown")
    score = record.get("q_risk_score", "N/A")
    host = record.get("hostname", "unknown-host")
    reasons: List[str] = record.get("reason_codes", []) or []
    reason_sentences = [REASON_TEXT.get(r, f"{r} 조건이 감지되었습니다.") for r in reasons]
    reason_block = " ".join(reason_sentences) if reason_sentences else "주요 원인은 추가 확인이 필요합니다."

    if level in {"Critical", "High"}:
        action = "ML-KEM 기반 키교환, ML-DSA 기반 서명, 하이브리드 TLS 적용 가능성을 우선 검토합니다."
    elif level == "Medium":
        action = "인증서·TLS 설정 인벤토리를 보강하고 벤더의 PQC 지원 일정을 확인합니다."
    else:
        action = "정기 점검 대상으로 유지하되 인증서 갱신 시 PQC 호환성을 함께 확인합니다."

    return (
        f"{host}의 Q-Risk는 {score}점({level})입니다. "
        f"{reason_block} "
        f"즉시 조치: {action} "
        f"DRI=token_24, DoD=전환 영향도 표·테스트 결과·갱신 일정 등록 완료."
    )


def add_recommendations(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for rec in records:
        enriched = dict(rec)
        enriched["recommendation"] = generate_recommendation(enriched)
        out.append(enriched)
    return out
