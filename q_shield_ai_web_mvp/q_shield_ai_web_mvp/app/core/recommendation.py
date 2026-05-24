from __future__ import annotations

from .models import AssetRecord, ScanResult


def action_due_for_level(level: str) -> str:
    return {
        "Critical": "7일",
        "High": "30일",
        "Medium": "90일",
        "Low": "다음 정기 검토",
    }.get(level, "다음 정기 검토")


def dod_for_level(level: str) -> str:
    return {
        "Critical": "영향도 표, 변경 티켓, 테스트 계획, PQC 전환 일정이 등록되어 있다.",
        "High": "공급업체 PQC 지원 현황, 인증서 갱신 계획, 마이그레이션 우선순위가 문서화되어 있다.",
        "Medium": "자산 메타데이터가 완성되어 다음 인벤토리 주기에 검토된다.",
        "Low": "자산이 일상 모니터링 대상으로 유지되며 다음 스냅샷에서 재평가된다.",
    }.get(level, "다음 스냅샷에서 재평가한다.")


def build_recommendation(asset: AssetRecord, scan: ScanResult, level: str, reasons: list[str]) -> str:
    parts: list[str] = []

    if level == "Critical":
        parts.append("즉시 변경 관리를 등록하고 7일 이내 PQC 전환 계획을 준비하세요.")
    elif level == "High":
        parts.append("30일 이내에 마이그레이션 우선순위와 공급업체 PQC 로드맵을 확인하세요.")
    elif level == "Medium":
        parts.append("자산 인벤토리 메타데이터를 완성하고 90일 검토 일정을 잡으세요.")
    else:
        parts.append("자산을 일상 모니터링 대상으로 유지하고 다음 스냅샷에서 재평가하세요.")

    alg = (scan.public_key_algorithm or "unknown").upper()
    if any(token in alg for token in ["RSA", "ECDSA", "ECDH", "DSA", "EC"]):
        parts.append(f"현재 공개키 알고리즘 `{scan.public_key_algorithm}`은(는) Q-Day 전환 대상으로 간주됩니다. ML-KEM, ML-DSA 및 하이브리드 TLS 준비 상태를 검토하세요.")

    if asset.exposure.lower() == "external":
        parts.append("외부 노출은 HNDL 우선순위를 높입니다. 가능한 한 노출을 줄이고 인증서 수명 주기 관리를 우선하세요.")

    if asset.data_sensitivity.lower() == "high":
        parts.append("데이터 민감도가 높으면 장기 보존 데이터가 더 이른 보호를 필요로 할 수 있으므로 마이그레이션 우선순위가 올라갑니다.")

    if asset.legacy_flag:
        parts.append("레거시 의존성이 존재합니다. 인증서 또는 TLS 스택 마이그레이션 전에 호환성 테스트와 롤백 계획을 추가하세요.")

    if scan.days_to_expiry is not None and scan.days_to_expiry <= 90:
        parts.append(f"인증서가 {scan.days_to_expiry}일 후 만료됩니다. 갱신을 암호 전환 계획과 일치시키세요.")

    if scan.error_message:
        parts.append("스캔 불확실성이 존재합니다. 최종 경영진 보고 전에 승인된 네트워크에서 스캔을 다시 실행하세요.")

    return " ".join(parts)
