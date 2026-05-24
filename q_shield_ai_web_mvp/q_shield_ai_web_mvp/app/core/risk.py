from __future__ import annotations

from .models import AssetRecord, ScanResult


Q_VULNERABLE_ALGORITHMS = {"RSA", "ECDSA", "ECDH", "DSA", "EC"}


def _norm(value: object) -> str:
    return str(value or "").strip().lower()


def is_q_vulnerable_algorithm(algorithm: str) -> bool:
    alg = str(algorithm or "").upper()
    return any(token in alg for token in Q_VULNERABLE_ALGORITHMS)


def level_from_score(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def calculate_q_risk(asset: AssetRecord, scan: ScanResult) -> tuple[int, str, list[str]]:
    score = 0
    reasons: list[str] = []

    if is_q_vulnerable_algorithm(scan.public_key_algorithm):
        score += 30
        reasons.append("QALG_PUBLIC_KEY_TRANSITION_REQUIRED")

    if _norm(asset.exposure) == "external":
        score += 20
        reasons.append("EXTERNAL_EXPOSURE_HNDL_PRIORITY")

    sensitivity = _norm(asset.data_sensitivity)
    if sensitivity == "high":
        score += 20
        reasons.append("HIGH_DATA_SENSITIVITY")
    elif sensitivity == "medium":
        score += 12
        reasons.append("MEDIUM_DATA_SENSITIVITY")
    else:
        score += 5
        reasons.append("LOW_DATA_SENSITIVITY")

    days = scan.days_to_expiry
    if days is None:
        score += 5
        reasons.append("CERT_EXPIRY_UNKNOWN")
    elif days <= 30:
        score += 10
        reasons.append("CERT_EXPIRES_WITHIN_30D")
    elif days <= 90:
        score += 5
        reasons.append("CERT_EXPIRES_WITHIN_90D")

    criticality = _norm(asset.business_criticality)
    if criticality == "high":
        score += 10
        reasons.append("HIGH_BUSINESS_CRITICALITY")
    elif criticality == "medium":
        score += 6
        reasons.append("MEDIUM_BUSINESS_CRITICALITY")
    else:
        score += 3
        reasons.append("LOW_BUSINESS_CRITICALITY")

    if asset.legacy_flag:
        score += 10
        reasons.append("LEGACY_TRANSITION_COMPLEXITY")

    if "sha1" in _norm(scan.signature_algorithm):
        score += 8
        reasons.append("SHA1_SIGNATURE_ADDITIONAL_RISK")

    if scan.scan_status == "failed" or scan.error_message:
        score += 5
        reasons.append("SCAN_FAILURE_UNCERTAINTY")

    score = max(0, min(100, int(score)))
    return score, level_from_score(score), reasons
