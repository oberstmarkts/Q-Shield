from dataclasses import dataclass, field
from typing import Any


@dataclass
class AssetRecord:
    asset_id: str
    hostname: str
    port: int = 443
    exposure: str = "internal"
    data_sensitivity: str = "low"
    business_criticality: str = "low"
    legacy_flag: bool = False
    owner_token: str = "token_24"
    allowed_to_scan: bool = False


@dataclass
class ScanResult:
    asset_id: str
    scan_status: str = "unknown"
    tls_version: str = ""
    cipher_suite: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    days_to_expiry: int | None = None
    public_key_algorithm: str = "unknown"
    public_key_size: int | None = None
    curve: str = ""
    signature_algorithm: str = ""
    error_message: str = ""


@dataclass
class RiskResult:
    asset_id: str
    hostname: str
    port: int
    q_risk_score: int
    risk_level: str
    reason_codes: list[str] = field(default_factory=list)
    recommendation: str = ""
    action_due: str = ""
    dod: str = ""
    evidence_id: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
