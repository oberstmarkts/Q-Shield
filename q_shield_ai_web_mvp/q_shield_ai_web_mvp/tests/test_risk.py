from app.core.models import AssetRecord, ScanResult
from app.core.risk import calculate_q_risk, level_from_score


def test_level_boundaries():
    assert level_from_score(85) == "Critical"
    assert level_from_score(84) == "High"
    assert level_from_score(70) == "High"
    assert level_from_score(69) == "Medium"
    assert level_from_score(40) == "Medium"
    assert level_from_score(39) == "Low"


def test_critical_score_for_external_high_rsa_legacy():
    asset = AssetRecord(
        asset_id="A001",
        hostname="backup.example.local",
        exposure="external",
        data_sensitivity="high",
        business_criticality="high",
        legacy_flag=True,
    )
    scan = ScanResult(asset_id="A001", public_key_algorithm="RSA", days_to_expiry=365, signature_algorithm="sha256")
    score, level, reasons = calculate_q_risk(asset, scan)
    assert score == 90
    assert level == "Critical"
    assert "QALG_PUBLIC_KEY_TRANSITION_REQUIRED" in reasons


def test_low_for_non_q_alg_low_business_external():
    asset = AssetRecord(
        asset_id="A004",
        hostname="static.example.local",
        exposure="external",
        data_sensitivity="low",
        business_criticality="low",
        legacy_flag=False,
    )
    scan = ScanResult(asset_id="A004", public_key_algorithm="Ed25519", days_to_expiry=365)
    score, level, reasons = calculate_q_risk(asset, scan)
    assert score == 28
    assert level == "Low"
