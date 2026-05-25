"""Boundary-value and additive-point tests for the Q-Risk scoring engine.

Covers the score->level cut points (built through the full ``calculate_q_risk``
pipeline) and the individual additive risk factors: SHA1 signature, legacy flag,
and scan failure uncertainty.
"""
import pytest

from app.core.models import AssetRecord, ScanResult
from app.core.risk import calculate_q_risk


def _score(
    public_key_algorithm: str = "Ed25519",
    exposure: str = "internal",
    data_sensitivity: str = "low",
    business_criticality: str = "low",
    days_to_expiry: int | None = 365,
    legacy_flag: bool = False,
    signature_algorithm: str = "sha256",
    scan_status: str = "success",
    error_message: str = "",
):
    """Run the full scoring pipeline and return ``(score, level, reasons)``.

    Defaults are deliberately benign (non-Q algorithm, internal, low/low, fresh
    cert, SHA-256, clean scan) so each test can toggle a single contributor.
    """
    asset = AssetRecord(
        asset_id="T-BOUND",
        hostname="boundary.example.local",
        exposure=exposure,
        data_sensitivity=data_sensitivity,
        business_criticality=business_criticality,
        legacy_flag=legacy_flag,
    )
    scan = ScanResult(
        asset_id="T-BOUND",
        scan_status=scan_status,
        days_to_expiry=days_to_expiry,
        public_key_algorithm=public_key_algorithm,
        signature_algorithm=signature_algorithm,
        error_message=error_message,
    )
    return calculate_q_risk(asset, scan)


# --- Score -> level boundaries (exact scores built through the full pipeline) ---

@pytest.mark.parametrize(
    "kwargs, expected_score, expected_level",
    [
        # 85 = Critical: RSA 30 + external 20 + high-sens 20 + high-crit 10 + expiry<=90 5
        (dict(public_key_algorithm="RSA", exposure="external", data_sensitivity="high",
              business_criticality="high", days_to_expiry=60), 85, "Critical"),
        # 84 = High: RSA 30 + external 20 + high-sens 20 + medium-crit 6 + sha1 8
        (dict(public_key_algorithm="RSA", exposure="external", data_sensitivity="high",
              business_criticality="medium", signature_algorithm="sha1WithRSAEncryption"), 84, "High"),
        # 70 = High: RSA 30 + external 20 + medium-sens 12 + low-crit 3 + expiry<=90 5
        (dict(public_key_algorithm="RSA", exposure="external", data_sensitivity="medium",
              business_criticality="low", days_to_expiry=60), 70, "High"),
        # 69 = Medium: RSA 30 + high-sens 20 + medium-crit 6 + expiry<=90 5 + sha1 8 (internal)
        (dict(public_key_algorithm="RSA", data_sensitivity="high", business_criticality="medium",
              days_to_expiry=60, signature_algorithm="sha1WithRSAEncryption"), 69, "Medium"),
        # 40 = Medium: external 20 + medium-sens 12 + low-crit 3 + expiry<=90 5 (non-Q algorithm)
        (dict(exposure="external", data_sensitivity="medium", business_criticality="low",
              days_to_expiry=60), 40, "Medium"),
        # 39 = Low: high-sens 20 + medium-crit 6 + expiry<=90 5 + sha1 8 (non-Q algorithm, internal)
        (dict(data_sensitivity="high", business_criticality="medium", days_to_expiry=60,
              signature_algorithm="sha1WithRSAEncryption"), 39, "Low"),
    ],
)
def test_score_to_level_boundaries(kwargs, expected_score, expected_level):
    score, level, _ = _score(**kwargs)
    assert score == expected_score
    assert level == expected_level


# --- Additive risk factors (each delta isolates a single contributor) ---

def test_sha1_signature_adds_8():
    base_score, _, base_reasons = _score(signature_algorithm="sha256")
    sha1_score, _, sha1_reasons = _score(signature_algorithm="sha1WithRSAEncryption")
    assert sha1_score - base_score == 8
    assert "SHA1_SIGNATURE_ADDITIONAL_RISK" in sha1_reasons
    assert "SHA1_SIGNATURE_ADDITIONAL_RISK" not in base_reasons


def test_legacy_flag_adds_10():
    base_score, _, base_reasons = _score(legacy_flag=False)
    legacy_score, _, legacy_reasons = _score(legacy_flag=True)
    assert legacy_score - base_score == 10
    assert "LEGACY_TRANSITION_COMPLEXITY" in legacy_reasons
    assert "LEGACY_TRANSITION_COMPLEXITY" not in base_reasons


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(scan_status="failed"),                                  # failed status
        dict(scan_status="success", error_message="connection refused"),  # error message present
    ],
)
def test_scan_failure_adds_5(kwargs):
    base_score, _, base_reasons = _score()
    fail_score, _, fail_reasons = _score(**kwargs)
    assert fail_score - base_score == 5
    assert "SCAN_FAILURE_UNCERTAINTY" in fail_reasons
    assert "SCAN_FAILURE_UNCERTAINTY" not in base_reasons
