from app.risk.q_risk_score import risk_level, risk_score, score_records


def test_risk_level_boundaries():
    assert risk_level(39) == "Low"
    assert risk_level(40) == "Medium"
    assert risk_level(70) == "High"
    assert risk_level(85) == "Critical"


def test_critical_external_rsa_sensitive():
    rec = {
        "public_key_algorithm": "RSA",
        "q_vulnerable": True,
        "exposure": "external",
        "data_sensitivity": "high",
        "business_criticality": "high",
        "days_to_expiry": 700,
        "legacy_flag": True,
        "reason_codes": []
    }
    assert risk_score(rec) >= 85


def test_score_records_adds_fields():
    records = [{"public_key_algorithm": "RSA", "q_vulnerable": True, "exposure": "internal", "data_sensitivity": "low", "business_criticality": "low", "days_to_expiry": 100}]
    out = score_records(records)
    assert "q_risk_score" in out[0]
    assert "risk_level" in out[0]
