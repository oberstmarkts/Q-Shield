from app.ai.recommendation_engine import generate_recommendation


def test_recommendation_contains_dod():
    rec = {"hostname": "x", "q_risk_score": 90, "risk_level": "Critical", "reason_codes": ["Q_PUBLIC_KEY_RSA"]}
    text = generate_recommendation(rec)
    assert "DoD" in text
    assert "ML-KEM" in text
