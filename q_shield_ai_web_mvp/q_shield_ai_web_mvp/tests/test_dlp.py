import pytest
from app.core.dlp import DLPViolation, assert_no_sensitive_text, detect_sensitive_text


def test_dlp_allows_normal_report_text():
    assert detect_sensitive_text("Q-Shield AI sample report Owner token_24") == []


def test_dlp_blocks_private_key():
    with pytest.raises(DLPViolation):
        assert_no_sensitive_text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")
