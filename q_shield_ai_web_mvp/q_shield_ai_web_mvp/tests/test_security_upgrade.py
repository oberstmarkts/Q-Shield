import io
import csv
from pathlib import Path

import pytest

from app.core.dlp import DLPViolation, assert_no_sensitive_text
from app.core.io_utils import load_assets_csv, write_csv_rows
from app.core.security import SecurityValidationError, assert_scan_target_allowed


def test_dlp_blocks_email_and_github_token():
    with pytest.raises(DLPViolation):
        assert_no_sensitive_text("contact admin@example.com")
    with pytest.raises(DLPViolation):
        assert_no_sensitive_text("token=ghp_abcdefghijklmnopqrstuvwxyz1234567890")


def test_csv_formula_injection_is_neutralized(tmp_path):
    out = tmp_path / "out.csv"
    write_csv_rows(out, [{"asset_id": "A001", "hostname": "=cmd|' /C calc'!A0"}])
    text = out.read_text(encoding="utf-8-sig")
    assert "'=cmd" in text


def test_asset_csv_validation_blocks_bad_hostname(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text(
        "asset_id,hostname,port,exposure,data_sensitivity,business_criticality,legacy_flag,owner_token,allowed_to_scan\n"
        "A001,<script>,443,external,high,high,false,token_24,false\n",
        encoding="utf-8",
    )
    with pytest.raises(SecurityValidationError):
        load_assets_csv(path)


def test_private_scan_blocked_by_default():
    with pytest.raises(SecurityValidationError):
        assert_scan_target_allowed("127.0.0.1", True)


def test_web_security_headers_present():
    pytest.importorskip("flask")
    from app.web.server import create_app
    app = create_app()
    client = app.test_client()
    response = client.get("/")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_upload_dlp_fail_closed():
    pytest.importorskip("flask")
    from app.web.server import create_app
    app = create_app()
    client = app.test_client()
    data = {
        "asset_csv": (
            io.BytesIO(
                b"asset_id,hostname,port,exposure,data_sensitivity,business_criticality,legacy_flag,owner_token,allowed_to_scan\n"
                b"A001,example.com,443,external,high,high,false,token_24,false\n"
                b"A002,admin@example.com,443,external,high,high,false,token_24,false\n"
            ),
            "assets.csv",
        )
    }
    response = client.post("/api/analyze", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    assert "DLP" in response.get_json()["error"] or "blocked" in response.get_json()["error"]
