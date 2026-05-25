from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .dlp import assert_no_sensitive_text

SAFE_TEXT_RE = re.compile(r"^[A-Za-z0-9_.:/@+\-\s\[\](),=;#]{0,5000}$")
ASSET_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$|^(?:\d{1,3}\.){3}\d{1,3}$")
OWNER_TOKEN_RE = re.compile(r"^token_[A-Za-z0-9_]{2,32}$")
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")
ALLOWED_LEVEL_VALUES = {"high", "medium", "low"}
ALLOWED_EXPOSURE_VALUES = {"external", "internal"}
DEFAULT_MAX_UPLOAD_BYTES = 1_048_576
DEFAULT_MAX_ASSETS = 200


class SecurityValidationError(ValueError):
    """Raised when fail-closed input validation blocks unsafe input."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assert_upload_size(data: bytes, max_bytes: int = DEFAULT_MAX_UPLOAD_BYTES) -> None:
    if len(data) > max_bytes:
        raise SecurityValidationError(
            f"Upload blocked. Cause=file_size_exceeds_{max_bytes}_bytes; "
            "Impact=analysis not executed; Scope=current upload; "
            "Action=reduce CSV size; DoD=upload size is within policy."
        )


def sanitize_error(exc: Exception) -> str:
    text = str(exc).replace("\n", " ").replace("\r", " ")
    return text[:240] if text else exc.__class__.__name__


def csv_safe_cell(value: Any) -> Any:
    """Neutralize spreadsheet formula injection when exporting CSV."""
    if value is None:
        return ""
    if isinstance(value, (int, float, bool)):
        return value
    text = str(value)
    if text and text[0] in CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


def sanitize_csv_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: csv_safe_cell(value) for key, value in row.items()}


def assert_safe_asset_fields(row: dict[str, Any], row_number: int) -> None:
    asset_id = str(row.get("asset_id", "")).strip()
    hostname = str(row.get("hostname", "")).strip()
    owner_token = str(row.get("owner_token", "token_24")).strip() or "token_24"
    exposure = str(row.get("exposure", "internal")).strip().lower()
    sensitivity = str(row.get("data_sensitivity", "low")).strip().lower()
    criticality = str(row.get("business_criticality", "low")).strip().lower()

    if not ASSET_ID_RE.match(asset_id):
        raise SecurityValidationError(f"CSV row {row_number} blocked. Cause=invalid_asset_id; DoD=use 1-64 chars of letters, numbers, dot, dash, underscore, or colon.")
    if not HOST_RE.match(hostname):
        raise SecurityValidationError(f"CSV row {row_number} blocked. Cause=invalid_hostname; DoD=use a valid hostname or IPv4 address.")
    if exposure not in ALLOWED_EXPOSURE_VALUES:
        raise SecurityValidationError(f"CSV row {row_number} blocked. Cause=invalid_exposure; DoD=use external or internal.")
    if sensitivity not in ALLOWED_LEVEL_VALUES:
        raise SecurityValidationError(f"CSV row {row_number} blocked. Cause=invalid_data_sensitivity; DoD=use high, medium, or low.")
    if criticality not in ALLOWED_LEVEL_VALUES:
        raise SecurityValidationError(f"CSV row {row_number} blocked. Cause=invalid_business_criticality; DoD=use high, medium, or low.")
    if not OWNER_TOKEN_RE.match(owner_token):
        raise SecurityValidationError(f"CSV row {row_number} blocked. Cause=invalid_owner_token; DoD=use token_24 style pseudonymous owner token.")
    try:
        port = int(row.get("port") or 443)
    except ValueError as exc:
        raise SecurityValidationError(f"CSV row {row_number} blocked. Cause=invalid_port; DoD=use integer 1-65535.") from exc
    if not (1 <= port <= 65535):
        raise SecurityValidationError(f"CSV row {row_number} blocked. Cause=port_out_of_range; DoD=use port 1-65535.")


def assert_csv_text_is_safe(text: str) -> None:
    assert_no_sensitive_text(text)
    # Keep uploaded CSV simple enough for MVP and block binary/control payloads.
    for char in text:
        code = ord(char)
        if code < 32 and char not in "\r\n\t":
            raise SecurityValidationError(
                "CSV upload blocked. Cause=control_character_detected; Impact=analysis not executed; "
                "Scope=current upload; Action=save CSV as UTF-8 text; DoD=zero control characters."
            )


def count_csv_rows(text: str) -> int:
    reader = csv.reader(text.splitlines())
    return max(0, sum(1 for _ in reader) - 1)


def assert_asset_count(text: str, max_assets: int = DEFAULT_MAX_ASSETS) -> None:
    rows = count_csv_rows(text)
    if rows > max_assets:
        raise SecurityValidationError(
            f"CSV upload blocked. Cause=asset_count_exceeds_{max_assets}; Impact=analysis not executed; "
            "Scope=current upload; Action=split the batch or raise policy limit; DoD=asset count within policy."
        )


def is_private_or_loopback_host(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        lowered = hostname.lower().strip(".")
        return lowered in {"localhost"} or lowered.endswith(".local")


def assert_scan_target_allowed(hostname: str, allowed_to_scan: bool) -> None:
    if not allowed_to_scan:
        raise SecurityValidationError(
            "Scan blocked. Cause=allowed_to_scan_false; Impact=network request not sent; "
            "Scope=current asset; Action=set allowed_to_scan=true only for owned or explicitly authorized assets; "
            "DoD=authorization recorded in asset CSV."
        )
    if is_private_or_loopback_host(hostname) and os.getenv("QSHIELD_ALLOW_PRIVATE_SCAN", "0") != "1":
        raise SecurityValidationError(
            "Scan blocked. Cause=private_or_loopback_target; Impact=network request not sent; "
            "Scope=current asset; Action=set QSHIELD_ALLOW_PRIVATE_SCAN=1 only inside an authorized lab; "
            "DoD=lab authorization and target scope are documented."
        )


def append_audit_event(event: dict[str, Any], audit_path: str | Path = "reports/security_audit_log.jsonl") -> None:
    path = Path(audit_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    safe_event = {"timestamp_utc": utc_now_iso(), **event}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(safe_event, ensure_ascii=False, sort_keys=True) + "\n")


def validate_and_write_upload(data: bytes, tmp_path: str | Path, *, max_bytes: int = DEFAULT_MAX_UPLOAD_BYTES, max_assets: int = DEFAULT_MAX_ASSETS) -> dict[str, Any]:
    assert_upload_size(data, max_bytes=max_bytes)
    text = data.decode("utf-8-sig", errors="strict")
    assert_csv_text_is_safe(text)
    assert_asset_count(text, max_assets=max_assets)
    Path(tmp_path).write_bytes(data)
    return {"sha256": sha256_bytes(data), "size_bytes": len(data), "asset_count": count_csv_rows(text)}
