from __future__ import annotations

import socket
import ssl

from .cert_parser import parse_der_certificate
from app.core.models import ScanResult


def scan_tls_asset(hostname: str, port: int = 443, timeout: float = 5.0, asset_id: str = "") -> ScanResult:
    """Safely scan a single authorized TLS endpoint.

    This is intentionally single-target and timeout-bound. Batch callers must
    check authorization before calling this function.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, int(port)), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                parsed = parse_der_certificate(cert_der or b"")
                cipher = ssock.cipher()
                return ScanResult(
                    asset_id=asset_id or hostname,
                    scan_status="success",
                    tls_version=ssock.version() or "",
                    cipher_suite=cipher[0] if cipher else "",
                    subject=parsed.get("subject", ""),
                    issuer=parsed.get("issuer", ""),
                    not_before=parsed.get("not_before", ""),
                    not_after=parsed.get("not_after", ""),
                    days_to_expiry=parsed.get("days_to_expiry"),
                    public_key_algorithm=parsed.get("public_key_algorithm", "unknown"),
                    public_key_size=parsed.get("public_key_size"),
                    curve=parsed.get("curve", ""),
                    signature_algorithm=parsed.get("signature_algorithm", ""),
                    error_message=parsed.get("error_message", ""),
                )
    except Exception as exc:
        return ScanResult(
            asset_id=asset_id or hostname,
            scan_status="failed",
            public_key_algorithm="unknown",
            error_message=str(exc),
        )
