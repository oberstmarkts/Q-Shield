from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives import serialization


def _dt_to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def _safe_name(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def parse_der_certificate(der_bytes: bytes) -> Dict[str, Any]:
    cert = x509.load_der_x509_certificate(der_bytes)
    public_key = cert.public_key()

    public_key_algorithm = "UNKNOWN"
    public_key_size: int | None = None
    curve_name: str | None = None

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_algorithm = "RSA"
        public_key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key_algorithm = "ECDSA"
        public_key_size = public_key.key_size
        curve_name = public_key.curve.name
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key_algorithm = "DSA"
        public_key_size = public_key.key_size

    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_to_expiry = int((not_after - now).total_seconds() // 86400)

    signature_algorithm = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "UNKNOWN"
    if "rsa" in cert.signature_algorithm_oid._name.lower():
        signature_algorithm = f"{signature_algorithm}WithRSAEncryption"
    elif "ecdsa" in cert.signature_algorithm_oid._name.lower():
        signature_algorithm = f"ecdsa-with-{signature_algorithm.upper()}"

    reason_codes: List[str] = []
    if public_key_algorithm == "RSA":
        reason_codes.append("Q_PUBLIC_KEY_RSA")
    if public_key_algorithm in {"ECDSA", "DSA"}:
        reason_codes.append("Q_PUBLIC_KEY_ECC" if public_key_algorithm == "ECDSA" else "Q_PUBLIC_KEY_DSA")
    if signature_algorithm.lower().startswith("sha1"):
        reason_codes.append("WEAK_SIGNATURE_SHA1")
    if days_to_expiry <= 30:
        reason_codes.append("EXPIRY_30D")
    elif days_to_expiry <= 90:
        reason_codes.append("EXPIRY_90D")

    pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    return {
        "subject": _safe_name(cert.subject),
        "issuer": _safe_name(cert.issuer),
        "serial_number": str(cert.serial_number),
        "not_before": _dt_to_iso(not_before),
        "not_after": _dt_to_iso(not_after),
        "days_to_expiry": days_to_expiry,
        "public_key_algorithm": public_key_algorithm,
        "public_key_size": public_key_size,
        "curve_name": curve_name,
        "signature_algorithm": signature_algorithm,
        "q_vulnerable": public_key_algorithm in {"RSA", "ECDSA", "DSA"},
        "reason_codes": reason_codes,
        "certificate_pem_preview": pem[:120] + "...",
    }
