from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_der_certificate(der_bytes: bytes) -> dict[str, Any]:
    """Parse DER certificate bytes.

    This function uses cryptography when available. It returns a stable dict
    even when parsing fails, so the scanner can continue safely.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
        cert = x509.load_der_x509_certificate(der_bytes)
        public_key = cert.public_key()

        alg = "unknown"
        size = None
        curve = ""
        if isinstance(public_key, rsa.RSAPublicKey):
            alg = "RSA"
            size = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            alg = "ECDSA"
            size = public_key.key_size
            curve = public_key.curve.name
        elif isinstance(public_key, dsa.DSAPublicKey):
            alg = "DSA"
            size = public_key.key_size
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            alg = "Ed25519"
            size = 256
            curve = "Ed25519"
        elif isinstance(public_key, ed448.Ed448PublicKey):
            alg = "Ed448"
            size = 456
            curve = "Ed448"

        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc
        days = (not_after - now).days

        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": not_after.isoformat(),
            "days_to_expiry": days,
            "public_key_algorithm": alg,
            "public_key_size": size,
            "curve": curve,
            "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
            "error_message": "",
        }
    except Exception as exc:
        return {
            "subject": "",
            "issuer": "",
            "not_before": "",
            "not_after": "",
            "days_to_expiry": None,
            "public_key_algorithm": "unknown",
            "public_key_size": None,
            "curve": "",
            "signature_algorithm": "",
            "error_message": f"certificate parse failed: {exc}",
        }
