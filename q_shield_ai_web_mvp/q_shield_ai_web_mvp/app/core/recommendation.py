from __future__ import annotations

from .models import AssetRecord, ScanResult


def action_due_for_level(level: str) -> str:
    return {
        "Critical": "7 days",
        "High": "30 days",
        "Medium": "90 days",
        "Low": "Next regular review",
    }.get(level, "Next regular review")


def dod_for_level(level: str) -> str:
    return {
        "Critical": "Impact table, change ticket, test plan, and PQC transition schedule are registered.",
        "High": "Vendor PQC support status, certificate renewal plan, and migration priority are documented.",
        "Medium": "Asset metadata is completed and reviewed in the next inventory cycle.",
        "Low": "Asset remains in routine monitoring and is reassessed in the next snapshot.",
    }.get(level, "Reassess in the next snapshot.")


def build_recommendation(asset: AssetRecord, scan: ScanResult, level: str, reasons: list[str]) -> str:
    parts: list[str] = []

    if level == "Critical":
        parts.append("Register immediate change control and prepare a 7-day PQC transition plan.")
    elif level == "High":
        parts.append("Confirm migration priority and vendor PQC roadmap within 30 days.")
    elif level == "Medium":
        parts.append("Complete asset inventory metadata and schedule a 90-day review.")
    else:
        parts.append("Keep the asset in routine monitoring and reassess at the next snapshot.")

    alg = (scan.public_key_algorithm or "unknown").upper()
    if any(token in alg for token in ["RSA", "ECDSA", "ECDH", "DSA", "EC"]):
        parts.append(f"Current public key algorithm `{scan.public_key_algorithm}` is treated as Q-Day transition target; review ML-KEM, ML-DSA, and hybrid TLS readiness.")

    if asset.exposure.lower() == "external":
        parts.append("External exposure increases HNDL priority; reduce exposure where possible and prioritize certificate lifecycle control.")

    if asset.data_sensitivity.lower() == "high":
        parts.append("High data sensitivity raises migration priority because long-retention data may require earlier protection.")

    if asset.legacy_flag:
        parts.append("Legacy dependency is present; add compatibility testing and rollback planning before certificate or TLS stack migration.")

    if scan.days_to_expiry is not None and scan.days_to_expiry <= 90:
        parts.append(f"Certificate expires in {scan.days_to_expiry} days; align renewal with cryptographic transition planning.")

    if scan.error_message:
        parts.append("Scan uncertainty exists; rerun scan on an authorized network before final executive reporting.")

    return " ".join(parts)
