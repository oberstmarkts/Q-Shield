from __future__ import annotations

from pathlib import Path

from .io_utils import load_assets_csv, load_scan_results_json, write_csv_rows
from .models import AssetRecord, ScanResult, RiskResult
from .recommendation import action_due_for_level, build_recommendation, dod_for_level
from .risk import calculate_q_risk
from app.scanner.tls_scanner import scan_tls_asset


def _blank_scan(asset: AssetRecord) -> ScanResult:
    return ScanResult(
        asset_id=asset.asset_id,
        scan_status="not_scanned",
        public_key_algorithm="unknown",
        error_message="No scan result available for this asset.",
    )


def analyze_assets(
    assets: list[AssetRecord],
    scan_results: dict[str, ScanResult] | None = None,
    scan_mode: bool = False,
    timeout: float = 5.0,
    allow_scan: bool = False,
) -> list[RiskResult]:
    scan_results = scan_results or {}
    output: list[RiskResult] = []

    for asset in assets:
        if scan_mode:
            if allow_scan and asset.allowed_to_scan:
                scan = scan_tls_asset(asset.hostname, asset.port, timeout=timeout, asset_id=asset.asset_id)
            else:
                scan = ScanResult(
                    asset_id=asset.asset_id,
                    scan_status="blocked",
                    public_key_algorithm="unknown",
                    error_message="Scan blocked. Set --allow-scan and allowed_to_scan=true only for authorized assets.",
                )
        else:
            scan = scan_results.get(asset.asset_id, _blank_scan(asset))

        score, level, reasons = calculate_q_risk(asset, scan)
        rec = build_recommendation(asset, scan, level, reasons)
        result = RiskResult(
            asset_id=asset.asset_id,
            hostname=asset.hostname,
            port=asset.port,
            q_risk_score=score,
            risk_level=level,
            reason_codes=reasons,
            recommendation=rec,
            action_due=action_due_for_level(level),
            dod=dod_for_level(level),
            evidence_id=f"EVID-QSHIELD-{asset.asset_id}",
            extra={
                "exposure": asset.exposure,
                "data_sensitivity": asset.data_sensitivity,
                "business_criticality": asset.business_criticality,
                "legacy_flag": asset.legacy_flag,
                "owner_token": asset.owner_token,
                "scan_status": scan.scan_status,
                "tls_version": scan.tls_version,
                "cipher_suite": scan.cipher_suite,
                "subject": scan.subject,
                "issuer": scan.issuer,
                "days_to_expiry": scan.days_to_expiry,
                "public_key_algorithm": scan.public_key_algorithm,
                "public_key_size": scan.public_key_size,
                "curve": scan.curve,
                "signature_algorithm": scan.signature_algorithm,
                "error_message": scan.error_message,
            },
        )
        output.append(result)

    output.sort(key=lambda r: r.q_risk_score, reverse=True)
    return output


def results_to_rows(results: list[RiskResult]) -> list[dict]:
    rows: list[dict] = []
    for r in results:
        row = {
            "asset_id": r.asset_id,
            "hostname": r.hostname,
            "port": r.port,
            "q_risk_score": r.q_risk_score,
            "risk_level": r.risk_level,
            "reason_codes": ";".join(r.reason_codes),
            "recommendation": r.recommendation,
            "action_due": r.action_due,
            "dod": r.dod,
            "evidence_id": r.evidence_id,
        }
        row.update(r.extra)
        rows.append(row)
    return rows


def run_offline(
    assets_path: str | Path = "data/sample_assets.csv",
    offline_results_path: str | Path = "data/offline_scan_results.json",
    reports_dir: str | Path = "reports",
) -> list[RiskResult]:
    assets = load_assets_csv(assets_path)
    scans = load_scan_results_json(offline_results_path)
    results = analyze_assets(assets, scans, scan_mode=False)
    rows = results_to_rows(results)
    write_csv_rows(Path(reports_dir) / "q_risk_results.csv", rows)
    return results


def run_scan(
    assets_path: str | Path,
    reports_dir: str | Path = "reports",
    timeout: float = 5.0,
    allow_scan: bool = False,
) -> list[RiskResult]:
    assets = load_assets_csv(assets_path)
    results = analyze_assets(assets, scan_mode=True, timeout=timeout, allow_scan=allow_scan)
    rows = results_to_rows(results)
    write_csv_rows(Path(reports_dir) / "q_risk_results.csv", rows)
    return results
