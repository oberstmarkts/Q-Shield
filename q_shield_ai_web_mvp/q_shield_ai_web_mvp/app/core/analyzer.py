from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .io_utils import load_assets_csv, load_scan_results_json, write_csv_rows
from .models import AssetRecord, ScanResult, RiskResult
from .recommendation import action_due_for_level, build_recommendation, dod_for_level
from .risk import calculate_q_risk
from app.scanner.tls_scanner import scan_tls_asset
from .security import SecurityValidationError, append_audit_event, assert_scan_target_allowed, sanitize_error


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
            try:
                if not allow_scan:
                    raise SecurityValidationError("Scan blocked. Cause=global_allow_scan_false; Impact=network request not sent; Scope=current asset; Action=add --allow-scan only for authorized scope; DoD=authorization recorded.")
                assert_scan_target_allowed(asset.hostname, asset.allowed_to_scan)
                scan = scan_tls_asset(asset.hostname, asset.port, timeout=timeout, asset_id=asset.asset_id)
                append_audit_event({"event": "tls_scan_attempt", "asset_id": asset.asset_id, "hostname": asset.hostname, "port": asset.port, "scan_status": scan.scan_status})
            except Exception as exc:
                scan = ScanResult(
                    asset_id=asset.asset_id,
                    scan_status="blocked",
                    public_key_algorithm="unknown",
                    error_message=sanitize_error(exc),
                )
                append_audit_event({"event": "tls_scan_blocked", "asset_id": asset.asset_id, "hostname": asset.hostname, "port": asset.port, "reason": sanitize_error(exc)})
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


SNAPSHOT_FILENAME = "q_risk_snapshot.json"
DRIFT_THRESHOLD = 0.05  # ±5% run-over-run change trips the alert + temporary lock.


class RiskDriftLockError(Exception):
    """Raised when run-over-run drift exceeds DRIFT_THRESHOLD.

    Report generation must halt (fail-closed temporary lock) until the change is
    reviewed. Breaching metrics are recorded as RCA entries in the snapshot file.
    """

    def __init__(self, message: str, breaches: list[dict]) -> None:
        super().__init__(message)
        self.breaches = breaches


def _aggregate_metrics(results: list[RiskResult]) -> dict:
    total = len(results)
    average_score = round(sum(r.q_risk_score for r in results) / total, 2) if total else 0.0
    critical_count = sum(1 for r in results if r.risk_level == "Critical")
    return {"average_score": average_score, "critical_count": critical_count}


def _relative_change(previous: float, current: float) -> float:
    """Relative change magnitude. A 0 -> nonzero move counts as a full (100%) change."""
    if previous == 0:
        return 0.0 if current == 0 else 1.0
    return abs(current - previous) / abs(previous)


def _write_snapshot(
    path: Path,
    metrics: dict,
    updated_at: str,
    status: str,
    rca: list[dict],
    locked_at: str | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": updated_at,
        "average_score": metrics["average_score"],
        "critical_count": metrics["critical_count"],
        "status": status,
        "rca": rca,
    }
    if locked_at:
        payload["locked_at"] = locked_at
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def evaluate_drift_lock(
    results: list[RiskResult],
    reports_dir: str | Path = "reports",
    threshold: float = DRIFT_THRESHOLD,
) -> dict:
    """Compare current metrics to the previous snapshot and enforce the drift lock.

    1. Read the previous snapshot (average score, Critical count) if present.
    2. Compare it with the current run.
    3. If average score or Critical count moved by >= threshold (±5% default):
       print an alert, append an RCA entry to the snapshot, keep the prior
       baseline, and raise RiskDriftLockError so the caller halts report
       generation (temporary lock).
    4. Otherwise (first run or within tolerance): refresh the snapshot baseline
       and return the current metrics.

    Reset the lock after remediation by deleting the snapshot file (treated as a
    first run) or by restoring metrics within tolerance of the kept baseline.
    """
    reports_dir = Path(reports_dir)
    snapshot_path = reports_dir / SNAPSHOT_FILENAME
    current = _aggregate_metrics(results)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    snapshot: dict = {}
    if snapshot_path.exists():
        try:
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            snapshot = {}

    prev_avg = snapshot.get("average_score")
    prev_critical = snapshot.get("critical_count")

    # First run (no comparable baseline): record the snapshot and continue.
    if prev_avg is None or prev_critical is None:
        _write_snapshot(snapshot_path, current, now, status="ok", rca=list(snapshot.get("rca", [])))
        return current

    previous = {"average_score": prev_avg, "critical_count": prev_critical}
    breaches: list[dict] = []
    for metric, label in (
        ("average_score", "Average Q-Risk Score"),
        ("critical_count", "Critical asset count"),
    ):
        change = _relative_change(float(previous[metric]), float(current[metric]))
        if change >= threshold:
            breaches.append({
                "timestamp": now,
                "metric": metric,
                "label": label,
                "previous": previous[metric],
                "current": current[metric],
                "delta_pct": round(change * 100, 2),
                "threshold_pct": round(threshold * 100, 2),
            })

    if breaches:
        rca = list(snapshot.get("rca", []))
        rca.extend(breaches)
        # Keep the prior baseline so the lock persists until reviewed (step 3, not step 4).
        _write_snapshot(
            snapshot_path,
            {"average_score": prev_avg, "critical_count": prev_critical},
            snapshot.get("updated_at", now),
            status="locked",
            rca=rca,
            locked_at=now,
        )
        for b in breaches:
            print(
                f"[ALERT] {b['label']} drifted {b['delta_pct']}% "
                f"({b['previous']} -> {b['current']}, threshold ±{b['threshold_pct']}%)"
            )
        print(f"[LOCK] Report generation halted (temporary lock). RCA recorded in {snapshot_path}.")
        raise RiskDriftLockError(
            f"Q-Risk drift exceeded ±{round(threshold * 100, 2)}% on {len(breaches)} metric(s); report generation locked.",
            breaches,
        )

    # Within tolerance: refresh the baseline.
    _write_snapshot(snapshot_path, current, now, status="ok", rca=list(snapshot.get("rca", [])))
    return current


def run_offline(
    assets_path: str | Path = "data/sample_assets.csv",
    offline_results_path: str | Path = "data/offline_scan_results.json",
    reports_dir: str | Path = "reports",
    check_drift: bool = True,
) -> list[RiskResult]:
    assets = load_assets_csv(assets_path)
    scans = load_scan_results_json(offline_results_path)
    results = analyze_assets(assets, scans, scan_mode=False)
    if check_drift:
        evaluate_drift_lock(results, reports_dir)  # raises RiskDriftLockError on a ±5% breach
    rows = results_to_rows(results)
    write_csv_rows(Path(reports_dir) / "q_risk_results.csv", rows)
    return results


def run_scan(
    assets_path: str | Path,
    reports_dir: str | Path = "reports",
    timeout: float = 5.0,
    allow_scan: bool = False,
    check_drift: bool = True,
) -> list[RiskResult]:
    assets = load_assets_csv(assets_path)
    results = analyze_assets(assets, scan_mode=True, timeout=timeout, allow_scan=allow_scan)
    if check_drift:
        evaluate_drift_lock(results, reports_dir)  # raises RiskDriftLockError on a ±5% breach
    rows = results_to_rows(results)
    write_csv_rows(Path(reports_dir) / "q_risk_results.csv", rows)
    return results
