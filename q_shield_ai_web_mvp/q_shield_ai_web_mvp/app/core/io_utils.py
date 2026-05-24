from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from .models import AssetRecord, ScanResult


def parse_bool(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def load_assets_csv(path: str | Path) -> list[AssetRecord]:
    records: list[AssetRecord] = []
    with Path(path).open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required = {"asset_id", "hostname", "port", "exposure", "data_sensitivity", "business_criticality", "legacy_flag", "owner_token"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing required CSV columns: {', '.join(sorted(missing))}")
        for row in reader:
            records.append(
                AssetRecord(
                    asset_id=row.get("asset_id", "").strip(),
                    hostname=row.get("hostname", "").strip(),
                    port=int(row.get("port") or 443),
                    exposure=row.get("exposure", "internal").strip().lower(),
                    data_sensitivity=row.get("data_sensitivity", "low").strip().lower(),
                    business_criticality=row.get("business_criticality", "low").strip().lower(),
                    legacy_flag=parse_bool(row.get("legacy_flag")),
                    owner_token=row.get("owner_token", "token_24").strip() or "token_24",
                    allowed_to_scan=parse_bool(row.get("allowed_to_scan", "false")),
                )
            )
    return records


def load_scan_results_json(path: str | Path) -> dict[str, ScanResult]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    results: dict[str, ScanResult] = {}
    for item in data:
        results[item["asset_id"]] = ScanResult(
            asset_id=item["asset_id"],
            scan_status=item.get("scan_status", "offline_sample"),
            tls_version=item.get("tls_version", ""),
            cipher_suite=item.get("cipher_suite", ""),
            subject=item.get("subject", ""),
            issuer=item.get("issuer", ""),
            not_before=item.get("not_before", ""),
            not_after=item.get("not_after", ""),
            days_to_expiry=item.get("days_to_expiry"),
            public_key_algorithm=item.get("public_key_algorithm", "unknown"),
            public_key_size=item.get("public_key_size"),
            curve=item.get("curve", ""),
            signature_algorithm=item.get("signature_algorithm", ""),
            error_message=item.get("error_message", ""),
        )
    return results


def write_csv_rows(path: str | Path, rows: Iterable[dict]) -> None:
    rows = list(rows)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
