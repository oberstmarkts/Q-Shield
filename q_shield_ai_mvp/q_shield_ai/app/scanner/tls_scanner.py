from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

import pandas as pd

from app.scanner.cert_parser import parse_der_certificate


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def scan_tls_endpoint(hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "hostname": hostname,
        "port": port,
        "scan_time_utc": utc_now_iso(),
        "scan_status": "failed",
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, int(port)), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                result.update({
                    "scan_status": "success",
                    "tls_version": ssock.version(),
                    "cipher_suite": ssock.cipher()[0] if ssock.cipher() else None,
                })
                if der_cert:
                    result.update(parse_der_certificate(der_cert))
                else:
                    result["error_message"] = "No peer certificate returned"
    except Exception as exc:
        result["error_message"] = f"{type(exc).__name__}: {exc}"
        result.setdefault("q_vulnerable", None)
        result.setdefault("reason_codes", ["SCAN_FAILED"])
    return result


def scan_assets_csv(csv_path: str | Path, timeout: float = 5.0) -> List[Dict[str, Any]]:
    df = pd.read_csv(csv_path)
    required = {"asset_id", "hostname", "port", "exposure", "business_criticality", "data_sensitivity", "owner_token", "legacy_flag"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    results: List[Dict[str, Any]] = []
    for _, row in df.iterrows():
        base = row.to_dict()
        scan = scan_tls_endpoint(str(row["hostname"]), int(row["port"]), timeout=timeout)
        merged = {**base, **scan}
        if str(base.get("exposure", "")).lower() == "external":
            merged.setdefault("reason_codes", [])
            if "EXTERNAL_EXPOSURE" not in merged["reason_codes"]:
                merged["reason_codes"].append("EXTERNAL_EXPOSURE")
        if str(base.get("data_sensitivity", "")).lower() == "high":
            merged.setdefault("reason_codes", [])
            if "HIGH_SENSITIVITY" not in merged["reason_codes"]:
                merged["reason_codes"].append("HIGH_SENSITIVITY")
        if str(base.get("legacy_flag", "false")).lower() == "true":
            merged.setdefault("reason_codes", [])
            if "LEGACY_FLAG" not in merged["reason_codes"]:
                merged["reason_codes"].append("LEGACY_FLAG")
        results.append(merged)
    return results


def save_json(results: Iterable[Dict[str, Any]], output_path: str | Path) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(list(results), f, ensure_ascii=False, indent=2)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Q-Shield AI TLS scanner")
    parser.add_argument("--assets", default="data/sample_assets.csv")
    parser.add_argument("--out", default="reports/scan_results.json")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    results = scan_assets_csv(args.assets, timeout=args.timeout)
    save_json(results, args.out)
    print(f"Saved {len(results)} scan results to {args.out}")


if __name__ == "__main__":
    main()
