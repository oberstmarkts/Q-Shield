# Security Checklist

| Item | Status |
|---|---|
| Offline demo succeeds | □ |
| No real `.env` committed | □ |
| No real API keys or tokens | □ |
| No personal data in sample data | □ |
| DLP check passes | □ |
| TLS scan uses only authorized assets | □ |
| CSV report generated | □ |
| Markdown report generated | □ |
| Evidence manifest generated | □ |
| Pytest passes | □ |
| `QSHIELD_ALLOW_PRIVATE_SCAN` unset in production | □ |

## Lab Override: `QSHIELD_ALLOW_PRIVATE_SCAN`

Private and loopback targets (e.g. `127.0.0.1`, `localhost`, `10.0.0.0/8`, `192.168.0.0/16`, `*.local`) are **blocked by default** (fail-closed), even when `--allow-scan` is set and a row has `allowed_to_scan=true`.

| Condition | Private / localhost scan |
|---|---|
| `QSHIELD_ALLOW_PRIVATE_SCAN` unset (default `"0"`) | **Blocked** |
| `QSHIELD_ALLOW_PRIVATE_SCAN` set to any value other than `"1"` | **Blocked** |
| `QSHIELD_ALLOW_PRIVATE_SCAN="1"` | **Allowed** |

- Enable **only** inside an authorized lab where you own the targets and the scope is documented.
- **Never set this in production.** It bypasses the private/loopback guard and can send network requests to internal hosts.
- The override only lifts the private/loopback guard; the other gates (`--allow-scan` flag and per-row `allowed_to_scan=true`) still apply.
- Unset the variable after the lab session so the default fail-closed behavior is restored.
