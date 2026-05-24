# Q-Risk Formula

| Factor | Score |
|---|---:|
| RSA/ECC/DSA public key | 30 |
| External exposure | 20 |
| Data sensitivity | 5/12/20 |
| Certificate expiry | 0/5/10 |
| Business criticality | 3/6/10 |
| Legacy flag | 10 |
| SHA1 signature | 8 |
| Scan failure uncertainty | 5 |

The score is capped at 100.

## Levels

- Critical: 85-100
- High: 70-84
- Medium: 40-69
- Low: 0-39
