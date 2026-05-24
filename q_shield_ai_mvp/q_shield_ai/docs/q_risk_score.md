# Q-Risk Score Policy

| Factor | Weight |
|---|---:|
| RSA/ECC/DSA quantum-vulnerable public key | 30 |
| External exposure | 20 |
| Data sensitivity | 5~20 |
| Certificate expiry | 0~10 |
| Business criticality | 3~10 |
| Legacy flag | 10 |
| SHA1 signature bonus risk | 8 |
| Scan failure uncertainty | 5 |

## Levels

- Critical: 85~100
- High: 70~84
- Medium: 40~69
- Low: 0~39
