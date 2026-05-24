# Threat Model

## Problem

Q-Day may break widely used public-key cryptography such as RSA and ECC. Organizations need an inventory of cryptographic assets before migration planning.

## Scope

- TLS endpoints
- X.509 certificate metadata
- Public key algorithm
- Signature algorithm
- Expiry window
- Exposure and business metadata

## Non-Scope

- Implementing PQC algorithms directly
- Unauthorized scanning
- Storing real secrets or personal data
- Internet-wide scanning

## Controls

- Offline-first sample data
- Explicit authorization flag for scan mode
- Timeout-bound scanner
- DLP fail-closed report generation
- Evidence manifest with hashes
