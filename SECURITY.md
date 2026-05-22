# Security Policy

## Supported Scope

This repository supports the Q-Shield final project for the Goorm Information Security Expert Course.

Security review currently applies to:

- Source code committed to this repository
- Documentation related to setup, detection rules, and response workflows
- GitHub Actions workflows
- Dependency configuration files
- Example environment files

## Reporting a Security Issue

Do not open a public issue for secrets, credentials, vulnerable endpoints, private logs, or personal data.

Use the following process:

1. Notify the project owner through a private team channel.
2. Include the affected file path, commit SHA, and reproduction steps when possible.
3. Do not share working exploit details in public discussions.
4. Remove exposed secrets immediately and rotate affected credentials.
5. Record the remediation result in `docs/security-admin-checklist.md`.

## Secret Handling Rules

- Never commit API keys, passwords, tokens, private keys, certificates, personal data, or production logs.
- Use `.env.example` for sample variables.
- Keep real `.env` files outside Git.
- If a secret is committed, treat it as compromised even after deletion.
- Rotate the exposed secret and check Git history before continuing development.

## Maintainer Response Target

| Severity | First Response | Target Fix |
|---|---:|---:|
| Critical | 24 hours | 48 hours |
| High | 48 hours | 7 days |
| Medium | 7 days | 14 days |
| Low | 14 days | 30 days |

## Disclosure Policy

Public disclosure is allowed only after the maintainer confirms remediation and verifies that no sensitive information remains exposed.

## Current Owner

- Primary maintainer: `@oberstmarkts`
