# GitHub Two-Track Management Guide

## Purpose

This guide separates personal-account repositories from the organization-owned final project repository.

## Track A: Personal Account

| Item | Setting |
|---|---|
| Owner | `oberstmarkts` |
| Main use | Personal portfolio, experiments, drafts, private learning notes |
| Repository example | `oberstmarkts/Q-Shield` |
| Permission model | Owner-centered, selective collaborators only |
| Visibility | Public for portfolio-ready work; Private for drafts or sensitive materials |

## Track B: Organization Account

| Item | Setting |
|---|---|
| Organization | `q-shield-ai` |
| Repository | `Final-Project` |
| Main use | Official team final project deliverables |
| Team | `q-shield-devs` |
| Team permission | `Write` |
| Visibility | Private during development; Public after review |
| Governance | PR-based review, issue tracking, evidence-first documentation |

## Separation Rules

1. Personal experiments stay in `oberstmarkts/*` repositories.
2. Official final project code and documentation stay in `q-shield-ai/Final-Project`.
3. Sensitive files, API keys, tokens, credentials, and personal data must never be committed.
4. Team members receive access through organization teams, not through shared passwords.
5. `main` should be protected in the organization repository.
6. Drafts may be prepared in the personal repository, then merged into the organization repository only after review.

## Recommended Organization Repository Setup

### Repository

- Owner: `q-shield-ai`
- Name: `Final-Project`
- Visibility: `Private` during development
- Default branch: `main`

### Teams

| Team | Permission | Purpose |
|---|---|---|
| `q-shield-devs` | `Write` | Active development and documentation |
| `q-shield-maintainers` | `Maintain` | Project management and issue/release control |
| `q-shield-owners` | `Admin` | Founder and Co-PM only |

### Branches

| Branch | Purpose |
|---|---|
| `main` | Reviewed stable deliverables |
| `dev` | Integration branch |
| `feature/*` | Feature work |
| `docs/*` | Documentation work |

## Branch Protection for `main`

- Require pull request before merging.
- Require at least one approval.
- Require conversation resolution before merge.
- Block force pushes.
- Block deletion.
- Prefer including administrators in the rule.

## Initial File Set for `q-shield-ai/Final-Project`

- `README.md`
- `.gitignore`
- `CONTRIBUTING.md`
- `docs/github-two-track-management.md`
- `docs/github-setup-checklist.md`

## Definition of Done

- `q-shield-ai/Final-Project` exists.
- GitHub app access is installed for `q-shield-ai`.
- `q-shield-devs` exists and has `Write` access.
- All active team members are added through teams.
- Repository is private during development.
- `main` is protected.
- Personal-account repository and organization repository roles are clearly separated.
