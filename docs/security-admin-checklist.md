# Q-Shield GitHub Security Admin Checklist

Snapshot: 2026-05-23 00:00 UTC / 2026-05-23 09:00 KST
Repository: `oberstmarkts/Q-Shield`
Owner token: `token_24_PM`
Review token: `token_24_SEC`

## 1. Applied Repository File Controls

| Status | Control | Evidence | Owner | DoD |
|---|---|---|---|---|
| Done | Security policy added | `SECURITY.md` | `token_24_SEC` | Private vulnerability reporting path exists |
| Done | Code owners added | `.github/CODEOWNERS` | `token_24_PM` | Default reviewer ownership is defined |
| Done | Dependabot configuration added | `.github/dependabot.yml` | `token_24_SEC` | Weekly dependency checks are configured |
| Done | CodeQL workflow added | `.github/workflows/codeql.yml` | `token_24_SEC` | Static security analysis workflow exists |
| Done | Local environment example added | `.env.example` | `token_24_DEV` | Real secrets stay outside Git |
| Done | Git ignore rule exists | `.gitignore` | `token_24_DEV` | Secret and generated files are excluded |

## 2. Admin UI Controls Still Required

These settings require GitHub repository or organization Settings UI access.

| Status | Control | Required Setting | Owner | Due | DoD |
|---|---|---|---|---|---|
| Action Required | Repository visibility | Set to `Private` during development | `token_24_PM` | 2026-05-24 | Repository shows Private |
| Action Required | Main branch protection | Require PR before merging | `token_24_PM` | 2026-05-24 | Direct push to main is blocked |
| Action Required | Pull request approval | Require at least 1 approval | `token_24_PM` | 2026-05-24 | PR cannot merge without approval |
| Action Required | CODEOWNERS review | Require review from Code Owners | `token_24_PM` | 2026-05-24 | CODEOWNERS review is enforced |
| Action Required | Stale approval handling | Dismiss stale approvals | `token_24_PM` | 2026-05-24 | New commits invalidate prior approval |
| Action Required | Conversation resolution | Require conversation resolution before merge | `token_24_PM` | 2026-05-24 | Unresolved threads block merge |
| Action Required | Force push protection | Block force pushes | `token_24_PM` | 2026-05-24 | Force push is disabled |
| Action Required | Branch deletion protection | Block branch deletion | `token_24_PM` | 2026-05-24 | Main cannot be deleted |
| Action Required | Dependency graph | Enable dependency graph | `token_24_SEC` | 2026-05-24 | Dependency graph is active |
| Action Required | Dependabot alerts | Enable alerts | `token_24_SEC` | 2026-05-24 | Vulnerable dependencies create alerts |
| Action Required | Dependabot security updates | Enable security updates | `token_24_SEC` | 2026-05-24 | Security update PRs are created |
| Action Required | Secret scanning | Enable secret scanning when available | `token_24_SEC` | 2026-05-24 | Secret alerts are active |
| Action Required | Push protection | Enable push protection when available | `token_24_SEC` | 2026-05-24 | Secret pushes are blocked |
| Action Required | Actions permissions | Allow trusted actions only | `token_24_SEC` | 2026-05-24 | Workflow actions are restricted |
| Action Required | Workflow token permissions | Set default GITHUB_TOKEN to read-only | `token_24_SEC` | 2026-05-24 | Workflows use least privilege by default |

## 3. Recommended Branch Rule for `main`

- Require a pull request before merging.
- Require at least one approval.
- Dismiss stale pull request approvals when new commits are pushed.
- Require review from Code Owners.
- Require status checks to pass before merging.
- Require conversation resolution before merging.
- Require linear history when team workflow is ready.
- Do not allow force pushes.
- Do not allow deletions.
- Restrict who can push to matching branches.

## 4. Permission Review

| Account | Current Result | Recommended Permission | Action |
|---|---:|---:|---|
| `oberstmarkts` | Admin | Admin | Keep |
| `jjung220555` | Write | Write | Keep if active contributor |
| `jbg080` | No repository permission returned | Write or Read | Invite only if active contributor |
| `rakseungchoegoodgood` | No repository permission returned | Write or Read | Invite only if active contributor |
| `sdcv0383` | No repository permission returned | Write or Read | Invite only if active contributor |

## 5. Public Release Gate

Before changing the repository to Public, complete the following:

- Security alerts are zero or accepted with documented rationale.
- No real `.env`, token, password, private key, production log, or personal data exists in the repository.
- CodeQL workflow has run at least once.
- Dependabot configuration is active.
- README describes project scope without exposing private infrastructure.
- Presentation artifacts do not include personal data or credentials.
- Final approval is recorded by `token_24_PM` and `token_24_SEC`.

## 6. Recheck Plan

Next recheck date: 2026-05-24 00:00 UTC / 2026-05-24 09:00 KST

Recheck method:

1. Confirm Settings UI controls.
2. Confirm CodeQL workflow execution result.
3. Confirm Dependabot alerts and security updates are active.
4. Confirm repository visibility.
5. Confirm collaborator permissions.
6. Record changes in this checklist.
