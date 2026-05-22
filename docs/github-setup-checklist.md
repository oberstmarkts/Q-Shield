# GitHub Setup Checklist for Q-Shield

## Target Structure

| Item | Target Setting |
|---|---|
| Organization | `q-shield-ai` |
| Repository | `Q-Shield` |
| Owner | Founder + 1 Co-PM |
| Team | `q-shield-devs` |
| Team Permission | `Write` |
| Initial Visibility | `Private` |
| Final Visibility | `Public` after review |

## Required Manual Actions

### 1. Create Organization

Create the GitHub Organization named `q-shield-ai`.

### 2. Install GitHub App Access

After creating the organization, install or authorize the connected GitHub app for `q-shield-ai` so automated checks can access the repository.

### 3. Transfer Repository

Transfer `oberstmarkts/Q-Shield` to `q-shield-ai/Q-Shield`.

### 4. Create Team

Create a team named `q-shield-devs` under the organization.

### 5. Grant Team Access

Grant the `q-shield-devs` team `Write` permission to `q-shield-ai/Q-Shield`.

### 6. Add Members

Add the team members to `q-shield-devs` using their exact GitHub usernames.

Current known permission check:

| Candidate Username | Current Permission on `oberstmarkts/Q-Shield` |
|---|---|
| `jbg080` | not confirmed |
| `rakseungchoegoodgood` | not confirmed |
| `sdcv0383` | not confirmed |
| `jjung220555` | write |

### 7. Set Repository Visibility

Set the repository to `Private` during development. Convert to `Public` only after presentation, secret scan, and team approval.

## Recommended Branch Protection

Protect `main` with the following rules:

- Require pull request before merging.
- Require at least one approval.
- Block force pushes.
- Block branch deletion.
- Require conversation resolution before merge.

## Definition of Done

- Organization exists.
- Repository is owned by the organization.
- Founder and Co-PM are organization owners.
- `q-shield-devs` team exists.
- All active team members have write access through the team.
- Repository is private during development.
- `main` is protected.
