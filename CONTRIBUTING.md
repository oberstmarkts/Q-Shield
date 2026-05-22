# Contributing Guide

## Workflow

1. Create an issue before starting meaningful work.
2. Create a branch from `dev` or `main` using one of the following patterns:
   - `feature/<short-name>`
   - `fix/<short-name>`
   - `docs/<short-name>`
3. Commit changes with clear messages.
4. Open a pull request.
5. Request review from at least one teammate.
6. Merge only after review and basic validation.

## Commit Message Examples

- `feat: add initial detection rule structure`
- `fix: correct log parser error handling`
- `docs: update project setup guide`
- `chore: add gitignore and repository rules`

## Security Rules

- Never commit API keys, tokens, passwords, private keys, credentials, or personal data.
- Use sample values in documentation.
- Use `.env.example` instead of `.env`.
- Report suspicious commits immediately through an issue.

## Pull Request Checklist

- [ ] Related issue is linked.
- [ ] No secrets are included.
- [ ] Documentation is updated if needed.
- [ ] Code or document changes are reviewed.
- [ ] The change can be explained during the final presentation.
