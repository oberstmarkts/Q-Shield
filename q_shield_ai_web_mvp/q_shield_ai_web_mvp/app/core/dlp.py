import re


DLP_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "korean_rrn": re.compile(r"\b\d{6}-[1-4]\d{6}\b"),
    "phone_kr": re.compile(r"\b01[016789]-?\d{3,4}-?\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "access_key_like": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
}


class DLPViolation(ValueError):
    pass


def detect_sensitive_text(text: str) -> list[str]:
    findings: list[str] = []
    for name, pattern in DLP_PATTERNS.items():
        if pattern.search(text or ""):
            findings.append(name)
    return findings


def assert_no_sensitive_text(text: str) -> None:
    findings = detect_sensitive_text(text)
    if findings:
        joined = ", ".join(findings)
        raise DLPViolation(
            f"DLP check blocked publication. Cause={joined}; "
            "Impact=report or upload analysis not generated; Scope=current data; "
            "Action=remove or mask sensitive data; DoD=rerun with zero DLP findings."
        )
