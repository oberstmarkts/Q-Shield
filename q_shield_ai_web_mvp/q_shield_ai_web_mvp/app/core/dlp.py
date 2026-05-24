import re


DLP_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{24,}"),
    "korean_rrn": re.compile(r"\b\d{6}-[1-4]\d{6}\b"),
    "phone_kr": re.compile(r"\b01[016789]-?\d{3,4}-?\d{4}\b"),
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
            f"DLP check blocked report generation. Cause={joined}; "
            "Impact=report not generated; Scope=current output; "
            "Action=remove or mask sensitive data; DoD=rerun with zero findings."
        )
