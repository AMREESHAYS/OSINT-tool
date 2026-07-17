from osint.core.models import Finding, Severity

_WEIGHTS = {
    Severity.CRITICAL: 10, Severity.HIGH: 5,
    Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0,
}


def evaluate(findings: list[Finding]) -> tuple[int, Severity]:
    total = sum(_WEIGHTS[f.severity] for f in findings)
    if total >= 15:
        return total, Severity.CRITICAL
    if total >= 8:
        return total, Severity.HIGH
    if total >= 3:
        return total, Severity.MEDIUM
    if total >= 1:
        return total, Severity.LOW
    return total, Severity.INFO
