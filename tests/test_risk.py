from osint.core.models import Finding, Severity
from osint.modules.risk import evaluate


def _f(sev):
    return Finding(module="x", title="t", detail="d", severity=sev)


def test_empty_is_info():
    assert evaluate([]) == (0, Severity.INFO)


def test_low_bucket():
    assert evaluate([_f(Severity.LOW)]) == (1, Severity.LOW)


def test_medium_bucket():
    score, level = evaluate([_f(Severity.MEDIUM), _f(Severity.LOW)])
    assert score == 3 and level is Severity.MEDIUM


def test_high_bucket():
    score, level = evaluate([_f(Severity.HIGH), _f(Severity.MEDIUM), _f(Severity.LOW)])
    assert score == 8 and level is Severity.HIGH


def test_critical_bucket():
    score, level = evaluate([_f(Severity.CRITICAL), _f(Severity.HIGH)])
    assert score == 15 and level is Severity.CRITICAL
