from datetime import datetime
from osint.core.models import Severity, Finding, ModuleResult, ScanReport


def test_finding_defaults():
    f = Finding(module="dns", title="A record", detail="1.2.3.4")
    assert f.severity is Severity.INFO
    assert f.data == {}


def test_scanreport_json_roundtrip():
    now = datetime(2026, 7, 16, 12, 0, 0)
    report = ScanReport(
        target="example.com",
        target_type="domain",
        started_at=now,
        finished_at=now,
        modules=[ModuleResult(module="dns", ok=True, error=None, duration_ms=5,
                              findings=[Finding(module="dns", title="A", detail="1.1.1.1")])],
        risk_score=3,
        risk_level=Severity.LOW,
    )
    dumped = report.model_dump_json()
    restored = ScanReport.model_validate_json(dumped)
    assert restored.target == "example.com"
    assert restored.modules[0].findings[0].title == "A"
    assert restored.risk_level is Severity.LOW
