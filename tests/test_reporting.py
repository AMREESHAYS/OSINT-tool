from datetime import datetime, timezone

from osint.core.models import Finding, ModuleResult, ScanReport, Severity
from osint.reporting.json_report import render_json
from osint.reporting.markdown_report import render_markdown
from osint.reporting.html_report import render_html


def _report():
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)
    return ScanReport(
        target="example.com", target_type="domain", started_at=now, finished_at=now,
        modules=[ModuleResult(module="headers", ok=True, duration_ms=12, findings=[
            Finding(module="headers", title="Missing CSP", detail="no csp", severity=Severity.MEDIUM)])],
        risk_score=2, risk_level=Severity.MEDIUM,
    )


def test_json_roundtrips():
    out = render_json(_report())
    restored = ScanReport.model_validate_json(out)
    assert restored.target == "example.com"


def test_markdown_has_target_and_finding():
    out = render_markdown(_report())
    assert "example.com" in out and "Missing CSP" in out and "MEDIUM" in out


def test_html_is_self_contained():
    out = render_html(_report())
    assert out.strip().startswith("<!DOCTYPE html>")
    assert "example.com" in out and "Missing CSP" in out
    # self-contained: no external asset references
    assert "http://" not in out.split("</head>")[0]
    assert "<style>" in out
