from datetime import datetime, timezone

from osint.core.models import Finding, ModuleResult, ScanReport, Severity
from osint.summary import summarize


def _report(modules, level=Severity.MEDIUM, score=6):
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)
    return ScanReport(target="example.com", target_type="domain", started_at=now,
                      finished_at=now, modules=modules, risk_score=score, risk_level=level)


def test_heuristic_mentions_risk_and_counts():
    modules = [
        ModuleResult(module="ports", ok=True, duration_ms=1, findings=[
            Finding(module="ports", title="Port 443/tcp open", detail="", severity=Severity.LOW),
            Finding(module="ports", title="Port 80/tcp open", detail="", severity=Severity.LOW)]),
        ModuleResult(module="headers", ok=True, duration_ms=1, findings=[
            Finding(module="headers", title="Missing Content-Security-Policy", detail="",
                    severity=Severity.MEDIUM)]),
    ]
    text = summarize(_report(modules))
    assert "example.com" in text
    assert "MEDIUM" in text
    # references the finding volume and a notable item
    assert "3 findings" in text
    assert "Content-Security-Policy" in text or "headers" in text


def test_heuristic_empty_report():
    text = summarize(_report([], level=Severity.INFO, score=0))
    assert "example.com" in text
    assert "no findings" in text.lower() or "0 findings" in text


def test_use_llm_without_key_falls_back(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    text = summarize(_report([]), use_llm=True)
    assert "example.com" in text  # heuristic, no crash
