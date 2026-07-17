from datetime import datetime, timezone

from osint.core.models import Finding, ModuleResult, ScanReport, Severity
from osint.summary import summarize
from osint import summary as summary_mod


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


def test_use_llm_uses_llm_result(monkeypatch):
    monkeypatch.setattr(summary_mod, "_llm_summary", lambda report: "LLM narrative here.")
    text = summarize(_report([]), use_llm=True)
    assert text == "LLM narrative here."


def test_use_llm_falls_back_when_llm_returns_none(monkeypatch):
    monkeypatch.setattr(summary_mod, "_llm_summary", lambda report: None)
    text = summarize(_report([]), use_llm=True)
    assert "example.com" in text  # heuristic fallback


def test_use_llm_false_never_calls_llm(monkeypatch):
    def boom(report):
        raise AssertionError("LLM must not be called when use_llm=False")
    monkeypatch.setattr(summary_mod, "_llm_summary", boom)
    assert "example.com" in summarize(_report([]), use_llm=False)


def test_trimmed_json_drops_finding_data():
    # A screenshot base64 blob must not be sent to the LLM.
    modules = [ModuleResult(module="screenshot", ok=True, duration_ms=1, findings=[
        Finding(module="screenshot", title="Homepage screenshot", detail="Homepage captured.",
                data={"image": "data:image/png;base64,HUGEBLOB"})])]
    out = summary_mod._trimmed_json(_report(modules))
    assert "HUGEBLOB" not in out
    assert "Homepage screenshot" in out  # titles kept
