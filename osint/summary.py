import json
import os

from osint.core.models import ScanReport, Severity


def _trimmed_json(report: ScanReport) -> str:
    # Drop per-finding `data` blobs (e.g. a screenshot's base64 PNG) before sending
    # to the LLM — they can be huge and blow up token cost / overflow the context.
    data = report.model_dump(mode="json")
    for module in data.get("modules", []):
        for finding in module.get("findings", []):
            finding.pop("data", None)
    return json.dumps(data)


def _heuristic(report: ScanReport) -> str:
    findings = [f for m in report.modules for f in m.findings]
    n = len(findings)
    parts = [f"{report.target} — risk {report.risk_level.value} (score {report.risk_score})."]
    if n == 0:
        parts.append("No findings surfaced.")
        return " ".join(parts)

    active = [m.module for m in report.modules if m.findings]
    parts.append(f"{n} findings across {len(active)} modules.")

    notable = []
    highs = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
    if highs:
        notable.append(f"{len(highs)} high/critical ({highs[0].title})")
    ports = [f for f in findings if f.module == "ports" and "open" in f.title]
    if ports:
        notable.append(f"{len(ports)} open ports")
    missing = [f for f in findings if f.module == "headers"]
    if missing:
        notable.append(f"{len(missing)} missing security headers")
    subs = next((f for f in findings if f.module == "subdomains"), None)
    if subs:
        notable.append(subs.title.lower())
    if notable:
        parts.append("Notable: " + ", ".join(notable) + ".")
    return " ".join(parts)


def _llm_summary(report: ScanReport) -> str | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    try:
        import anthropic  # optional dependency
    except ImportError:
        return None
    try:
        client = anthropic.Anthropic(api_key=key)
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=200,
            system="You are a security recon analyst. Summarize this scan in 2-3 concise sentences.",
            messages=[{"role": "user", "content": _trimmed_json(report)}],
        )
        text = "".join(block.text for block in message.content if getattr(block, "type", "") == "text")
        return text.strip() or None
    except Exception:  # noqa: BLE001 - any LLM failure must fall back to the heuristic, never raise
        return None


def summarize(report: ScanReport, use_llm: bool = False) -> str:
    if use_llm:
        llm = _llm_summary(report)
        if llm:
            return llm
    return _heuristic(report)
