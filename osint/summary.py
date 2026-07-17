from osint.core.models import ScanReport, Severity


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


def summarize(report: ScanReport, use_llm: bool = False) -> str:
    # LLM path added in a later task; heuristic is always the fallback.
    return _heuristic(report)
