from osint.core.models import ScanReport


def render_markdown(report: ScanReport) -> str:
    lines = [
        f"# OSINT Report — {report.target}",
        "",
        f"- **Type:** {report.target_type}",
        f"- **Risk:** {report.risk_level.value} (score {report.risk_score})",
        f"- **Scanned:** {report.started_at.isoformat()}",
        "",
    ]
    for mod in report.modules:
        status = "ok" if mod.ok else f"FAILED: {mod.error}"
        lines.append(f"## {mod.module} ({status}, {mod.duration_ms} ms)")
        if not mod.findings:
            lines.append("_No findings._\n")
            continue
        lines.append("")
        lines.append("| Severity | Title | Detail |")
        lines.append("| --- | --- | --- |")
        for f in mod.findings:
            detail = f.detail.replace("\n", "<br>").replace("|", "\\|")
            lines.append(f"| {f.severity.value} | {f.title} | {detail} |")
        lines.append("")
    return "\n".join(lines)
