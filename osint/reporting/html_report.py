from html import escape

from osint.core.models import ScanReport

_COLORS = {
    "INFO": "#6b7280", "LOW": "#2563eb", "MEDIUM": "#d97706",
    "HIGH": "#dc2626", "CRITICAL": "#7c3aed",
}

_CSS = """
body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:900px;color:#111;background:#fafafa}
h1{margin-bottom:.2rem}.meta{color:#555;margin-bottom:1.5rem}
details{background:#fff;border:1px solid #e5e7eb;border-radius:8px;margin:.6rem 0;padding:.6rem 1rem}
summary{font-weight:600;cursor:pointer}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:6px;color:#fff;font-size:.75rem;margin-right:.5rem}
pre{white-space:pre-wrap;background:#f3f4f6;padding:.5rem;border-radius:6px;font-size:.85rem}
.risk{font-size:1.2rem;font-weight:700}
"""


def render_html(report: ScanReport) -> str:
    parts = [
        "<!DOCTYPE html>", "<html lang='en'><head><meta charset='utf-8'>",
        f"<title>OSINT Report — {escape(report.target)}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>OSINT Report — {escape(report.target)}</h1>",
        f"<div class='meta'>Type: {escape(report.target_type)} · "
        f"<span class='risk' style='color:{_COLORS[report.risk_level.value]}'>"
        f"Risk: {report.risk_level.value} ({report.risk_score})</span> · "
        f"{escape(report.started_at.isoformat())}</div>",
    ]
    for mod in report.modules:
        status = "ok" if mod.ok else f"FAILED: {escape(mod.error or '')}"
        parts.append(f"<details open><summary>{escape(mod.module)} "
                     f"<small>({status}, {mod.duration_ms} ms, {len(mod.findings)} findings)</small></summary>")
        for f in mod.findings:
            color = _COLORS[f.severity.value]
            parts.append(f"<p><span class='badge' style='background:{color}'>{f.severity.value}</span>"
                         f"<strong>{escape(f.title)}</strong></p>"
                         f"<pre>{escape(f.detail)}</pre>")
        parts.append("</details>")
    parts.append("</body></html>")
    return "\n".join(parts)
