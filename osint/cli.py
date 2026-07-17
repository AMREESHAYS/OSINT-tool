import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table

from osint.core.classify import classify
from osint.core.models import ScanReport, Severity
from osint.core.orchestrator import scan as run_scan
from osint.core.settings import Settings
from osint.modules.registry import all_modules
from osint.reporting.html_report import render_html
from osint.reporting.json_report import render_json
from osint.reporting.markdown_report import render_markdown

app = typer.Typer(add_completion=False, help="OSINT reconnaissance engine — no paid API required.")
console = Console()

_SEV_COLOR = {
    Severity.INFO: "grey62", Severity.LOW: "blue", Severity.MEDIUM: "yellow",
    Severity.HIGH: "red", Severity.CRITICAL: "magenta",
}


@app.command()
def version():
    """Print the version."""
    console.print("osint 1.0.0")


@app.command()
def modules():
    """List available modules and the target types they apply to."""
    table = Table(title="Modules")
    table.add_column("Module")
    table.add_column("Applies to")
    for m in all_modules():
        table.add_row(m.name, ", ".join(sorted(m.applies_to)))
    console.print(table)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain, email, username, or IP"),
    json_out: str = typer.Option(None, "--json", help="Write JSON report to this path"),
    md_out: str = typer.Option(None, "--md", help="Write Markdown report to this path"),
    html_out: str = typer.Option(None, "--html", help="Write HTML report to this path"),
    only: str = typer.Option(None, "--only", help="Comma-separated module names to run"),
    skip: str = typer.Option(None, "--skip", help="Comma-separated module names to skip"),
    no_nmap: bool = typer.Option(False, "--no-nmap", help="Disable port scanning"),
    concurrency: int = typer.Option(20, "--concurrency"),
    timeout: float = typer.Option(10.0, "--timeout"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the live panel and summary (reports still written)"),
):
    """Run a recon scan against TARGET."""
    if classify(target) == "unknown":
        console.print(f"[red]Could not classify target:[/red] {target!r}")
        raise typer.Exit(code=2)

    if not quiet:
        console.print("[dim]Only scan targets you own or are authorized to test.[/dim]")

    mods = all_modules()
    if only:
        wanted = {s.strip() for s in only.split(",")}
        mods = [m for m in mods if m.name in wanted]
    if skip:
        unwanted = {s.strip() for s in skip.split(",")}
        mods = [m for m in mods if m.name not in unwanted]

    settings = Settings(concurrency=concurrency, timeout=timeout, nmap_enabled=not no_nmap)
    statuses: dict[str, str] = {}

    def render_panel() -> Table:
        t = Table(title=f"Scanning {target}")
        t.add_column("Module")
        t.add_column("Status")
        for name, state in statuses.items():
            t.add_row(name, state)
        return t

    def on_event(kind: str, module: str):
        statuses[module] = "running…" if kind == "module_started" else "done"

    async def go() -> ScanReport:
        if quiet:
            return await run_scan(target, settings, mods)
        with Live(render_panel(), console=console, refresh_per_second=8) as live:
            def cb(kind, module):
                on_event(kind, module)
                live.update(render_panel())
            return await run_scan(target, settings, mods, on_event=cb)

    report = asyncio.run(go())
    if not quiet:
        _print_summary(report)

    for path, renderer in ((json_out, render_json), (md_out, render_markdown), (html_out, render_html)):
        if path:
            Path(path).write_text(renderer(report), encoding="utf-8")
            console.print(f"[green]Wrote[/green] {path}")


def _print_summary(report: ScanReport):
    table = Table(title=f"Findings — {report.target}")
    table.add_column("Severity")
    table.add_column("Module")
    table.add_column("Title")
    for mod in report.modules:
        for f in mod.findings:
            table.add_row(f"[{_SEV_COLOR[f.severity]}]{f.severity.value}[/]", mod.module, f.title)
    console.print(table)
    color = _SEV_COLOR[report.risk_level]
    console.print(f"[{color}]RISK: {report.risk_level.value} (score {report.risk_score})[/]")
