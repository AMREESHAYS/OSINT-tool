# OSINT Phase 2b Implementation Plan — AI Summary, Screenshots, Breach

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three optional, gracefully-degrading enrichments — a heuristic/Claude recon summary, a Playwright screenshot module, and a HIBP breach module — and surface them in the CLI, the SSE API, and the dashboard, without adding any required dependency or breaking the "no paid API required" default.

**Architecture:** `summarize(report, use_llm)` is a derived function (like `build_graph`), heuristic by default with an opt-in, key-gated, fail-safe Claude path. Screenshots and breaches are ordinary modules that stream via the existing orchestrator with no core change. The API `report` event gains a `summary` field; the CLI gains `--ai`; the dashboard renders three cards.

**Tech Stack:** Python 3.11+, FastAPI, httpx, Pydantic v2, pytest + respx; optional `anthropic` (`[ai]` extra) and `playwright` (`[screenshots]` extra); React 18 + Vite + TS.

## Global Constraints

- Python `>=3.11`; Pydantic v2. No bare `except:` (name the exception class; a named `except Exception` with a `# noqa: BLE001` justification is allowed for total isolation, matching the existing codebase pattern).
- **No new *required* dependency.** `anthropic` and `playwright` are optional extras, lazy-imported inside their module/function. Breach uses the existing `httpx`.
- **No paid API on any default path.** LLM is opt-in (`--ai`/`?ai=true`) AND key-gated (`ANTHROPIC_API_KEY`); breach needs `HIBP_API_KEY`; both degrade to a clear notice/heuristic. Never raise.
- Python tests make **no live network calls, use no real browser, and call no real LLM** (respx + monkeypatch of the LLM/capture helpers).
- `summarize` is derived — it is NOT a field on the `ScanReport` model.
- The Anthropic call implementation MUST consult the `claude-api` skill for the current model id / SDK shape (default: Claude Haiku, cheapest tier, `max_tokens≈200`).
- Frontend: `ReportPayload` gains `summary: string`; TS types stay a mirror of the backend payloads. Keep the `cyber-*` palette / `SectionCard`.
- Commit messages must NOT contain any AI/Co-Authored-By/"Generated with" trailer. Commit with `git -c user.name="AMREESHAYS" -c user.email="amreesh192006@gmail.com" commit ...`.
- Work on branch `phase2b-enrichment`, created from `phase2a-sse-dashboard`. Python venv at repo `.venv`; run Python tests with `.venv/bin/pytest`. Frontend in `osint-dashboard/frontend`; typecheck with `npx tsc --noEmit`.

---

### Task 1: Heuristic summary

**Files:**
- Create: `osint/summary.py`
- Test: `tests/test_summary.py`

**Interfaces:**
- Consumes: `ScanReport`, `ModuleResult`, `Finding`, `Severity`.
- Produces: `summarize(report: ScanReport, use_llm: bool = False) -> str`. In this task the `use_llm` branch is a stub that always uses the heuristic (the real LLM path is Task 2). Keep the `use_llm` parameter now so callers (Tasks 5–6) have a stable signature.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_summary.py
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/pytest tests/test_summary.py -v`
Expected: FAIL — `No module named 'osint.summary'`.

- [ ] **Step 3: Write `osint/summary.py`**

```python
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/pytest tests/test_summary.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (all green — 46 + 3 = 49).

- [ ] **Step 6: Commit**

```bash
git add osint/summary.py tests/test_summary.py
git commit -m "feat: heuristic recon summary (summarize)"
```

---

### Task 2: Optional Anthropic (Claude) summary path

**Files:**
- Modify: `osint/summary.py`
- Modify: `pyproject.toml` (add `[project.optional-dependencies] ai = ["anthropic>=0.40"]`)
- Test: `tests/test_summary.py` (add cases)

**Interfaces:**
- Consumes: `ScanReport`.
- Produces: an internal `_llm_summary(report: ScanReport) -> str | None` returning the Claude narrative or `None` on any failure/absence; `summarize(report, use_llm=True)` calls it and falls back to `_heuristic` when it returns `None`.

**Implementation note:** Before writing `_llm_summary`, consult the `claude-api` skill for the current Anthropic SDK usage and model id. Use the cheapest Claude tier (Haiku), `max_tokens≈200`, a short system prompt ("You are a recon analyst; summarize this scan in 2–3 sentences"), and the report's `model_dump(mode="json")` (trimmed) as the user content. Read `ANTHROPIC_API_KEY` from the environment.

- [ ] **Step 1: Write the failing tests**

```python
# add to tests/test_summary.py
from osint import summary as summary_mod


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
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_summary.py -k llm -v`
Expected: FAIL — `_llm_summary` does not exist / `summarize` ignores it.

- [ ] **Step 3: Add the LLM path to `osint/summary.py`**

Add (and wire into `summarize`). Consult the `claude-api` skill to confirm the model id and SDK call before finalizing:

```python
import os


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
            messages=[{"role": "user", "content": report.model_dump_json()}],
        )
        text = "".join(block.text for block in message.content if getattr(block, "type", "") == "text")
        return text.strip() or None
    except Exception:  # noqa: BLE001 - any LLM failure must fall back to the heuristic, never raise
        return None
```

and change `summarize`:

```python
def summarize(report: ScanReport, use_llm: bool = False) -> str:
    if use_llm:
        llm = _llm_summary(report)
        if llm:
            return llm
    return _heuristic(report)
```

- [ ] **Step 4: Add the `[ai]` optional extra to `pyproject.toml`**

In the `[project.optional-dependencies]` table add:

```toml
ai = ["anthropic>=0.40"]
```

- [ ] **Step 5: Run the summary tests and full suite**

Run: `.venv/bin/pytest tests/test_summary.py -v`
Expected: PASS (6 passed).

Run: `.venv/bin/pytest -q`
Expected: PASS (all green).

- [ ] **Step 6: Commit**

```bash
git add osint/summary.py pyproject.toml tests/test_summary.py
git commit -m "feat: optional Claude summary path with heuristic fallback"
```

---

### Task 3: Screenshot module

**Files:**
- Create: `osint/modules/screenshot.py`
- Modify: `pyproject.toml` (add `screenshots = ["playwright>=1.44"]` extra)
- Test: `tests/test_screenshot.py`

**Interfaces:**
- Consumes: `Context`, `Finding`, `Severity`.
- Produces: `ScreenshotModule` (`name="screenshot"`, `applies_to={"domain"}`, `async def run`). Internal helper `async def _capture(url: str, timeout: float) -> bytes` is the single Playwright touch-point (monkeypatched in tests). `run()` catches `ImportError`/`Exception` from capture and returns an INFO "unavailable" finding instead.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_screenshot.py
import base64

import httpx
import pytest

from osint.core.models import Severity
from osint.core.settings import Settings
from osint.modules.base import Context
from osint.modules import screenshot as screenshot_mod
from osint.modules.screenshot import ScreenshotModule


@pytest.fixture
async def ctx():
    async with httpx.AsyncClient() as client:
        yield Context(client=client, settings=Settings())


@pytest.mark.asyncio
async def test_screenshot_success(monkeypatch, ctx):
    async def fake_capture(url, timeout):
        return b"PNGBYTES"
    monkeypatch.setattr(screenshot_mod, "_capture", fake_capture)
    findings = await ScreenshotModule().run("example.com", ctx)
    assert len(findings) == 1
    uri = findings[0].data["image"]
    assert uri.startswith("data:image/png;base64,")
    assert base64.b64decode(uri.split(",", 1)[1]) == b"PNGBYTES"
    # base64 blob is NOT dumped into detail
    assert "PNGBYTES" not in findings[0].detail


@pytest.mark.asyncio
async def test_screenshot_unavailable(monkeypatch, ctx):
    async def boom(url, timeout):
        raise ImportError("playwright not installed")
    monkeypatch.setattr(screenshot_mod, "_capture", boom)
    findings = await ScreenshotModule().run("example.com", ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "unavailable" in findings[0].title.lower()
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/pytest tests/test_screenshot.py -v`
Expected: FAIL — `No module named 'osint.modules.screenshot'`.

- [ ] **Step 3: Write `osint/modules/screenshot.py`**

```python
import base64

from osint.core.models import Finding, Severity
from osint.modules.base import Context


async def _capture(url: str, timeout: float) -> bytes:
    # Lazy-import so Playwright stays an optional dependency.
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        try:
            page = await browser.new_page(viewport={"width": 1280, "height": 800})
            await page.goto(url, timeout=int(timeout * 1000))
            return await page.screenshot(type="png")
        finally:
            await browser.close()


class ScreenshotModule:
    name = "screenshot"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        url = f"https://{target}"
        try:
            png = await _capture(url, ctx.settings.timeout)
        except Exception:  # noqa: BLE001 - Playwright/browser absent or capture failed → degrade, never raise
            return [Finding(module=self.name, title="Screenshots unavailable",
                            detail="Install with: pip install 'osint[screenshots]' && playwright install chromium.")]
        uri = "data:image/png;base64," + base64.b64encode(png).decode("ascii")
        return [Finding(module=self.name, title="Homepage screenshot",
                        detail="Homepage captured.", data={"image": uri})]
```

- [ ] **Step 4: Add the `[screenshots]` extra to `pyproject.toml`**

```toml
screenshots = ["playwright>=1.44"]
```

- [ ] **Step 5: Run to verify it passes**

Run: `.venv/bin/pytest tests/test_screenshot.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit**

```bash
git add osint/modules/screenshot.py pyproject.toml tests/test_screenshot.py
git commit -m "feat: optional Playwright screenshot module (degrades gracefully)"
```

---

### Task 4: Breach module

**Files:**
- Create: `osint/modules/breach.py`
- Test: `tests/test_breach.py`

**Interfaces:**
- Consumes: `Context`, `Finding`, `Severity`.
- Produces: `BreachModule` (`name="breach"`, `applies_to={"email"}`, `async def run`). Reads `HIBP_API_KEY` from the environment.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_breach.py
import httpx
import pytest
import respx

from osint.core.models import Severity
from osint.core.settings import Settings
from osint.modules.base import Context
from osint.modules.breach import BreachModule


@pytest.fixture
async def ctx():
    async with httpx.AsyncClient() as client:
        yield Context(client=client, settings=Settings())


@pytest.mark.asyncio
async def test_breach_no_key_skips(monkeypatch, ctx):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    findings = await BreachModule().run("a@example.com", ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "skipped" in findings[0].title.lower()


@respx.mock
@pytest.mark.asyncio
async def test_breach_none_found(monkeypatch, ctx):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    respx.get(url__regex=r"https://haveibeenpwned\.com/api/v3/breachedaccount/.*").mock(
        return_value=httpx.Response(404))
    findings = await BreachModule().run("a@example.com", ctx)
    assert "no known breaches" in findings[0].title.lower()


@respx.mock
@pytest.mark.asyncio
async def test_breach_password_is_high(monkeypatch, ctx):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    body = [{"Name": "Acme", "BreachDate": "2019-01-01", "DataClasses": ["Email addresses", "Passwords"]}]
    respx.get(url__regex=r"https://haveibeenpwned\.com/api/v3/breachedaccount/.*").mock(
        return_value=httpx.Response(200, json=body))
    findings = await BreachModule().run("a@example.com", ctx)
    high = [f for f in findings if f.severity is Severity.HIGH]
    assert high and "Acme" in high[0].title
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/pytest tests/test_breach.py -v`
Expected: FAIL — `No module named 'osint.modules.breach'`.

- [ ] **Step 3: Write `osint/modules/breach.py`**

```python
import os

from osint.core.models import Finding, Severity
from osint.modules.base import Context

_PASSWORD_CLASSES = {"passwords", "password hints", "security questions and answers"}


class BreachModule:
    name = "breach"
    applies_to = {"email"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        key = os.environ.get("HIBP_API_KEY")
        if not key:
            return [Finding(module=self.name, title="Breach check skipped",
                            detail="Set HIBP_API_KEY to enable HaveIBeenPwned breach lookups.")]

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}?truncateResponse=false"
        headers = {"hibp-api-key": key, "User-Agent": "osint-recon"}
        resp = await ctx.client.get(url, headers=headers)

        if resp.status_code == 404:
            return [Finding(module=self.name, title="No known breaches",
                            detail=f"{target} not found in HaveIBeenPwned.")]
        if resp.status_code != 200:
            return [Finding(module=self.name, title="Breach check failed",
                            detail=f"HaveIBeenPwned returned HTTP {resp.status_code}.")]

        findings = []
        for b in resp.json():
            classes = [c.lower() for c in b.get("DataClasses", [])]
            sev = Severity.HIGH if any(c in _PASSWORD_CLASSES for c in classes) else Severity.MEDIUM
            findings.append(Finding(module=self.name,
                                    title=f"Breach: {b.get('Name')} ({b.get('BreachDate')})",
                                    detail="Exposed: " + ", ".join(b.get("DataClasses", [])),
                                    severity=sev, data=b))
        return findings
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/pytest tests/test_breach.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add osint/modules/breach.py tests/test_breach.py
git commit -m "feat: optional HIBP breach module for email targets"
```

---

### Task 5: Register modules + wire summary into API and CLI

**Files:**
- Modify: `osint/modules/registry.py` (add ScreenshotModule, BreachModule)
- Modify: `osint/api.py` (`ai` param + `summary` in the report event)
- Modify: `osint/cli.py` (`--ai` flag + print summary)
- Test: `tests/test_api.py` (extend), `tests/test_cli.py` (extend), `tests/test_ports_username_email.py` or a small registry assertion

**Interfaces:**
- Consumes: `summarize` (Task 1/2), the two modules (Tasks 3/4).
- Produces: `registry.all_modules()` now returns 12 modules; the API `report` event payload gains `summary`; the CLI `scan` gains `--ai`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_api.py`:

```python
@pytest.mark.asyncio
async def test_report_event_includes_summary(monkeypatch):
    monkeypatch.setattr(api, "all_modules", lambda: [FakeModule()])
    text = await _get_text("/scan?target=example.com")
    events = _parse_sse(text)
    report_ev = events[-1]["data"]
    assert isinstance(report_ev["summary"], str)
    assert "example.com" in report_ev["summary"]
```

Add to `tests/test_cli.py`:

```python
def test_scan_prints_summary():
    result = runner.invoke(app, ["scan", "example.com", "--only", "none"])
    assert result.exit_code == 0
    assert "risk" in result.stdout.lower()
```

Add a registry assertion (in `tests/test_ports_username_email.py`, or a new `tests/test_registry.py`):

```python
def test_registry_includes_2b_modules():
    from osint.modules.registry import all_modules
    names = {m.name for m in all_modules()}
    assert {"screenshot", "breach"} <= names
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_api.py::test_report_event_includes_summary tests/test_cli.py::test_scan_prints_summary -v`
Expected: FAIL — no `summary` in the report event; CLI prints no summary; registry missing the modules.

- [ ] **Step 3: Register the two modules**

In `osint/modules/registry.py`, import `ScreenshotModule` and `BreachModule` and add them to the `all_modules()` return list (alongside the existing 10).

- [ ] **Step 4: Add `summary` to the API report event**

In `osint/api.py`: import `from osint.summary import summarize`; add `ai: bool = False` to the `scan_stream` signature; change the final `report` yield to include the summary:

```python
        yield _sse("report", {"report": json.loads(report.model_dump_json()),
                              "graph": build_graph(report),
                              "summary": summarize(report, use_llm=ai)})
```

- [ ] **Step 5: Add `--ai` and the summary print to the CLI**

In `osint/cli.py`: import `from osint.summary import summarize`; add `ai: bool = typer.Option(False, "--ai", help="Use the optional LLM summary (needs ANTHROPIC_API_KEY)")` to `scan`; after `_print_summary(report)` (and inside `if not quiet:` is fine), print:

```python
        console.print(f"\n[cyan]{summarize(report, use_llm=ai)}[/]")
```

- [ ] **Step 6: Run the tests and full suite**

Run: `.venv/bin/pytest tests/test_api.py tests/test_cli.py -v`
Expected: PASS.

Run: `.venv/bin/pytest -q`
Expected: PASS (all green).

- [ ] **Step 7: Commit**

```bash
git add osint/modules/registry.py osint/api.py osint/cli.py tests/test_api.py tests/test_cli.py tests/test_ports_username_email.py
git commit -m "feat: register screenshot+breach modules; wire summary into API and CLI"
```

---

### Task 6: Frontend — summary, screenshot, and breach cards

**Files:**
- Modify: `osint-dashboard/frontend/src/types/osint.ts` (`ReportPayload.summary`)
- Modify: `osint-dashboard/frontend/src/pages/ResultsPage.tsx`

**Interfaces:**
- Consumes: `ReportPayload.summary`, findings from `states` (module `screenshot` / `breach`).
- No frontend unit tests (per the established pattern); gate is a clean `npx tsc --noEmit` + `npm run build`, then a browser check in Task 7.

- [ ] **Step 1: Add `summary` to the payload type**

In `src/types/osint.ts`, add `summary: string;` to `ReportPayload`:

```typescript
export type ReportPayload = {
  report: ScanReport;
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  summary: string;
};
```

- [ ] **Step 2: Render the summary + add screenshot and breach cards in `ResultsPage.tsx`**

Replace the placeholder AI Summary `SectionCard` with one bound to the payload, and add two more cards. Within `ResultsPage`, after `const findings = ...`, derive:

```tsx
  const screenshot = findings.find((f) => f.module === 'screenshot' && typeof f.data?.image === 'string');
  const breaches = findings.filter((f) => f.module === 'breach');
  const summary = payload?.summary;
```

Change the AI Summary card body to:

```tsx
        <SectionCard title="AI Summary">
          <p className="text-slate-200">{summary ?? (payload ? 'No summary.' : 'Analyzing…')}</p>
        </SectionCard>
```

Add, after the existing three-column grid (before or after the Findings section), a screenshot + breach row:

```tsx
      <div className="mt-6 grid gap-4 md:grid-cols-2">
        <SectionCard title="Screenshot">
          {screenshot ? (
            <img src={screenshot.data.image as string} alt="Homepage screenshot" className="max-w-full rounded-md" />
          ) : (
            <p className="text-cyber-muted">No screenshot (domain scans only; enable the screenshots extra).</p>
          )}
        </SectionCard>
        <SectionCard title="Breaches">
          {breaches.length === 0 ? (
            <p className="text-cyber-muted">No breach data (email scans with HIBP_API_KEY).</p>
          ) : (
            breaches.map((b, i) => (
              <p key={`${b.title}-${i}`} className="text-slate-200">
                <span className="text-cyber-accent">{b.title}</span> — {b.detail}
              </p>
            ))
          )}
        </SectionCard>
      </div>
```

(`Finding.data` is `Record<string, unknown>`, so cast `screenshot.data.image as string` when used as the `src`.)

- [ ] **Step 3: Typecheck and build**

Run (from `osint-dashboard/frontend`): `npx tsc --noEmit`
Expected: no errors.

Run: `npm run build`
Expected: succeeds, emits `dist/`.

- [ ] **Step 4: Commit**

```bash
git add osint-dashboard/frontend/src/types/osint.ts osint-dashboard/frontend/src/pages/ResultsPage.tsx
git commit -m "feat(ui): summary, screenshot, and breach cards"
```

---

### Task 7: End-to-end verification + docs

**Files:**
- Modify: `README.md` (optional-enrichments section)

**Interfaces:** none (integration + docs).

- [ ] **Step 1: Full Python suite green**

Run: `.venv/bin/pytest -q`
Expected: PASS (all Python tests, no live network / no real browser / no real LLM).

- [ ] **Step 2: Browser end-to-end check**

Start the API (`.venv/bin/osint serve --port 8000 &`) and the Vite dev server (preview tool / `npm run dev`). In the browser:
- Domain scan (`example.com`): the **AI Summary** card shows a heuristic narrative; the **Screenshot** card shows either an image (if Playwright is installed) or the clean "no screenshot / enable extra" state; no console errors.
- Email scan (`test@example.com`): the **Breach** card shows the "skipped (HIBP_API_KEY)" state.
Capture evidence (page text / DOM read; screenshots of this dashboard may time out due to the animating graph canvas — the DOM read is sufficient proof). Stop the servers when done.

- [ ] **Step 3: CLI smoke**

Run: `.venv/bin/osint scan example.com --only dns,headers | tail -5`
Expected: the printed summary line appears after the risk verdict.

- [ ] **Step 4: Document the optional enrichments in `README.md`**

Add a short "Optional enrichments" subsection under the Web dashboard section:

```markdown
### Optional enrichments (Phase 2b)

All degrade gracefully; none are required.

```bash
pip install 'osint[ai,screenshots]'   # optional extras
playwright install chromium           # for screenshots
export ANTHROPIC_API_KEY=...           # AI summary via Claude (else heuristic)
export HIBP_API_KEY=...                # email breach lookups (else skipped)
```

- **AI summary** — `osint scan <t> --ai` (or `?ai=true`); heuristic without a key.
- **Screenshots** — homepage capture on domain scans; "unavailable" notice if not installed.
- **Breaches** — HaveIBeenPwned on email scans; "skipped" notice without a key.
```

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: document optional Phase 2b enrichments"
```

---

## Self-Review

**Spec coverage:**
- Heuristic summary → Task 1; optional Claude path (opt-in, key-gated, fail-safe) → Task 2; `[ai]` extra → Task 2. ✓
- Screenshot module (optional Playwright, degrades, base64 in `data.image`) + `[screenshots]` extra → Task 3. ✓
- Breach module (HIBP optional key, 404/200/error handling, passwords→HIGH) → Task 4. ✓
- Registry adds both modules; API `report` event gains `summary`; `?ai=true`; CLI `--ai` + printed summary → Task 5. ✓
- Frontend `ReportPayload.summary` + summary/screenshot/breach cards → Task 6. ✓
- README optional-enablement docs → Task 7. ✓
- No required dep; no paid API default; no live network/browser/LLM in tests → Global Constraints, enforced per task (monkeypatch `_llm_summary`/`_capture`, respx for HIBP, env-var toggles). ✓
- `summarize` derived, not on the model → Tasks 1/2 (function in `osint/summary.py`). ✓
- claude-api skill consulted for the Anthropic call → Task 2 implementation note. ✓

**Placeholder scan:** No TBD/TODO. Every code step has complete code. The Anthropic model id is given (`claude-haiku-4-5-20251001`) with an explicit instruction to confirm via the claude-api skill — not a placeholder.

**Type consistency:**
- `summarize(report, use_llm=False) -> str` identical across definition (Task 1), LLM wiring (Task 2), API (Task 5), CLI (Task 5).
- `_llm_summary(report) -> str | None` and `_capture(url, timeout) -> bytes` are the monkeypatch points named consistently between module code and tests.
- Report event payload keys `report`/`graph`/`summary` consistent between API (Task 5) and frontend `ReportPayload` (Task 6).
- Module names `"screenshot"`/`"breach"` consistent between the modules (Tasks 3/4), the registry (Task 5), and the frontend card filters (Task 6).
- `Finding.data["image"]` (screenshot) consistent between module (Task 3) and frontend (`f.data?.image`, Task 6).
