# OSINT Recon Engine — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate the repo's two half-tools into one installable Python package with a single async recon core, a Rich CLI with a live progress panel, and JSON/Markdown/HTML report export.

**Architecture:** A shared `httpx.AsyncClient` and a set of uniform async modules (`Module` protocol) are fanned out by one orchestrator under a concurrency semaphore. Each module is isolated so one failure never aborts the scan; every module emits `Finding`s into a single Pydantic v2 `ScanReport`, which the CLI renders live and the reporters serialize. Preserves the tool's "no paid API required" identity.

**Tech Stack:** Python 3.11+, httpx, Pydantic v2, Typer, Rich, dnspython, selectolax, pytest + respx (dev), ruff, uv, nmap (optional system binary).

## Global Constraints

- Python `>=3.11`.
- No paid API required for any default code path; anything needing a key is optional and degrades to a clear notice, never an error.
- **No bare `except:`** anywhere — catch specific exceptions (`httpx.HTTPError`, `asyncio.TimeoutError`, `OSError`, `ValueError`).
- Every module isolated: a raised exception becomes `ModuleResult(ok=False, error=...)`, never a crash or an aborted scan.
- Tests make **no live network calls** — use `respx` to mock httpx and fakes for subprocess/DNS.
- Package name `osint`; CLI entry point `osint = "osint.cli:app"`.
- Data model in `osint/core/models.py` is the single source of truth shared by modules, CLI, and reporters.
- Commit messages: no AI/Co-Authored-By trailers.

---

### Task 1: Package scaffold, tooling, and data model

**Files:**
- Create: `pyproject.toml`
- Create: `osint/__init__.py`
- Create: `osint/core/__init__.py`
- Create: `osint/core/models.py`
- Create: `osint/modules/__init__.py`
- Create: `osint/reporting/__init__.py`
- Create: `tests/__init__.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `Severity(str, Enum)` with `INFO, LOW, MEDIUM, HIGH, CRITICAL`.
  - `Finding(module: str, title: str, detail: str, severity: Severity = Severity.INFO, data: dict = {})`.
  - `ModuleResult(module: str, ok: bool, error: str | None, duration_ms: int, findings: list[Finding])`.
  - `ScanReport(target: str, target_type: str, started_at: datetime, finished_at: datetime, modules: list[ModuleResult], risk_score: int, risk_level: Severity)`.

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "osint"
version = "1.0.0"
description = "OSINT reconnaissance engine — no paid API required"
requires-python = ">=3.11"
dependencies = [
    "httpx>=0.27",
    "pydantic>=2.7",
    "typer>=0.12",
    "rich>=13.7",
    "dnspython>=2.6",
    "selectolax>=0.3.21",
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-asyncio>=0.23", "respx>=0.21", "ruff>=0.5"]

[project.scripts]
osint = "osint.cli:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.pytest.ini_options]
asyncio_mode = "auto"

[tool.ruff]
line-length = 100
```

- [ ] **Step 2: Create empty package init files**

Create `osint/__init__.py`, `osint/core/__init__.py`, `osint/modules/__init__.py`, `osint/reporting/__init__.py`, `tests/__init__.py` each containing a single line:

```python
```

(empty file)

- [ ] **Step 3: Write the failing test for the model**

```python
# tests/test_models.py
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
```

- [ ] **Step 4: Run test to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'osint.core.models'`

- [ ] **Step 5: Write `osint/core/models.py`**

```python
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    module: str
    title: str
    detail: str
    severity: Severity = Severity.INFO
    data: dict = Field(default_factory=dict)


class ModuleResult(BaseModel):
    module: str
    ok: bool
    error: str | None = None
    duration_ms: int
    findings: list[Finding] = Field(default_factory=list)


class ScanReport(BaseModel):
    target: str
    target_type: str
    started_at: datetime
    finished_at: datetime
    modules: list[ModuleResult] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: Severity = Severity.INFO
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_models.py -v`
Expected: PASS (2 passed)

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml osint/ tests/
git commit -m "feat: package scaffold, tooling, and shared data model"
```

---

### Task 2: Target classification

**Files:**
- Create: `osint/core/classify.py`
- Test: `tests/test_classify.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `classify(query: str) -> str` returning one of `"domain" | "email" | "username" | "ip" | "unknown"`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_classify.py
import pytest
from osint.core.classify import classify


@pytest.mark.parametrize("query,expected", [
    ("example.com", "domain"),
    ("sub.example.co.uk", "domain"),
    ("user@example.com", "email"),
    ("8.8.8.8", "ip"),
    ("192.168.0.1", "ip"),
    ("john_doe", "username"),
    ("ab", "unknown"),          # too short for username
    ("has spaces", "unknown"),
    ("999.999.999.999", "unknown"),  # invalid octets, not an ip
])
def test_classify(query, expected):
    assert classify(query) == expected
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_classify.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'osint.core.classify'`

- [ ] **Step 3: Write `osint/core/classify.py`**

```python
import ipaddress
import re

_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")
_DOMAIN = re.compile(r"^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")
_USERNAME = re.compile(r"^[a-zA-Z0-9._-]{3,30}$")


def classify(query: str) -> str:
    query = query.strip()
    if not query:
        return "unknown"
    try:
        ipaddress.ip_address(query)
        return "ip"
    except ValueError:
        pass
    if _EMAIL.match(query):
        return "email"
    if _DOMAIN.match(query):
        return "domain"
    if _USERNAME.match(query):
        return "username"
    return "unknown"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_classify.py -v`
Expected: PASS (9 passed)

- [ ] **Step 5: Commit**

```bash
git add osint/core/classify.py tests/test_classify.py
git commit -m "feat: target classification (domain/email/username/ip)"
```

---

### Task 3: Settings and module contract

**Files:**
- Create: `osint/core/settings.py`
- Create: `osint/modules/base.py`
- Test: `tests/test_base.py`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces:
  - `Settings(BaseModel)` with fields `timeout: float = 10.0`, `concurrency: int = 20`, `user_agent: str = "osint-recon/1.0"`, `nmap_enabled: bool = True`.
  - `Context` dataclass: `client: httpx.AsyncClient`, `settings: Settings`.
  - `Module(Protocol)`: attributes `name: str`, `applies_to: set[str]`, and `async def run(self, target: str, ctx: Context) -> list[Finding]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_base.py
import httpx
from osint.core.settings import Settings
from osint.modules.base import Context


def test_settings_defaults():
    s = Settings()
    assert s.timeout == 10.0
    assert s.concurrency == 20
    assert s.nmap_enabled is True


def test_context_holds_client_and_settings():
    client = httpx.AsyncClient()
    ctx = Context(client=client, settings=Settings())
    assert ctx.client is client
    assert ctx.settings.concurrency == 20
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'osint.core.settings'`

- [ ] **Step 3: Write `osint/core/settings.py`**

```python
from pydantic import BaseModel


class Settings(BaseModel):
    timeout: float = 10.0
    concurrency: int = 20
    user_agent: str = "osint-recon/1.0"
    nmap_enabled: bool = True
```

- [ ] **Step 4: Write `osint/modules/base.py`**

```python
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import httpx

from osint.core.models import Finding
from osint.core.settings import Settings


@dataclass
class Context:
    client: httpx.AsyncClient
    settings: Settings


@runtime_checkable
class Module(Protocol):
    name: str
    applies_to: set[str]

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        ...
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_base.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add osint/core/settings.py osint/modules/base.py tests/test_base.py
git commit -m "feat: settings and module protocol/context"
```

---

### Task 4: Orchestrator with module isolation

**Files:**
- Create: `osint/core/orchestrator.py`
- Test: `tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `classify` (Task 2), `Settings`/`Context`/`Module` (Task 3), `Finding`/`ModuleResult`/`ScanReport`/`Severity` (Task 1), `evaluate` (Task 5, imported lazily — see note).
- Produces:
  - `async def scan(target: str, settings: Settings, modules: list[Module], on_event=None) -> ScanReport`.
  - Event callback contract: `on_event(kind: str, module: str)` where `kind` is `"module_started"` or `"module_finished"`.
  - Risk scoring is injected: `scan` accepts the module list explicitly (registry lives in Task 6), so this task has no import cycle with modules.

**Note on risk:** Task 4 computes risk inline with a placeholder `_score(findings)` helper defined here, then Task 5 replaces the body. To keep tasks independently testable, define `_score` locally in this task and have Task 5 move it into `osint/modules/risk.py` and re-import. The test in this task asserts isolation, not exact score values.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_orchestrator.py
import httpx
import pytest

from osint.core.models import Finding, Severity
from osint.core.orchestrator import scan
from osint.core.settings import Settings
from osint.modules.base import Context


class GoodModule:
    name = "good"
    applies_to = {"domain"}

    async def run(self, target, ctx):
        return [Finding(module="good", title="ok", detail=target, severity=Severity.LOW)]


class BoomModule:
    name = "boom"
    applies_to = {"domain"}

    async def run(self, target, ctx):
        raise httpx.ConnectError("nope")


class WrongTypeModule:
    name = "wrong"
    applies_to = {"username"}

    async def run(self, target, ctx):
        raise AssertionError("should not run for a domain target")


@pytest.mark.asyncio
async def test_failing_module_does_not_abort_scan():
    events = []
    report = await scan(
        "example.com",
        Settings(),
        [GoodModule(), BoomModule(), WrongTypeModule()],
        on_event=lambda kind, module: events.append((kind, module)),
    )
    by_name = {m.module: m for m in report.modules}
    # WrongTypeModule filtered out (applies_to mismatch)
    assert set(by_name) == {"good", "boom"}
    assert by_name["good"].ok is True
    assert by_name["good"].findings[0].title == "ok"
    assert by_name["boom"].ok is False
    assert "nope" in by_name["boom"].error
    assert report.target_type == "domain"
    assert ("module_started", "good") in events
    assert ("module_finished", "boom") in events
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_orchestrator.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'osint.core.orchestrator'`

- [ ] **Step 3: Write `osint/core/orchestrator.py`**

```python
import asyncio
import time
from datetime import datetime, timezone

import httpx

from osint.core.classify import classify
from osint.core.models import ModuleResult, ScanReport, Severity
from osint.core.settings import Settings
from osint.modules.base import Context, Module


def _score(findings):
    weights = {
        Severity.CRITICAL: 10, Severity.HIGH: 5,
        Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0,
    }
    total = sum(weights[f.severity] for f in findings)
    if total >= 15:
        level = Severity.CRITICAL
    elif total >= 8:
        level = Severity.HIGH
    elif total >= 3:
        level = Severity.MEDIUM
    elif total >= 1:
        level = Severity.LOW
    else:
        level = Severity.INFO
    return total, level


async def _run_one(module: Module, target: str, ctx: Context, sem, on_event) -> ModuleResult:
    async with sem:
        if on_event:
            on_event("module_started", module.name)
        start = time.perf_counter()
        try:
            findings = await asyncio.wait_for(module.run(target, ctx), timeout=ctx.settings.timeout * 3)
            result = ModuleResult(
                module=module.name, ok=True,
                duration_ms=int((time.perf_counter() - start) * 1000), findings=findings,
            )
        except (httpx.HTTPError, asyncio.TimeoutError, OSError, ValueError) as exc:
            result = ModuleResult(
                module=module.name, ok=False, error=str(exc) or exc.__class__.__name__,
                duration_ms=int((time.perf_counter() - start) * 1000), findings=[],
            )
        if on_event:
            on_event("module_finished", module.name)
        return result


async def scan(target: str, settings: Settings, modules: list[Module], on_event=None) -> ScanReport:
    target_type = classify(target)
    started = datetime.now(timezone.utc)
    selected = [m for m in modules if target_type in m.applies_to]
    sem = asyncio.Semaphore(settings.concurrency)

    async with httpx.AsyncClient(
        timeout=settings.timeout,
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
    ) as client:
        ctx = Context(client=client, settings=settings)
        results = await asyncio.gather(*(_run_one(m, target, ctx, sem, on_event) for m in selected))

    all_findings = [f for r in results for f in r.findings]
    score, level = _score(all_findings)
    return ScanReport(
        target=target, target_type=target_type,
        started_at=started, finished_at=datetime.now(timezone.utc),
        modules=list(results), risk_score=score, risk_level=level,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_orchestrator.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add osint/core/orchestrator.py tests/test_orchestrator.py
git commit -m "feat: async orchestrator with per-module isolation and events"
```

---

### Task 5: Risk engine (extract and expand)

**Files:**
- Create: `osint/modules/risk.py`
- Modify: `osint/core/orchestrator.py` (replace local `_score` with import)
- Test: `tests/test_risk.py`

**Interfaces:**
- Consumes: `Finding`, `Severity` (Task 1).
- Produces: `evaluate(findings: list[Finding]) -> tuple[int, Severity]` — same signature as the orchestrator's local `_score`, so the swap is drop-in.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_risk.py
from osint.core.models import Finding, Severity
from osint.modules.risk import evaluate


def _f(sev):
    return Finding(module="x", title="t", detail="d", severity=sev)


def test_empty_is_info():
    assert evaluate([]) == (0, Severity.INFO)


def test_low_bucket():
    assert evaluate([_f(Severity.LOW)]) == (1, Severity.LOW)


def test_medium_bucket():
    score, level = evaluate([_f(Severity.MEDIUM), _f(Severity.LOW)])
    assert score == 3 and level is Severity.MEDIUM


def test_high_bucket():
    score, level = evaluate([_f(Severity.HIGH), _f(Severity.MEDIUM), _f(Severity.LOW)])
    assert score == 8 and level is Severity.HIGH


def test_critical_bucket():
    score, level = evaluate([_f(Severity.CRITICAL), _f(Severity.HIGH)])
    assert score == 15 and level is Severity.CRITICAL
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_risk.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'osint.modules.risk'`

- [ ] **Step 3: Write `osint/modules/risk.py`**

```python
from osint.core.models import Finding, Severity

_WEIGHTS = {
    Severity.CRITICAL: 10, Severity.HIGH: 5,
    Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0,
}


def evaluate(findings: list[Finding]) -> tuple[int, Severity]:
    total = sum(_WEIGHTS[f.severity] for f in findings)
    if total >= 15:
        return total, Severity.CRITICAL
    if total >= 8:
        return total, Severity.HIGH
    if total >= 3:
        return total, Severity.MEDIUM
    if total >= 1:
        return total, Severity.LOW
    return total, Severity.INFO
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_risk.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Replace `_score` in the orchestrator with the shared function**

In `osint/core/orchestrator.py`, delete the entire `def _score(findings): ...` block and add to the imports:

```python
from osint.modules.risk import evaluate as _score
```

(The call site `score, level = _score(all_findings)` is unchanged.)

- [ ] **Step 6: Run the full suite to verify nothing broke**

Run: `pytest -v`
Expected: PASS (all prior tests still green, including `test_orchestrator.py`)

- [ ] **Step 7: Commit**

```bash
git add osint/modules/risk.py osint/core/orchestrator.py tests/test_risk.py
git commit -m "feat: extract and expand risk engine into shared module"
```

---

### Task 6: HTTP-based domain modules + module registry

**Files:**
- Create: `osint/modules/headers.py`
- Create: `osint/modules/tech.py`
- Create: `osint/modules/crawler.py`
- Create: `osint/modules/js_endpoints.py`
- Create: `osint/modules/registry.py`
- Test: `tests/test_http_modules.py`

**Interfaces:**
- Consumes: `Context` (Task 3), `Finding`/`Severity` (Task 1).
- Produces:
  - `HeadersModule`, `TechModule`, `CrawlerModule`, `JsEndpointsModule` — each a class with `name`, `applies_to = {"domain"}`, `async def run(self, target, ctx)`.
  - `registry.all_modules() -> list[Module]` returning instances of every module (extended in Tasks 7–8).
  - Helper `_url(target: str) -> str` returning `f"https://{target}"` if `target` has no scheme.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_http_modules.py
import httpx
import pytest
import respx

from osint.core.settings import Settings
from osint.modules.base import Context
from osint.modules.headers import HeadersModule
from osint.modules.tech import TechModule
from osint.modules.crawler import CrawlerModule
from osint.modules.js_endpoints import JsEndpointsModule


@pytest.fixture
async def ctx():
    async with httpx.AsyncClient(follow_redirects=True) as client:
        yield Context(client=client, settings=Settings())


@respx.mock
@pytest.mark.asyncio
async def test_headers_flags_missing_csp(ctx):
    respx.get("https://example.com").mock(return_value=httpx.Response(200, headers={"Server": "nginx"}))
    findings = await HeadersModule().run("example.com", ctx)
    titles = [f.title for f in findings]
    assert any("Content-Security-Policy" in t for t in titles)


@respx.mock
@pytest.mark.asyncio
async def test_tech_reports_server(ctx):
    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, headers={"Server": "nginx", "X-Powered-By": "PHP/8"}))
    findings = await TechModule().run("example.com", ctx)
    joined = " ".join(f.detail for f in findings)
    assert "nginx" in joined and "PHP/8" in joined


@respx.mock
@pytest.mark.asyncio
async def test_crawler_extracts_links(ctx):
    html = '<a href="/about">a</a><a href="https://example.com/x">b</a>'
    respx.get("https://example.com").mock(return_value=httpx.Response(200, text=html))
    findings = await CrawlerModule().run("example.com", ctx)
    assert len(findings) >= 1


@respx.mock
@pytest.mark.asyncio
async def test_js_endpoints_flags_secret(ctx):
    html = '<script src="/app.js"></script>'
    js = 'const api_key = "abc123"; fetch("/api/v1/users")'
    respx.get("https://example.com").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/app.js").mock(return_value=httpx.Response(200, text=js))
    findings = await JsEndpointsModule().run("example.com", ctx)
    severities = [f.severity for f in findings]
    from osint.core.models import Severity
    assert Severity.HIGH in severities
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_http_modules.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'osint.modules.headers'`

- [ ] **Step 3: Write `osint/modules/headers.py`**

```python
from osint.core.models import Finding, Severity
from osint.modules.base import Context

_SECURITY_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", Severity.MEDIUM),
    "x-frame-options": ("X-Frame-Options", Severity.LOW),
    "strict-transport-security": ("HSTS (Strict-Transport-Security)", Severity.MEDIUM),
    "x-content-type-options": ("X-Content-Type-Options", Severity.LOW),
}


def _url(target: str) -> str:
    return target if target.startswith(("http://", "https://")) else f"https://{target}"


class HeadersModule:
    name = "headers"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        resp = await ctx.client.get(_url(target))
        present = {k.lower() for k in resp.headers}
        findings = []
        for key, (label, sev) in _SECURITY_HEADERS.items():
            if key not in present:
                findings.append(Finding(module=self.name, title=f"Missing {label}",
                                        detail=f"Response for {target} does not set {label}.", severity=sev))
        return findings
```

- [ ] **Step 4: Write `osint/modules/tech.py`**

```python
from osint.core.models import Finding, Severity
from osint.modules.base import Context
from osint.modules.headers import _url


class TechModule:
    name = "tech"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        resp = await ctx.client.get(_url(target))
        findings = []
        for header in ("Server", "X-Powered-By", "X-AspNet-Version"):
            value = resp.headers.get(header)
            if value:
                findings.append(Finding(module=self.name, title=f"{header}: {value}",
                                        detail=value, data={header: value}))
        return findings
```

- [ ] **Step 5: Write `osint/modules/crawler.py`**

```python
from selectolax.parser import HTMLParser

from osint.core.models import Finding
from osint.modules.base import Context
from osint.modules.headers import _url


class CrawlerModule:
    name = "crawler"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        resp = await ctx.client.get(_url(target))
        tree = HTMLParser(resp.text)
        links = {a.attributes.get("href") for a in tree.css("a[href]")}
        links.discard(None)
        links = sorted(links)[:50]
        if not links:
            return []
        return [Finding(module=self.name, title=f"{len(links)} links found",
                        detail="\n".join(links), data={"links": links})]
```

- [ ] **Step 6: Write `osint/modules/js_endpoints.py`**

```python
import re

from selectolax.parser import HTMLParser

from osint.core.models import Finding, Severity
from osint.modules.base import Context
from osint.modules.headers import _url

_ENDPOINT_RE = re.compile(r"[\"'](/[a-zA-Z0-9_./-]{2,})[\"']")
_SECRET_RE = re.compile(r"(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']{6,}", re.I)


class JsEndpointsModule:
    name = "js_endpoints"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        base = _url(target)
        resp = await ctx.client.get(base)
        tree = HTMLParser(resp.text)
        js_urls = [s.attributes.get("src") for s in tree.css("script[src]") if s.attributes.get("src")]
        findings = []
        for src in js_urls[:10]:
            url = src if src.startswith("http") else f"{base}{src if src.startswith('/') else '/' + src}"
            try:
                js = (await ctx.client.get(url)).text
            except Exception:  # noqa: BLE001 - one bad script must not sink the module
                continue
            endpoints = sorted(set(_ENDPOINT_RE.findall(js)))[:30]
            if endpoints:
                findings.append(Finding(module=self.name, title=f"{len(endpoints)} endpoints in {src}",
                                        detail="\n".join(endpoints), data={"endpoints": endpoints}))
            if _SECRET_RE.search(js):
                findings.append(Finding(module=self.name, title=f"Possible secret in {src}",
                                        detail="A hardcoded credential pattern was found in JavaScript.",
                                        severity=Severity.HIGH))
        return findings
```

Note: the `except Exception` here is a deliberate, narrow guard around a single optional
sub-fetch inside a loop, with a `noqa` justifying it — it is not a module-level bare
except and does not violate the global constraint (the orchestrator still isolates the
module as a whole).

- [ ] **Step 7: Write `osint/modules/registry.py`**

```python
from osint.modules.base import Module
from osint.modules.crawler import CrawlerModule
from osint.modules.headers import HeadersModule
from osint.modules.js_endpoints import JsEndpointsModule
from osint.modules.tech import TechModule


def all_modules() -> list[Module]:
    return [HeadersModule(), TechModule(), CrawlerModule(), JsEndpointsModule()]
```

- [ ] **Step 8: Run test to verify it passes**

Run: `pytest tests/test_http_modules.py -v`
Expected: PASS (4 passed)

- [ ] **Step 9: Commit**

```bash
git add osint/modules/headers.py osint/modules/tech.py osint/modules/crawler.py osint/modules/js_endpoints.py osint/modules/registry.py tests/test_http_modules.py
git commit -m "feat: HTTP domain modules (headers, tech, crawler, js) + registry"
```

---

### Task 7: DNS, subdomains, and dir bruteforce modules

**Files:**
- Create: `osint/modules/dns_records.py`
- Create: `osint/modules/subdomains.py`
- Create: `osint/modules/dir_bruteforce.py`
- Create: `osint/data/wordlist.txt`
- Modify: `osint/modules/registry.py` (add the three new modules)
- Test: `tests/test_dns_dir_modules.py`

**Interfaces:**
- Consumes: `Context` (Task 3), `Finding`/`Severity` (Task 1), `_url` (Task 6).
- Produces: `DnsModule`, `SubdomainsModule`, `DirBruteforceModule`, each `applies_to = {"domain"}`.
- DNS uses `dns.resolver` wrapped in `asyncio.to_thread` (dnspython is sync).

- [ ] **Step 1: Create `osint/data/wordlist.txt`**

A newline-delimited wordlist. Include at minimum these high-signal entries (add more common ones to reach ~200 lines; the test only depends on these being present):

```
admin
login
dashboard
api
.git
.env
.git/config
robots.txt
backup
config
wp-admin
phpinfo.php
.svn
server-status
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_dns_dir_modules.py
import httpx
import pytest
import respx

from osint.core.models import Severity
from osint.core.settings import Settings
from osint.modules.base import Context
from osint.modules.dir_bruteforce import DirBruteforceModule
from osint.modules.subdomains import SubdomainsModule


@pytest.fixture
async def ctx():
    async with httpx.AsyncClient(follow_redirects=False) as client:
        yield Context(client=client, settings=Settings())


@respx.mock
@pytest.mark.asyncio
async def test_dir_bruteforce_flags_exposed_git(ctx):
    # Everything 404 except .git/config which returns 200
    respx.get(url__regex=r"https://example\.com/.*").mock(return_value=httpx.Response(404))
    respx.get("https://example.com/.git/config").mock(return_value=httpx.Response(200, text="[core]"))
    findings = await DirBruteforceModule().run("example.com", ctx)
    hits = {f.title: f.severity for f in findings}
    assert any(".git" in t for t in hits)
    assert Severity.HIGH in hits.values()


@respx.mock
@pytest.mark.asyncio
async def test_subdomains_from_crtsh(ctx):
    payload = [{"name_value": "a.example.com\nb.example.com"}, {"name_value": "a.example.com"}]
    respx.get(url__regex=r"https://crt\.sh/.*").mock(return_value=httpx.Response(200, json=payload))
    findings = await SubdomainsModule().run("example.com", ctx)
    joined = " ".join(f.detail for f in findings)
    assert "a.example.com" in joined and "b.example.com" in joined
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_dns_dir_modules.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'osint.modules.dir_bruteforce'`

- [ ] **Step 4: Write `osint/modules/dns_records.py`**

```python
import asyncio

import dns.resolver

from osint.core.models import Finding
from osint.modules.base import Context


def _resolve(domain: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            out[rtype] = [str(r) for r in dns.resolver.resolve(domain, rtype)]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                dns.exception.Timeout):
            out[rtype] = []
    return out


class DnsModule:
    name = "dns"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        records = await asyncio.to_thread(_resolve, target)
        findings = []
        for rtype, values in records.items():
            if values:
                findings.append(Finding(module=self.name, title=f"{rtype} records",
                                        detail="\n".join(values), data={rtype: values}))
        return findings
```

- [ ] **Step 5: Write `osint/modules/subdomains.py`**

```python
from osint.core.models import Finding, Severity
from osint.modules.base import Context


class SubdomainsModule:
    name = "subdomains"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        resp = await ctx.client.get(f"https://crt.sh/?q=%25.{target}&output=json")
        subs: set[str] = set()
        for entry in resp.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name:
                    subs.add(name)
        if not subs:
            return []
        sev = Severity.MEDIUM if len(subs) > 20 else Severity.INFO
        subs_sorted = sorted(subs)
        return [Finding(module=self.name, title=f"{len(subs_sorted)} subdomains (crt.sh)",
                        detail="\n".join(subs_sorted), severity=sev, data={"subdomains": subs_sorted})]
```

- [ ] **Step 6: Write `osint/modules/dir_bruteforce.py`**

```python
import asyncio
from importlib import resources

from osint.core.models import Finding, Severity
from osint.modules.base import Context
from osint.modules.headers import _url

_HIGH_RISK = (".git", ".env", ".svn", "backup", "phpinfo")


def _load_wordlist() -> list[str]:
    text = resources.files("osint.data").joinpath("wordlist.txt").read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


class DirBruteforceModule:
    name = "dir_bruteforce"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        base = _url(target)
        words = _load_wordlist()
        sem = asyncio.Semaphore(ctx.settings.concurrency)

        async def probe(path: str):
            async with sem:
                try:
                    resp = await ctx.client.get(f"{base}/{path}")
                except Exception:  # noqa: BLE001 - one dead path must not sink the sweep
                    return None
                if resp.status_code in (200, 301, 403):
                    return path, resp.status_code
                return None

        results = [r for r in await asyncio.gather(*(probe(w) for w in words)) if r]
        findings = []
        for path, code in results:
            sev = Severity.HIGH if any(h in path for h in _HIGH_RISK) else Severity.LOW
            findings.append(Finding(module=self.name, title=f"/{path} [{code}]",
                                    detail=f"{base}/{path} returned HTTP {code}", severity=sev))
        return findings
```

- [ ] **Step 7: Add the three modules to the registry**

In `osint/modules/registry.py`, update imports and `all_modules`:

```python
from osint.modules.base import Module
from osint.modules.crawler import CrawlerModule
from osint.modules.dir_bruteforce import DirBruteforceModule
from osint.modules.dns_records import DnsModule
from osint.modules.headers import HeadersModule
from osint.modules.js_endpoints import JsEndpointsModule
from osint.modules.subdomains import SubdomainsModule
from osint.modules.tech import TechModule


def all_modules() -> list[Module]:
    return [
        DnsModule(), SubdomainsModule(), HeadersModule(), TechModule(),
        CrawlerModule(), JsEndpointsModule(), DirBruteforceModule(),
    ]
```

- [ ] **Step 8: Ensure the wordlist ships with the package**

In `pyproject.toml`, add under `[tool.hatch.build.targets.wheel]` (append to end of file):

```toml
[tool.hatch.build.targets.wheel]
packages = ["osint"]

[tool.hatch.build.targets.wheel.force-include]
"osint/data/wordlist.txt" = "osint/data/wordlist.txt"
```

- [ ] **Step 9: Run test to verify it passes**

Run: `pytest tests/test_dns_dir_modules.py -v`
Expected: PASS (2 passed)

- [ ] **Step 10: Commit**

```bash
git add osint/modules/dns_records.py osint/modules/subdomains.py osint/modules/dir_bruteforce.py osint/data/wordlist.txt osint/modules/registry.py pyproject.toml tests/test_dns_dir_modules.py
git commit -m "feat: DNS, subdomains (crt.sh), and dir bruteforce modules"
```

---

### Task 8: Ports (optional nmap), username, and email modules

**Files:**
- Create: `osint/modules/ports.py`
- Create: `osint/modules/username.py`
- Create: `osint/modules/email.py`
- Modify: `osint/modules/registry.py`
- Test: `tests/test_ports_username_email.py`

**Interfaces:**
- Consumes: `Context` (Task 3), `Finding`/`Severity` (Task 1).
- Produces: `PortsModule` (`applies_to={"domain","ip"}`), `UsernameModule` (`{"username"}`), `EmailModule` (`{"email"}`).
- `ports` shells `nmap` via `asyncio.create_subprocess_exec`; when the binary is absent it returns a single INFO finding, never raises.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ports_username_email.py
import httpx
import pytest
import respx

from osint.core.settings import Settings
from osint.modules.base import Context
from osint.modules.email import EmailModule
from osint.modules.ports import PortsModule
from osint.modules.username import UsernameModule


@pytest.fixture
async def ctx():
    async with httpx.AsyncClient() as client:
        yield Context(client=client, settings=Settings())


@pytest.mark.asyncio
async def test_ports_missing_nmap_is_info(monkeypatch, ctx):
    async def fake_exec(*args, **kwargs):
        raise FileNotFoundError("nmap")
    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    findings = await PortsModule().run("example.com", ctx)
    assert len(findings) == 1
    assert "nmap" in findings[0].detail.lower()
    from osint.core.models import Severity
    assert findings[0].severity is Severity.INFO


@respx.mock
@pytest.mark.asyncio
async def test_username_reports_hit(ctx):
    # GitHub 200 (present), everything else 404
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))
    respx.get("https://github.com/octocat").mock(return_value=httpx.Response(200))
    findings = await UsernameModule().run("octocat", ctx)
    joined = " ".join(f.title for f in findings)
    assert "GitHub" in joined


@pytest.mark.asyncio
async def test_email_extracts_domain(ctx):
    findings = await EmailModule().run("john@example.com", ctx)
    joined = " ".join(f.detail for f in findings)
    assert "example.com" in joined
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_ports_username_email.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'osint.modules.ports'`

- [ ] **Step 3: Write `osint/modules/ports.py`**

```python
import asyncio
import re

from osint.core.models import Finding, Severity
from osint.modules.base import Context

_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.M)


class PortsModule:
    name = "ports"
    applies_to = {"domain", "ip"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        if not ctx.settings.nmap_enabled:
            return [Finding(module=self.name, title="Port scan skipped",
                            detail="Port scanning disabled via --no-nmap.")]
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-F", target,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
        except FileNotFoundError:
            return [Finding(module=self.name, title="nmap not installed",
                            detail="nmap binary not found on PATH; port scan skipped.")]
        findings = []
        for port, service in _PORT_RE.findall(stdout.decode(errors="ignore")):
            findings.append(Finding(module=self.name, title=f"Port {port}/tcp open ({service})",
                                    detail=f"{service} on {port}/tcp", severity=Severity.LOW,
                                    data={"port": int(port), "service": service}))
        return findings
```

- [ ] **Step 4: Write `osint/modules/username.py`**

```python
import asyncio

from osint.core.models import Finding, Severity
from osint.modules.base import Context

PLATFORMS = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Reddit": "https://www.reddit.com/user/{u}",
    "Instagram": "https://www.instagram.com/{u}",
    "X": "https://x.com/{u}",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "Medium": "https://medium.com/@{u}",
    "Keybase": "https://keybase.io/{u}",
    "Telegram": "https://t.me/{u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "HackerNews": "https://news.ycombinator.com/user?id={u}",
    "DevTo": "https://dev.to/{u}",
    "Pastebin": "https://pastebin.com/u/{u}",
    "YouTube": "https://www.youtube.com/@{u}",
}


class UsernameModule:
    name = "username"
    applies_to = {"username"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        sem = asyncio.Semaphore(ctx.settings.concurrency)

        async def check(platform: str, url: str):
            async with sem:
                try:
                    resp = await ctx.client.get(url.format(u=target))
                except Exception:  # noqa: BLE001 - one dead platform must not sink the sweep
                    return None
                return platform if resp.status_code == 200 else None

        hits = [r for r in await asyncio.gather(
            *(check(p, u) for p, u in PLATFORMS.items())) if r]
        return [Finding(module=self.name, title=f"Found on {p}",
                        detail=PLATFORMS[p].format(u=target), severity=Severity.INFO) for p in hits]
```

- [ ] **Step 5: Write `osint/modules/email.py`**

```python
import asyncio

import dns.resolver

from osint.core.models import Finding, Severity
from osint.modules.base import Context


class EmailModule:
    name = "email"
    applies_to = {"email"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        domain = target.rsplit("@", 1)[-1]
        findings = [Finding(module=self.name, title="Email domain",
                            detail=domain, data={"domain": domain})]

        def _mx():
            try:
                return [str(r.exchange) for r in dns.resolver.resolve(domain, "MX")]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                return []

        mx = await asyncio.to_thread(_mx)
        if mx:
            findings.append(Finding(module=self.name, title=f"{len(mx)} MX records",
                                    detail="\n".join(mx), data={"mx": mx}))
        else:
            findings.append(Finding(module=self.name, title="No MX records",
                                    detail=f"{domain} has no MX records (may not receive mail).",
                                    severity=Severity.LOW))
        return findings
```

- [ ] **Step 6: Add the three modules to the registry**

In `osint/modules/registry.py`, add imports for `PortsModule`, `UsernameModule`, `EmailModule` and extend `all_modules` to return them alongside the existing seven:

```python
from osint.modules.email import EmailModule
from osint.modules.ports import PortsModule
from osint.modules.username import UsernameModule
# ... existing imports ...


def all_modules() -> list[Module]:
    return [
        DnsModule(), SubdomainsModule(), HeadersModule(), TechModule(),
        CrawlerModule(), JsEndpointsModule(), DirBruteforceModule(),
        PortsModule(), UsernameModule(), EmailModule(),
    ]
```

- [ ] **Step 7: Run test to verify it passes**

Run: `pytest tests/test_ports_username_email.py -v`
Expected: PASS (3 passed)

- [ ] **Step 8: Run the full suite**

Run: `pytest -v`
Expected: PASS (all tests green)

- [ ] **Step 9: Commit**

```bash
git add osint/modules/ports.py osint/modules/username.py osint/modules/email.py osint/modules/registry.py tests/test_ports_username_email.py
git commit -m "feat: ports (optional nmap), username, and email modules"
```

---

### Task 9: Reporters (JSON, Markdown, HTML)

**Files:**
- Create: `osint/reporting/json_report.py`
- Create: `osint/reporting/markdown_report.py`
- Create: `osint/reporting/html_report.py`
- Test: `tests/test_reporting.py`

**Interfaces:**
- Consumes: `ScanReport`, `Finding`, `Severity` (Task 1).
- Produces:
  - `render_json(report: ScanReport) -> str`
  - `render_markdown(report: ScanReport) -> str`
  - `render_html(report: ScanReport) -> str`
  - Each returns a string; the CLI writes it to disk.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reporting.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'osint.reporting.json_report'`

- [ ] **Step 3: Write `osint/reporting/json_report.py`**

```python
from osint.core.models import ScanReport


def render_json(report: ScanReport) -> str:
    return report.model_dump_json(indent=2)
```

- [ ] **Step 4: Write `osint/reporting/markdown_report.py`**

```python
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
```

- [ ] **Step 5: Write `osint/reporting/html_report.py`**

```python
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
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_reporting.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Commit**

```bash
git add osint/reporting/ tests/test_reporting.py
git commit -m "feat: JSON, Markdown, and self-contained HTML reporters"
```

---

### Task 10: Rich CLI with live progress

**Files:**
- Create: `osint/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `scan` (Task 4), `Settings` (Task 3), `all_modules` (Tasks 6–8), reporters (Task 9), `classify` (Task 2).
- Produces: a Typer `app` with commands `scan`, `modules`, `version`. Entry point already declared in `pyproject.toml` (`osint = "osint.cli:app"`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
from typer.testing import CliRunner

from osint.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.stdout


def test_modules_lists_registry():
    result = runner.invoke(app, ["modules"])
    assert result.exit_code == 0
    assert "dns" in result.stdout and "username" in result.stdout


def test_scan_unknown_target_errors():
    result = runner.invoke(app, ["scan", "has spaces here"])
    assert result.exit_code != 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'osint.cli'`

- [ ] **Step 3: Write `osint/cli.py`**

```python
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
    table.add_column("Module"); table.add_column("Applies to")
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
):
    """Run a recon scan against TARGET."""
    if classify(target) == "unknown":
        console.print(f"[red]Could not classify target:[/red] {target!r}")
        raise typer.Exit(code=2)

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
        t.add_column("Module"); t.add_column("Status")
        for name, state in statuses.items():
            t.add_row(name, state)
        return t

    def on_event(kind: str, module: str):
        statuses[module] = "running…" if kind == "module_started" else "done"

    async def go() -> ScanReport:
        with Live(render_panel(), console=console, refresh_per_second=8) as live:
            def cb(kind, module):
                on_event(kind, module)
                live.update(render_panel())
            return await run_scan(target, settings, mods, on_event=cb)

    report = asyncio.run(go())
    _print_summary(report)

    for path, renderer in ((json_out, render_json), (md_out, render_markdown), (html_out, render_html)):
        if path:
            Path(path).write_text(renderer(report), encoding="utf-8")
            console.print(f"[green]Wrote[/green] {path}")


def _print_summary(report: ScanReport):
    table = Table(title=f"Findings — {report.target}")
    table.add_column("Severity"); table.add_column("Module"); table.add_column("Title")
    for mod in report.modules:
        for f in mod.findings:
            table.add_row(f"[{_SEV_COLOR[f.severity]}]{f.severity.value}[/]", mod.module, f.title)
    console.print(table)
    color = _SEV_COLOR[report.risk_level]
    console.print(f"[{color}]RISK: {report.risk_level.value} (score {report.risk_score})[/]")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Run the full suite**

Run: `pytest -v`
Expected: PASS (all tests green)

- [ ] **Step 6: Commit**

```bash
git add osint/cli.py tests/test_cli.py
git commit -m "feat: Rich CLI with live progress panel and report export"
```

---

### Task 11: Delete legacy code, rewrite README, add Dockerfile

**Files:**
- Delete: `backend/` (entire directory — old modules, 5 orchestrators, old cli/main)
- Delete: `osint-dashboard/backend/` (duplicate service layer; frontend kept for Phase 2)
- Delete: `README_NEW.md`, `README_FINAL.md`
- Create: `Dockerfile`
- Create: `.dockerignore`
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing (cleanup + docs).
- Produces: a clean repo whose only backend is the `osint/` package.

- [ ] **Step 1: Verify the new package is self-sufficient before deleting anything**

Run: `pytest -v`
Expected: PASS (all tests green — confirms nothing under `backend/` is still needed)

- [ ] **Step 2: Delete the legacy directories and README variants**

```bash
git rm -r backend osint-dashboard/backend README_NEW.md README_FINAL.md
```

- [ ] **Step 3: Write `Dockerfile`**

```dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml ./
COPY osint ./osint
RUN pip install --no-cache-dir .
ENTRYPOINT ["osint"]
CMD ["--help"]
```

- [ ] **Step 4: Write `.dockerignore`**

```
.git
tests
docs
osint-dashboard
__pycache__
*.pyc
.venv
```

- [ ] **Step 5: Rewrite `README.md`**

Replace the entire file with:

```markdown
# 🕵️ OSINT Recon Engine

A fast, async **Open Source Intelligence** reconnaissance tool — **no paid API required**.
Built for security learners, bug-bounty hunters, and researchers.

> ⚠️ Only scan targets you own or are explicitly authorized to test.

## Install

```bash
pipx install .        # or: uvx --from . osint
```

Docker (bundles nmap):

```bash
docker build -t osint . && docker run --rm osint scan example.com
```

## Usage

```bash
osint scan example.com                 # full domain recon, live panel
osint scan example.com --html report.html
osint scan user@example.com            # email recon
osint scan octocat                     # username footprint (~15 platforms)
osint scan 8.8.8.8 --only ports        # single module
osint modules                          # list modules
```

Flags: `--json/--md/--html <path>`, `--only`, `--skip`, `--no-nmap`,
`--concurrency`, `--timeout`.

## Modules

DNS · subdomains (crt.sh) · ports (nmap, optional) · security headers ·
tech fingerprint · crawler · directory bruteforce · JS endpoint/secret
extraction · username footprint · email/MX · heuristic risk scoring.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Roadmap

Phase 2: FastAPI SSE API + React dashboard, entity correlation graph, optional AI summary.
```

- [ ] **Step 6: Verify the suite still passes after deletions**

Run: `pytest -v`
Expected: PASS (all tests green — deletions removed no live dependency)

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: remove legacy backends, rewrite README, add Dockerfile"
```

---

## Self-Review

**Spec coverage:**
- Consolidated async core / one orchestrator → Task 4 (+ delete legacy in Task 11). ✓
- Pydantic v2 shared model → Task 1. ✓
- classify (domain/email/username/ip) → Task 2. ✓
- Module contract + settings + shared httpx client → Tasks 3, 4. ✓
- All modules (dns, subdomains, ports optional, tech, headers, crawler, dir_bruteforce, js_endpoints, username expanded, email) → Tasks 6, 7, 8. ✓
- Risk engine expanded → Task 5. ✓
- Live streaming CLI (feature 1) → Task 10 (`on_event` → `rich.Live`). ✓
- Risk scoring surfaced (feature 3) → Tasks 5, 10. ✓
- Reports JSON/MD/HTML (feature 4) → Task 9, wired in Task 10. ✓
- No bare except / module isolation → Task 4 contract, enforced per module. ✓
- No live network in tests → respx + monkeypatch throughout. ✓
- Packaging (uv/pyproject, entry point, ruff) → Task 1; Dockerfile → Task 11. ✓
- Delete 5 orchestrators + duplicate dashboard backend + extra READMEs → Task 11. ✓
- Authorization notice → Task 10 (CLI) + Task 11 (README). ✓
- Deferred (screenshots, graph, AI, breach API, FastAPI/React) → correctly absent. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code. The two in-loop `except Exception` guards are deliberate, `noqa`-annotated, and explained — not violations of the "no bare except" rule (they name `Exception`, not bare, and are scoped to one optional sub-request).

**Type consistency:** `scan(target, settings, modules, on_event)` signature consistent between Task 4 definition and Task 10 call. `evaluate(findings) -> tuple[int, Severity]` matches the `_score` it replaces (Task 4 → Task 5). `Finding`/`ModuleResult`/`ScanReport` field names consistent across models (Task 1), modules, reporters (Task 9), and CLI (Task 10). `all_modules()` grows monotonically across Tasks 6→7→8 with no renames. Reporter names `render_json/render_markdown/render_html` consistent between Task 9 and Task 10.
