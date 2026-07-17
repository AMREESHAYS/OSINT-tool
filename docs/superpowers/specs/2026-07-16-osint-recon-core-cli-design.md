# OSINT Recon Engine — Phase 1 Design (Async Core + Rich CLI + Reports)

**Date:** 2026-07-16
**Status:** Approved design, ready for implementation planning
**Scope:** Phase 1 only. Phase 2 (FastAPI SSE wrapper + React dashboard + graph + AI summary) is out of scope here and gets its own spec.

## Problem

The current repo is two disconnected half-tools:

- `backend/` — real recon muscle (DNS, crt.sh subdomains, nmap, crawler, tech, dir brute, JS endpoints, screenshot, risk) but rough: bare `except:` everywhere, prints a raw dict, and **five competing orchestrators** (`orchestrator`, `_v2`, `_pro`, `_elite`, `_async`) wired inconsistently (`cli.py`→`_pro`, `main.py`→`_async`, `_elite` imported by nothing).
- `osint-dashboard/` — cleaner React/FastAPI shell with its own *thinner* parallel service layer that shares no code with `backend/`.

Plus three README variants. The goal is one polished, genuinely useful tool.

## Goal (Phase 1)

One installable Python package with a single async recon core, exposed as a **Rich CLI** with live progress and multi-format report export. Must be both demo-able (portfolio) and genuinely useful (bug-bounty/recon). Preserves the tool's original identity: **no paid API required** — everything works free/offline; anything needing a key is optional and degrades gracefully.

## Non-goals (deferred to Phase 2)

- FastAPI API, SSE streaming endpoint, React dashboard wiring.
- Entity correlation graph visualization.
- LLM/AI written summary.
- Screenshots (heavy Chromium/webkit dependency).
- Breach-database lookups requiring an API key.

## Target structure

```
pyproject.toml                # uv-managed, entry point: osint = "osint.cli:app"
osint/
  __init__.py
  core/
    classify.py               # domain | email | username | ip
    models.py                 # Pydantic v2: Finding, ModuleResult, ScanReport
    orchestrator.py           # THE one async orchestrator
    settings.py               # timeouts, concurrency, wordlist paths, optional keys
  modules/
    base.py                   # Module protocol + shared httpx client helper
    dns_records.py            # A/AAAA/MX/NS/TXT
    subdomains.py             # crt.sh
    ports.py                  # nmap -F (optional; skipped w/ warning if absent)
    tech.py                   # header + fingerprint detection
    headers.py                # security-header analysis
    crawler.py                # link extraction (httpx + selectolax)
    dir_bruteforce.py         # bundled small wordlist, concurrent
    js_endpoints.py           # regex endpoint/secret extraction from JS
    username.py               # curated ~15-platform async presence check
    email.py                  # domain/MX extraction + validity
    risk.py                   # heuristic scoring over collected findings
  reporting/
    json_report.py
    markdown_report.py
    html_report.py            # single self-contained file (inline CSS)
  cli.py                      # Typer + Rich
tests/
docs/
```

Deletes: all of `backend/services/orchestrator*.py` (collapsed to one), the duplicate
`osint-dashboard/backend/` service layer, `README_NEW.md`, `README_FINAL.md`. The
`osint-dashboard/frontend/` is kept untouched for Phase 2.

## Data model (`core/models.py`, Pydantic v2)

The single source of truth shared by every module, the CLI, and the reports.

```python
class Severity(str, Enum): INFO, LOW, MEDIUM, HIGH, CRITICAL

class Finding(BaseModel):
    module: str            # "subdomains", "headers", ...
    title: str             # human-readable, e.g. "Missing Content-Security-Policy"
    detail: str
    severity: Severity = Severity.INFO
    data: dict = {}        # structured payload for reports/machines

class ModuleResult(BaseModel):
    module: str
    ok: bool
    error: str | None = None
    duration_ms: int
    findings: list[Finding] = []

class ScanReport(BaseModel):
    target: str
    target_type: Literal["domain","email","username","ip","unknown"]
    started_at: datetime
    finished_at: datetime
    modules: list[ModuleResult]
    risk_score: int
    risk_level: Severity
```

## Module contract (`modules/base.py`)

Every module is an async callable with a uniform signature so the orchestrator treats
them identically and one failure never kills the scan:

```python
class Module(Protocol):
    name: str
    applies_to: set[str]          # {"domain"}, {"username"}, ...
    async def run(self, target: str, ctx: Context) -> list[Finding]: ...
```

- `ctx` carries a shared `httpx.AsyncClient`, settings, and a `progress` callback.
- The orchestrator wraps each `run()` in timing + try/except, producing a `ModuleResult`.
  A raised exception → `ok=False, error=...`, never a crash. **No bare `except:` anywhere** —
  catch specific exceptions (`httpx.HTTPError`, `asyncio.TimeoutError`, `OSError`).

## Orchestrator (`core/orchestrator.py`)

```python
async def scan(target: str, settings: Settings, on_event=None) -> ScanReport
```

1. `classify(target)` → target_type.
2. Select modules whose `applies_to` contains target_type.
3. `asyncio.gather` them under a shared client and a concurrency semaphore.
4. Emit progress events (`module_started`, `module_finished`) via `on_event` — this is
   the hook the CLI's live panel and (Phase 2) the SSE endpoint both consume.
5. Feed all findings to `risk.evaluate()` for score + level.
6. Return a `ScanReport`.

Single orchestrator replaces all five existing ones.

## Modules — behavior notes (cleaned/modernized from existing code)

- **dns_records** — `dnspython`, resolve A/AAAA/MX/NS/TXT; each record set a `Finding`.
- **subdomains** — crt.sh JSON; dedupe; INFO findings; MEDIUM if wildcard/many.
- **ports** — `nmap -F` via `asyncio.create_subprocess_exec` (not shell string). Parse
  open ports into structured findings. If `nmap` not on PATH → single INFO finding
  "nmap not installed, port scan skipped", not an error.
- **tech / headers** — one `httpx` GET, share the response; `tech` reports Server/
  X-Powered-By + basic fingerprints; `headers` flags each *missing* security header
  (CSP, X-Frame-Options, HSTS, X-Content-Type-Options) as LOW/MEDIUM.
- **crawler** — `httpx` + `selectolax` (faster than bs4), extract same-origin links, cap 50.
- **dir_bruteforce** — bundled ~200-entry wordlist (replaces the 5 hardcoded paths),
  concurrent GETs via semaphore; report 200/403/301 hits. Exposed `.git/`, `.env`,
  `admin` → HIGH.
- **js_endpoints** — fetch linked JS, regex for API paths and obvious secret patterns
  (`api_key`, `token=`); secret-looking hits → HIGH.
- **username** — curated dict of ~15 platforms (GitHub, Reddit, GitLab, Instagram,
  X/Twitter, TikTok, Twitch, Medium, Keybase, Telegram, Steam, HackerNews, Dev.to,
  Pastebin, YouTube). Async HEAD/GET with status heuristics; each hit a Finding.
- **email** — extract domain, MX lookup, RFC-ish validity. INFO only (no paid breach API).
- **risk** — weighted heuristics over *all* findings by severity (CRITICAL=10, HIGH=5,
  MEDIUM=2, LOW=1) → total score → level bucket. Replaces the toy 3-signal version.

## CLI (`cli.py`, Typer + Rich)

```
osint scan <target> [--json out.json] [--md out.md] [--html out.html]
                    [--only dns,ports] [--skip ports] [--no-nmap]
                    [--concurrency N] [--timeout S] [-q]
osint modules              # list available modules and what they apply to
osint version
```

- Live `rich.Live` panel: a table of modules with spinner → ✓/✗ + duration + finding
  count, driven by the orchestrator's `on_event` callback (feature 1: live streaming).
- After completion: a summary table of findings colored by severity + the risk verdict.
- `--json/--md/--html` write reports; multiple may be combined. No flag → pretty terminal only.
- Exit code: 0 on completion (findings are not failures); non-zero only on bad input/usage.

## Reporting

- **JSON** — `ScanReport.model_dump_json()`. The canonical machine format.
- **Markdown** — sectioned by module, severity badges, a findings table. Bug-bounty-writeup friendly.
- **HTML** — single self-contained file, inline CSS, collapsible module sections,
  severity color coding. No external assets (portable, shareable).

## Error handling

- Every module isolated (see contract). One dead module → `ok=False`, scan continues.
- Network: explicit timeouts from settings; retries left to Phase 2.
- Input: `classify` → `unknown` yields a clear CLI error, exit non-zero.
- A top-level authorization/ethics notice printed on first run and in the README:
  scan only targets you own or are authorized to test.

## Testing (pytest, no heavy fixtures)

- `classify` truth table (domain/email/username/ip/unknown edge cases).
- `risk.evaluate` scoring boundaries (each level bucket).
- Orchestrator isolation: a deliberately-throwing fake module yields `ok=False` and does
  not abort sibling modules or the scan.
- One module (`dir_bruteforce` or `username`) tested against a `respx`-mocked httpx
  transport — no live network in the test suite.
- Report round-trip: build a `ScanReport`, render each format, assert key fields present.

## Packaging / modern tooling

- `pyproject.toml` (uv), Python 3.11+, `ruff` for lint/format.
- Deps: `httpx`, `pydantic>=2`, `typer`, `rich`, `dnspython`, `selectolax`, `respx` (dev),
  `pytest` (dev). Drops `requests`, `beautifulsoup4`.
- `nmap` is an optional *system* binary, not a Python dep; absence is handled.
- Runnable via `uvx` / `pipx install`; single `Dockerfile` (Phase 1 includes nmap in image).
- One rewritten `README.md`; the two variant READMEs deleted.

## Success criteria

1. `osint scan example.com` runs the full domain pipeline with a live panel and prints a
   colored findings + risk summary.
2. `--html report.html` produces a self-contained shareable file.
3. A failing module never aborts the scan.
4. `pytest` green with no live network calls.
5. Five orchestrators and the duplicate dashboard backend are gone; one core remains.
