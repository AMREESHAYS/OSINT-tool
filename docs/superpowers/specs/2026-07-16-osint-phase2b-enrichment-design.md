# OSINT Recon Engine — Phase 2b Design (AI Summary, Screenshots, Breach)

**Date:** 2026-07-16
**Status:** Approved design, ready for implementation planning
**Depends on:** Phase 1 (`osint` package, `ScanReport`, orchestrator, registry) and Phase 2a (SSE API, `build_graph`, live dashboard with placeholder cards).
**Scope:** Phase 2b — three optional enrichments that plug into the existing pipeline and light up the dashboard cards already wired in 2a.

## Problem

The engine and live dashboard exist, but the "AI Summary" card is a placeholder and there is no page-screenshot or breach-intelligence surface. Phase 2b adds these as **optional, gracefully-degrading** enrichments without compromising the tool's identity: the default install and default code path require **no paid API and no heavy dependency**.

## Goal

1. A written recon **summary** — free heuristic always; optional Anthropic Claude when explicitly opted in.
2. A **screenshot** module — optional Playwright headless Chromium; degrades to a notice.
3. A **breach** module — optional HIBP key; degrades to a notice.
4. Surface all three in the dashboard (and the summary in the CLI).

## Non-goals

- No new *required* dependency; core install stays paid-API-free and lightweight.
- No auto-calling the LLM on every scan — the LLM path is opt-in (`--ai` / `?ai=true`) *and* key-gated.
- No persistence/history; no auth. (Unchanged from prior phases.)
- Breach passwords/credentials are never fetched or stored — only breach metadata from HIBP.

## Components

### 1. Summary — `osint/summary.py`

```python
def summarize(report: ScanReport, use_llm: bool = False) -> str
```

- **Heuristic (always, instant, offline):** a 2–4 sentence narrative built from the report — risk level/score, counts by module, and notable findings (open ports, exposed `.git`/`.env`, missing security headers, subdomain count, HIGH/CRITICAL items). Deterministic string assembly, no I/O.
- **Optional LLM:** when `use_llm=True` **and** `ANTHROPIC_API_KEY` is set, lazy-import the `anthropic` SDK and ask Claude (default model **Claude Haiku**, cheapest tier, `max_tokens≈200`) for a sharper recon narrative given a trimmed report JSON. **Any** failure — SDK not installed, no key, API error, timeout — falls back to the heuristic. Never raises, never blocks the response.
- Derived like `build_graph` — **not** a field on the `ScanReport` model.
- Implementation note: the plan/implementation of the Anthropic call MUST consult the `claude-api` skill for the current model id, SDK shape, and message format. The spec fixes behavior (Haiku, opt-in, graceful fallback), not SDK line-detail.

### 2. Screenshot — `osint/modules/screenshot.py`

- `ScreenshotModule`, `name="screenshot"`, `applies_to={"domain"}` — a normal module, so it streams via `module_finished` like any other.
- Lazy-imports `playwright.async_api` inside `run()`. If Playwright (or its Chromium) is unavailable (`ImportError` or launch failure) → a single **INFO** finding `title="Screenshots unavailable"` (`detail` explains how to enable: `pip install 'osint[screenshots]' && playwright install chromium`). Never raises.
- On success: capture the homepage (`https://<target>`, viewport 1280×800, `timeout` from settings), a finding with `title="Homepage screenshot"`, `detail="Homepage captured"`, and `data={"image": "data:image/png;base64,<...>"}`. The base64 stays in `data` (not `detail`) so the findings list stays readable.
- Optional dependency: new `[screenshots]` extra = `playwright`.

### 3. Breach — `osint/modules/breach.py`

- `BreachModule`, `name="breach"`, `applies_to={"email"}`.
- No `HIBP_API_KEY` in the environment → one **INFO** finding `title="Breach check skipped"` (`detail`: set `HIBP_API_KEY` to enable). Preserves "no paid API required" as the default.
- With a key → GET `https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false` with the `hibp-api-key` header and a descriptive `User-Agent` (HIBP requires both), via the shared `httpx` client:
  - `404` → INFO `title="No known breaches"`.
  - `200` → one finding per breach: `title="Breach: {Name} ({BreachDate})"`, `detail` = the exposed data classes, severity **HIGH** if the `DataClasses` include passwords/credentials else **MEDIUM**, `data` = the breach record.
  - `401`/`429`/other → INFO `title="Breach check failed"` with the status (never raises).
- Uses the existing `httpx` dependency; no new package.

### 4. Registry / orchestrator

`registry.all_modules()` gains `ScreenshotModule()` and `BreachModule()`. No orchestrator change — both are ordinary modules, isolated by the existing per-module wrapper.

### 5. API (`osint/api.py`)

- `/scan` gains a `ai: bool = False` query param.
- The `report` event payload gains a `summary` field: `{"report": <ScanReport>, "graph": <graph>, "summary": <str>}` where `summary = summarize(report, use_llm=ai)`.
- Everything else unchanged.

### 6. CLI (`osint/cli.py`)

- `osint scan` gains `--ai` (bool). After the risk verdict, print the summary (`summarize(report, use_llm=ai)`). Heuristic by default; LLM only with `--ai` + key.

### 7. Frontend

- `types/osint.ts`: `ReportPayload` gains `summary: string`.
- `ResultsPage`:
  - The existing **AI Summary** `SectionCard` renders `payload.summary` (falls back to a "running…" state pre-report).
  - New **Screenshot** card: finds the `screenshot` finding across module results and, if it has `data.image`, renders `<img src={dataUri}>` (with an empty state otherwise). Only shown for domain scans.
  - New **Breach** card (email scans): lists `breach`-module findings, or an empty state.
- Styling: reuse `SectionCard` and the `cyber-*` palette. No new dependency.

## Data / degradation matrix

| Enrichment | Default (no extra/key) | Opted-in |
|---|---|---|
| Summary | heuristic narrative | Claude Haiku (`--ai`/`?ai=true` + `ANTHROPIC_API_KEY`), heuristic on any failure |
| Screenshot | INFO "unavailable" + how-to | PNG data-URI card (`[screenshots]` extra) |
| Breach | INFO "skipped" (email only) | HIBP findings (`HIBP_API_KEY`) |

## Error handling

- Every enrichment degrades to an INFO finding or the heuristic; none can raise out of the module (the orchestrator also isolates them as a backstop).
- The LLM call is wrapped so no exception escapes `summarize`; heuristic is the fallback.
- Screenshot base64 can be large; it rides the existing SSE `module_finished` frame (acceptable for single-page captures). Documented as a known weight.

## Testing (no live network, no real browser, no real LLM)

- **`tests/test_summary.py`**: heuristic output contains risk level + a notable finding for a sample report; `use_llm=True` with `ANTHROPIC_API_KEY` unset returns the heuristic (fallback); the LLM path is exercised by monkeypatching the internal `_llm_summary` helper (or the anthropic client) to return a canned string — no network.
- **`tests/test_screenshot.py`**: simulate Playwright missing (monkeypatch the lazy import / capture helper to raise `ImportError`) → one INFO "unavailable" finding, no raise; simulate a successful capture helper returning PNG bytes → a finding with a `data:image/png;base64,` URI.
- **`tests/test_breach.py`** (respx): no key → INFO "skipped"; key + mocked `404` → INFO "no breaches"; key + mocked `200` with a passwords breach → a HIGH finding; mocked `401` → INFO "failed". No live HIBP.
- **`tests/test_api.py`** (extend): the `report` event payload includes a `summary` string; `?ai=true` still returns (heuristic fallback, no network).
- **`tests/test_cli.py`** (extend): `osint scan <target> --only none` prints a summary line (heuristic over an empty report).
- **Frontend**: verified in the browser preview — a domain scan shows the summary card populated and a screenshot card (unavailable state acceptable if Playwright isn't installed in the preview env); an email scan shows the breach card ("skipped" state without a key).

## Packaging

- `pyproject.toml` optional extras: `[ai]` = `anthropic`; `[screenshots]` = `playwright`. Core deps unchanged.
- README: document the three optional enablements (`pip install 'osint[ai,screenshots]'`, `playwright install chromium`, `ANTHROPIC_API_KEY`, `HIBP_API_KEY`).
- Docker: base image unchanged (lightweight); a comment notes how to add the screenshots extra + browser if desired.

## Success criteria

1. A domain scan (CLI and dashboard) shows a written summary; with `--ai` + a key it uses Claude, otherwise the heuristic — and a missing key/SDK never errors.
2. The screenshot module either renders a homepage image card or a clean "unavailable" notice; never crashes a scan.
3. An email scan shows breach findings with a key, or a "skipped" notice without one.
4. `pytest` green with no live network, no real browser, no real LLM. Core `pip install .` pulls no LLM/browser dependency.
5. The "no paid API required" default path is fully intact.
