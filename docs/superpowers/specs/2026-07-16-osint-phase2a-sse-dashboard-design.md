# OSINT Recon Engine — Phase 2a Design (SSE API + Live Dashboard)

**Date:** 2026-07-16
**Status:** Approved design, ready for implementation planning
**Depends on:** Phase 1 (merged/branch `phase1-recon-core`) — the `osint` package, its `ScanReport` model, orchestrator, 10 modules, and registry.
**Scope:** Phase 2a only. Phase 2b (AI summary, screenshots, breach lookups) is a separate follow-up spec.

## Problem

Phase 1 produced a fast async recon core with a CLI, but its only surface is the terminal. The repo still carries a React/Vite dashboard (`osint-dashboard/frontend/`) wired to an old, deleted backend whose data shape (`domain_intelligence.dns`, `email_intelligence.breaches`, `username_intelligence.profiles`) does not match Phase 1's generic `ScanReport` (`modules[] → findings[]`, `risk_score`, `risk_level`). The dashboard is dead.

## Goal (Phase 2a)

Expose the Phase 1 core over an HTTP API that **streams findings live** as each module finishes, and rewrite the existing dashboard to consume the real `ScanReport` model with that live stream and a relationship graph. One schema end-to-end (Pydantic model → JSON → TypeScript mirror). Keep the existing cyberpunk styling. Preserve "no paid API required."

## Non-goals (Phase 2b)

- AI summary generation, screenshots, breach-database lookups. Their UI cards render an empty/"coming soon" state in 2a and light up when 2b lands.
- Auth, persistence/history, multi-user. Scans are per-connection and ephemeral.
- WebSocket transport (SSE via `EventSource` is the chosen transport).

## Architecture

```
osint/
  api.py            # NEW: FastAPI app — SSE /scan, /modules, /health
  graph.py          # NEW: build_graph(report) -> {nodes, edges}
  core/orchestrator.py   # MODIFIED: on_event gains a 3rd arg (result)
  cli.py            # MODIFIED: callback accepts the new arg; add `osint serve`
osint-dashboard/frontend/src/
  types/osint.ts    # REWRITE: mirror ScanReport
  services/api.ts   # REWRITE: EventSource SSE client
  pages/InputPage.tsx    # MODIFIED: route to /results?target=
  pages/ResultsPage.tsx  # REWRITE: live stream consumer
  graph/GraphView.tsx    # MODIFIED: color nodes by type
  components/RiskGauge.tsx   # NEW
  components/ModuleProgress.tsx  # NEW
```

### SSE event protocol (`GET /scan?target=&only=&skip=&no_nmap=`)

`Content-Type: text/event-stream`. Events, in order:

1. `event: module_started` — `data: {"module": "dns"}` — one per module as it begins.
2. `event: module_finished` — `data: <ModuleResult JSON>` (`{module, ok, error, duration_ms, findings[]}`) — one per module as it completes; findings stream in here.
3. `event: report` — `data: {"report": <ScanReport JSON>, "graph": {"nodes":[...], "edges":[...]}}` — terminal event; the client closes the `EventSource` on receipt.
4. `event: error` — `data: {"detail": "..."}` — emitted (then stream closes) if the target classifies as `unknown`. (Sent as an SSE event, not an HTTP error, because `EventSource` cannot read a non-200 body.)

Framing: each message is `event: <name>\ndata: <json>\n\n`. Response headers include `Cache-Control: no-cache` and `X-Accel-Buffering: no` (disables proxy buffering so events flush immediately).

### Streaming mechanism (async bridge)

The orchestrator's `on_event` is a synchronous callback invoked inside the running scan's event loop. The API bridges it to the async SSE generator with an `asyncio.Queue` and a sentinel:

```
queue = asyncio.Queue()
def on_event(kind, module, result=None):
    queue.put_nowait({"kind": kind, "module": module, "result": result})

async def run_and_signal():
    try:
        holder["report"] = await scan(target, settings, mods, on_event=on_event)
    finally:
        await queue.put(_SENTINEL)

# generator: drain the queue until the sentinel, yield each as an SSE frame,
# then yield the terminal `report` event built from holder["report"].
```

No two-task racing; the sentinel guarantees the generator terminates even if the scan raises (a raised scan is impossible today — modules are isolated — but the `finally` makes it robust).

### Orchestrator change (the one core edit)

`on_event(kind, module)` → `on_event(kind, module, result=None)`. On `module_finished`, the orchestrator passes the completed `ModuleResult` as `result`; on `module_started` it passes `None`. This is the only change that lets the API stream a module's findings the instant it finishes. Backward-compatible: the Phase 1 CLI callback signature is widened to accept and ignore the third argument. All existing orchestrator tests stay green; one test gains an assertion that `result` is populated on finish.

### Graph builder (`osint/graph.py`)

`build_graph(report: ScanReport) -> dict` with `nodes: list[{id, type}]` and `edges: list[{source, target}]`. Derivation (all edges originate from the target root, deduped by node id, each category capped to keep the graph legible):

| Source finding | Node(s) | type | cap |
|---|---|---|---|
| root | `target` | `target` | 1 |
| dns A records (`data["A"]`) | each IP | `ip` | 10 |
| subdomains (`data["subdomains"]`) | each subdomain | `subdomain` | 50 |
| tech findings | header value | `tech` | — |
| ports (`data["port"]`) | `"{port}/tcp"` | `port` | — |
| js_endpoints (`data["endpoints"]`) | each endpoint | `endpoint` | 40 |
| username "Found on X" | platform | `profile` | — |

### API app details

- `GET /modules` → `[{name, applies_to}]` from the registry (feeds a UI "what will run" hint).
- `GET /health` → `{"status":"ok"}`.
- CORS: allow origins `http://localhost:5173` and `http://127.0.0.1:5173` (the Vite dev server), methods GET, all headers.
- `only`/`skip` are comma-separated module-name filters, same semantics as the CLI; `no_nmap` toggles `Settings.nmap_enabled`.
- New CLI convenience command `osint serve [--host --port]` runs `uvicorn osint.api:app` so the backend starts with one command.
- New deps: `fastapi`, `uvicorn[standard]` added to `pyproject` core dependencies.

### Frontend

- **`types/osint.ts`** — exact mirror of the Pydantic model: `Severity` union, `Finding`, `ModuleResult`, `ScanReport`, `GraphNode`, `GraphEdge`, plus the SSE payload types (`ModuleStartedEvent`, `ReportEvent`).
- **`services/api.ts`** — `openScanStream(target, handlers): EventSource`. Opens `EventSource(${API_BASE}/scan?target=...)`, dispatches `module_started` / `module_finished` / `report` / `error` to typed handlers, closes on `report`/`error`. `API_BASE` from `VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'`.
- **`InputPage`** — on submit, client-side classify sanity-check optional; navigate to `/results?target=<encoded>` (query param, since targets contain `.`/`@`). Remove the old `analyzeQuery` call.
- **`ResultsPage`** — reads `target` from the query string, opens the stream on mount (cleanup closes the `EventSource`). Renders: a live **ModuleProgress** list (each module: pending → running → ✓/✗ + finding count), findings grouped by module with severity-colored badges, a **RiskGauge** (from the final `report`), and **GraphView** fed by the streamed `graph`. Placeholder cards for AI summary / screenshots / breaches (Phase 2b). Keeps `cyber-card` styling and the `cyber` Tailwind palette.
- **`RiskGauge`** — small component: risk level + score, colored by severity (INFO grey → CRITICAL magenta), matching the CLI's palette.
- **`GraphView`** — extend the existing `react-force-graph-2d` node renderer to color nodes by `type` (target/ip/subdomain/tech/port/endpoint/profile).

## Error handling

- Unknown target → `error` SSE event + stream close; the UI shows the detail and a "New Scan" link.
- Module failure already isolated by the orchestrator (`ok=false` streamed in its `module_finished` event); the UI shows it as a failed module, scan continues.
- `EventSource` network drop → the UI shows a "connection lost" state (its native `onerror` with `readyState === CLOSED`).
- Backend/frontend origin mismatch handled by CORS; documented in the README run steps.

## Testing

- **`tests/test_api.py`** (httpx `ASGITransport`, no network): (1) `GET /health` ok; (2) `GET /modules` lists the registry; (3) a scan whose module source is monkeypatched (patch the `all_modules` reference used by `api.py` to return a single in-test fake module that emits one finding without touching the network) yields the ordered event sequence `module_started` → `module_finished` (with the fake finding) → `report`, and the `report` event contains a valid `ScanReport` + a `graph` key; (4) an unknown target (e.g. `"has spaces"`) yields an `error` event. Read the stream via `AsyncClient.stream("GET", ...)` and parse SSE frames.
- **`tests/test_graph.py`**: `build_graph` over a hand-built `ScanReport` (subdomain + tech + port findings) produces the expected node types and target-rooted edges, deduped.
- **`tests/test_orchestrator.py`** (extend): assert the `module_finished` event carries the `ModuleResult` (new third arg); existing isolation tests unchanged and green.
- **Frontend**: verified live in the browser preview (Vite dev + `osint serve`) — run a real scan against `example.com`, confirm modules stream in, findings + risk gauge render, graph draws. No frontend unit-test framework added (YAGNI); the SSE accumulator logic is thin and covered by the manual end-to-end pass.

## Success criteria

1. `osint serve` + `npm run dev`, enter `example.com` → modules appear live one-by-one, findings stream in with severity colors, a risk gauge shows the verdict, and the relationship graph renders.
2. `GET /scan?target=example.com` emits a well-formed SSE stream ending in a `report` event whose payload round-trips as a `ScanReport`.
3. The Phase 1 CLI still works unchanged (`osint scan example.com`), proving the orchestrator change is backward-compatible.
4. `pytest` green (API + graph + orchestrator), no live network in the suite. Frontend end-to-end verified in-browser.
5. One schema: the TS `ScanReport` type mirrors the Pydantic model; no translation/adapter layer exists.
