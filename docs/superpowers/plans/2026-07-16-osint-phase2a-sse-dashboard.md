# OSINT Phase 2a Implementation Plan — SSE API + Live Dashboard

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the Phase 1 recon core over a FastAPI SSE endpoint that streams findings as each module finishes, and rewrite the existing React dashboard to consume that stream live with a risk gauge and a relationship graph.

**Architecture:** The orchestrator's `on_event` callback is widened to carry each finished `ModuleResult`. A FastAPI endpoint bridges that synchronous callback to an async SSE generator via an `asyncio.Queue` + sentinel, emitting `module_started` / `module_finished` / `report` events. A pure `build_graph(report)` derives graph nodes/edges from findings. The frontend's TypeScript types mirror the Pydantic `ScanReport`; a native `EventSource` client feeds a live-updating results page. One schema end-to-end, no adapter layer.

**Tech Stack:** Python 3.11+, FastAPI, uvicorn, httpx (ASGITransport for tests), Pydantic v2, pytest; React 18 + Vite + TypeScript + Tailwind, `react-force-graph-2d`, native `EventSource`.

## Global Constraints

- Python `>=3.11`; Pydantic v2. No bare `except:` (name the exception class).
- No paid API on any default path.
- Python tests make **no live network calls** (use `httpx.ASGITransport` + monkeypatched fake modules; never hit the real registry's network modules).
- **One schema:** the TypeScript `ScanReport`/`Finding`/`ModuleResult` types mirror the Pydantic model exactly; no translation/adapter layer may exist.
- Frontend keeps the existing `cyber-*` Tailwind palette and `cyber-card` style; API base URL = `import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'`.
- SSE transport is native `EventSource` (GET only).
- The Phase 1 CLI (`osint scan ...`) must keep working unchanged after the orchestrator edit.
- Commit messages must NOT contain any AI/Co-Authored-By/"Generated with" trailer. Commit with `git -c user.name="AMREESHAYS" -c user.email="amreesh192006@gmail.com" commit ...`.
- Work happens on branch `phase2a-sse-dashboard`, created from `phase1-recon-core`. Python venv at repo `.venv`; run Python tests with `.venv/bin/pytest`.

---

### Task 1: Widen the orchestrator event callback

**Files:**
- Modify: `osint/core/orchestrator.py` (the two `on_event(...)` call sites in `_run_one`)
- Modify: `osint/cli.py` (the `on_event`/`cb` callback signatures)
- Test: `tests/test_orchestrator.py` (add one assertion)

**Interfaces:**
- Consumes: existing `scan`, `_run_one`, `ModuleResult`.
- Produces: `on_event(kind: str, module: str, result: ModuleResult | None)` — `result` is the completed `ModuleResult` on `module_finished`, `None` on `module_started`. This is the contract the API (Task 3) relies on to stream findings.

- [ ] **Step 1: Add a failing assertion to the existing isolation test**

In `tests/test_orchestrator.py`, add a new test after the existing ones:

```python
@pytest.mark.asyncio
async def test_finished_event_carries_result():
    seen = {}

    def on_event(kind, module, result=None):
        if kind == "module_finished":
            seen[module] = result

    await scan("example.com", Settings(), [GoodModule()], on_event=on_event)
    assert seen["good"].ok is True
    assert seen["good"].findings[0].title == "ok"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/pytest tests/test_orchestrator.py::test_finished_event_carries_result -v`
Expected: FAIL — the current `on_event` is called with only 2 args on finish, so `seen["good"]` is never assigned a `ModuleResult` (KeyError / None).

- [ ] **Step 3: Pass the result on the finished event**

In `osint/core/orchestrator.py`, in `_run_one`, change the finished-event call site from:

```python
        if on_event:
            on_event("module_finished", module.name)
        return result
```

to:

```python
        if on_event:
            on_event("module_finished", module.name, result)
        return result
```

(Leave the `module_started` call site as `on_event("module_started", module.name)` — callbacks give `result` a default of `None`.)

- [ ] **Step 4: Widen the CLI callback signatures**

In `osint/cli.py`, update the two nested callbacks in `scan` so they accept the third argument:

```python
    def on_event(kind: str, module: str, result=None):
        statuses[module] = "running…" if kind == "module_started" else "done"
```

and:

```python
            def cb(kind, module, result=None):
                on_event(kind, module, result)
                live.update(render_panel())
```

- [ ] **Step 5: Run the new test and the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (39 passed — the new test plus the existing 38).

- [ ] **Step 6: Commit**

```bash
git add osint/core/orchestrator.py osint/cli.py tests/test_orchestrator.py
git commit -m "feat: carry ModuleResult on the orchestrator module_finished event"
```

---

### Task 2: Graph builder

**Files:**
- Create: `osint/graph.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: `ScanReport`, `ModuleResult`, `Finding` (Phase 1 models).
- Produces: `build_graph(report: ScanReport) -> dict` returning `{"nodes": list[dict], "edges": list[dict]}` where each node is `{"id": str, "type": str}` and each edge is `{"source": str, "target": str}`. Node types: `target`, `ip`, `subdomain`, `tech`, `port`, `endpoint`, `profile`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_graph.py
from datetime import datetime, timezone

from osint.core.models import Finding, ModuleResult, ScanReport, Severity
from osint.graph import build_graph


def _report(findings_by_module):
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)
    modules = [
        ModuleResult(module=m, ok=True, duration_ms=1, findings=fs)
        for m, fs in findings_by_module.items()
    ]
    return ScanReport(target="example.com", target_type="domain",
                      started_at=now, finished_at=now, modules=modules,
                      risk_score=0, risk_level=Severity.INFO)


def test_graph_has_target_root_and_typed_nodes():
    report = _report({
        "subdomains": [Finding(module="subdomains", title="2 subdomains", detail="",
                               data={"subdomains": ["a.example.com", "b.example.com"]})],
        "tech": [Finding(module="tech", title="Server: nginx", detail="nginx", data={"Server": "nginx"})],
        "ports": [Finding(module="ports", title="Port 443/tcp open", detail="",
                          data={"port": 443, "service": "https"})],
    })
    graph = build_graph(report)
    nodes = {(n["id"], n["type"]) for n in graph["nodes"]}
    assert ("example.com", "target") in nodes
    assert ("a.example.com", "subdomain") in nodes
    assert ("b.example.com", "subdomain") in nodes
    assert ("443/tcp", "port") in nodes
    assert any(t == "tech" for _, t in nodes)
    # every edge originates from the target root
    assert all(e["source"] == "example.com" for e in graph["edges"])
    # a subdomain edge exists
    assert {"source": "example.com", "target": "a.example.com"} in graph["edges"]


def test_graph_dedupes_nodes():
    report = _report({
        "tech": [Finding(module="tech", title="Server: nginx", detail="nginx", data={"Server": "nginx"}),
                 Finding(module="tech", title="Server: nginx", detail="nginx", data={"Server": "nginx"})],
    })
    graph = build_graph(report)
    ids = [n["id"] for n in graph["nodes"]]
    assert len(ids) == len(set(ids))
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/pytest tests/test_graph.py -v`
Expected: FAIL — `No module named 'osint.graph'`.

- [ ] **Step 3: Write `osint/graph.py`**

```python
from osint.core.models import ScanReport


def build_graph(report: ScanReport) -> dict:
    root = report.target
    nodes: dict[str, str] = {root: "target"}  # id -> type
    edges: list[dict] = []

    def link(node_id: str, node_type: str):
        if node_id and node_id not in nodes:
            nodes[node_id] = node_type
        if node_id:
            edge = {"source": root, "target": node_id}
            if edge not in edges:
                edges.append(edge)

    for mod in report.modules:
        for f in mod.findings:
            if mod.module == "dns":
                for ip in f.data.get("A", [])[:10]:
                    link(ip, "ip")
            elif mod.module == "subdomains":
                for sub in f.data.get("subdomains", [])[:50]:
                    link(sub, "subdomain")
            elif mod.module == "tech":
                link(f.detail or f.title, "tech")
            elif mod.module == "ports":
                port = f.data.get("port")
                if port is not None:
                    link(f"{port}/tcp", "port")
            elif mod.module == "js_endpoints":
                for ep in f.data.get("endpoints", [])[:40]:
                    link(ep, "endpoint")
            elif mod.module == "username":
                # username findings are titled "Found on <platform>"
                link(f.title.replace("Found on ", ""), "profile")

    return {"nodes": [{"id": i, "type": t} for i, t in nodes.items()], "edges": edges}
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/pytest tests/test_graph.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add osint/graph.py tests/test_graph.py
git commit -m "feat: build relationship graph from a ScanReport"
```

---

### Task 3: FastAPI SSE API + deps + serve command

**Files:**
- Create: `osint/api.py`
- Modify: `pyproject.toml` (add `fastapi`, `uvicorn[standard]` to core deps)
- Modify: `osint/cli.py` (add `serve` command)
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `classify`, `scan`, `Settings`, `all_modules`, `build_graph`.
- Produces: `app` (FastAPI instance). Endpoints: `GET /health`, `GET /modules`, `GET /scan?target=&only=&skip=&no_nmap=` (SSE). Module lookup uses the module-global name `all_modules` so tests can monkeypatch `osint.api.all_modules`.

- [ ] **Step 1: Add deps and install**

In `pyproject.toml`, add to the `[project].dependencies` list:

```toml
    "fastapi>=0.110",
    "uvicorn[standard]>=0.29",
```

Then install:

Run: `uv pip install --python .venv/bin/python -e ".[dev]"`
Expected: fastapi + uvicorn installed.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_api.py
import json

import httpx
import pytest

from osint.core.models import Finding, Severity
from osint import api


class FakeModule:
    name = "fake"
    applies_to = {"domain"}

    async def run(self, target, ctx):
        return [Finding(module="fake", title="hello", detail=target, severity=Severity.LOW)]


def _parse_sse(text: str) -> list[dict]:
    events = []
    for block in text.strip().split("\n\n"):
        if not block.strip():
            continue
        ev = {}
        for line in block.splitlines():
            if line.startswith("event: "):
                ev["event"] = line[len("event: "):]
            elif line.startswith("data: "):
                ev["data"] = json.loads(line[len("data: "):])
        events.append(ev)
    return events


async def _get_text(path: str) -> str:
    transport = httpx.ASGITransport(app=api.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(path)
        return resp.text


@pytest.mark.asyncio
async def test_health():
    transport = httpx.ASGITransport(app=api.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_modules_lists_registry():
    transport = httpx.ASGITransport(app=api.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/modules")
    names = {m["name"] for m in resp.json()}
    assert "dns" in names and "username" in names


@pytest.mark.asyncio
async def test_scan_streams_events(monkeypatch):
    monkeypatch.setattr(api, "all_modules", lambda: [FakeModule()])
    text = await _get_text("/scan?target=example.com")
    events = _parse_sse(text)
    kinds = [e["event"] for e in events]
    assert kinds == ["module_started", "module_finished", "report"]
    assert events[1]["data"]["module"] == "fake"
    assert events[1]["data"]["findings"][0]["title"] == "hello"
    report_ev = events[2]["data"]
    assert report_ev["report"]["target"] == "example.com"
    assert "graph" in report_ev and "nodes" in report_ev["graph"]


@pytest.mark.asyncio
async def test_scan_unknown_target_emits_error():
    text = await _get_text("/scan?target=has spaces")
    events = _parse_sse(text)
    assert events[0]["event"] == "error"
    assert "classify" in events[0]["data"]["detail"].lower()
```

- [ ] **Step 3: Run to verify it fails**

Run: `.venv/bin/pytest tests/test_api.py -v`
Expected: FAIL — `No module named 'osint.api'`.

- [ ] **Step 4: Write `osint/api.py`**

```python
import asyncio
import json

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from osint.core.classify import classify
from osint.core.orchestrator import scan
from osint.core.settings import Settings
from osint.graph import build_graph
from osint.modules.registry import all_modules

app = FastAPI(title="OSINT Recon Engine API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

_SENTINEL = object()


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/modules")
async def modules():
    return [{"name": m.name, "applies_to": sorted(m.applies_to)} for m in all_modules()]


@app.get("/scan")
async def scan_stream(target: str, only: str | None = None,
                      skip: str | None = None, no_nmap: bool = False):
    async def gen():
        if classify(target) == "unknown":
            yield _sse("error", {"detail": f"Could not classify target: {target!r}"})
            return

        mods = all_modules()
        if only:
            wanted = {s.strip() for s in only.split(",")}
            mods = [m for m in mods if m.name in wanted]
        if skip:
            unwanted = {s.strip() for s in skip.split(",")}
            mods = [m for m in mods if m.name not in unwanted]

        settings = Settings(nmap_enabled=not no_nmap)
        queue: asyncio.Queue = asyncio.Queue()
        holder: dict = {}

        def on_event(kind, module, result=None):
            queue.put_nowait({"kind": kind, "module": module, "result": result})

        async def run_and_signal():
            try:
                holder["report"] = await scan(target, settings, mods, on_event=on_event)
            finally:
                await queue.put(_SENTINEL)

        task = asyncio.create_task(run_and_signal())
        while True:
            item = await queue.get()
            if item is _SENTINEL:
                break
            if item["kind"] == "module_started":
                yield _sse("module_started", {"module": item["module"]})
            else:
                yield _sse("module_finished", item["result"].model_dump(mode="json"))
        await task
        report = holder["report"]
        yield _sse("report", {"report": json.loads(report.model_dump_json()),
                              "graph": build_graph(report)})

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
```

- [ ] **Step 5: Add the `serve` command to the CLI**

In `osint/cli.py`, add a new command (imports go at the top of the function to avoid importing uvicorn at CLI load time):

```python
@app.command()
def serve(host: str = typer.Option("127.0.0.1", "--host"),
          port: int = typer.Option(8000, "--port")):
    """Run the SSE API server (uvicorn)."""
    import uvicorn
    uvicorn.run("osint.api:app", host=host, port=port)
```

- [ ] **Step 6: Run the API tests and the full suite**

Run: `.venv/bin/pytest tests/test_api.py -v`
Expected: PASS (4 passed).

Run: `.venv/bin/pytest -q`
Expected: PASS (all green — 45 tests: 39 + 2 graph + 4 api).

- [ ] **Step 7: Smoke-test the server boots and streams**

Run:
```bash
.venv/bin/osint serve --port 8011 &
sleep 2
curl -sN "http://127.0.0.1:8011/scan?target=example.com&only=dns,headers" | head -8
kill %1
```
Expected: SSE frames (`event: module_started` … `event: report`). Capture in the report.

- [ ] **Step 8: Commit**

```bash
git add osint/api.py osint/cli.py pyproject.toml tests/test_api.py
git commit -m "feat: FastAPI SSE /scan endpoint, /modules, /health, osint serve"
```

---

### Task 4: Frontend data layer — types + SSE client

**Files:**
- Rewrite: `osint-dashboard/frontend/src/types/osint.ts`
- Rewrite: `osint-dashboard/frontend/src/services/api.ts`

**Interfaces:**
- Produces:
  - Types mirroring the Pydantic model: `Severity`, `Finding`, `ModuleResult`, `ScanReport`, `GraphNode`, `GraphEdge`, `ReportPayload`.
  - `openScanStream(target: string, handlers: ScanStreamHandlers): EventSource` where `ScanStreamHandlers = { onModuleStarted(module: string), onModuleFinished(result: ModuleResult), onReport(payload: ReportPayload), onError(detail: string) }`.

**Note:** No frontend unit tests (per spec — verified in-browser). The gate for frontend tasks is a clean `npx tsc --noEmit` typecheck plus `npm run build`.

- [ ] **Step 1: Ensure frontend deps are installed**

Run (from `osint-dashboard/frontend`): `npm install`
Expected: `node_modules` present, no errors. (If `node`/`npm` is unavailable, STOP and report BLOCKED — the frontend tasks need it.)

- [ ] **Step 2: Write `src/types/osint.ts` (replace entire file)**

```typescript
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type Finding = {
  module: string;
  title: string;
  detail: string;
  severity: Severity;
  data: Record<string, unknown>;
};

export type ModuleResult = {
  module: string;
  ok: boolean;
  error: string | null;
  duration_ms: number;
  findings: Finding[];
};

export type ScanReport = {
  target: string;
  target_type: string;
  started_at: string;
  finished_at: string;
  modules: ModuleResult[];
  risk_score: number;
  risk_level: Severity;
};

export type GraphNode = { id: string; type: string };
export type GraphEdge = { source: string; target: string };

export type ReportPayload = {
  report: ScanReport;
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
};
```

- [ ] **Step 3: Write `src/services/api.ts` (replace entire file)**

```typescript
import type { ModuleResult, ReportPayload } from '../types/osint';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

export type ScanStreamHandlers = {
  onModuleStarted: (module: string) => void;
  onModuleFinished: (result: ModuleResult) => void;
  onReport: (payload: ReportPayload) => void;
  onError: (detail: string) => void;
};

export function openScanStream(target: string, handlers: ScanStreamHandlers): EventSource {
  const url = `${API_BASE_URL}/scan?target=${encodeURIComponent(target)}`;
  const es = new EventSource(url);
  let settled = false;
  const finish = () => {
    settled = true;
    es.close();
  };

  es.addEventListener('module_started', (e) => {
    handlers.onModuleStarted(JSON.parse((e as MessageEvent).data).module);
  });
  es.addEventListener('module_finished', (e) => {
    handlers.onModuleFinished(JSON.parse((e as MessageEvent).data) as ModuleResult);
  });
  es.addEventListener('report', (e) => {
    handlers.onReport(JSON.parse((e as MessageEvent).data) as ReportPayload);
    finish();
  });
  es.addEventListener('error', (e) => {
    if (settled) return;
    const raw = (e as MessageEvent).data;
    if (raw) {
      handlers.onError(JSON.parse(raw).detail ?? 'Scan error.');
    } else {
      handlers.onError('Connection lost.');
    }
    finish();
  });

  return es;
}
```

- [ ] **Step 4: Typecheck**

Run (from `osint-dashboard/frontend`): `npx tsc --noEmit`
Expected: no errors. (`ResultsPage.tsx`/`InputPage.tsx` still reference the old API here — if `tsc` reports errors *only* in those two not-yet-migrated files, that is expected; they are rewritten in Task 6. Confirm there are no errors in `types/osint.ts` or `services/api.ts` themselves.)

- [ ] **Step 5: Commit**

```bash
git add osint-dashboard/frontend/src/types/osint.ts osint-dashboard/frontend/src/services/api.ts
git commit -m "feat(ui): ScanReport types + EventSource SSE client"
```

---

### Task 5: Frontend components — RiskGauge, ModuleProgress, GraphView colors

**Files:**
- Create: `osint-dashboard/frontend/src/components/RiskGauge.tsx`
- Create: `osint-dashboard/frontend/src/components/ModuleProgress.tsx`
- Modify: `osint-dashboard/frontend/src/graph/GraphView.tsx`

**Interfaces:**
- Consumes: `Severity`, `ModuleResult`, `GraphNode`, `GraphEdge`.
- Produces:
  - `RiskGauge({ level: Severity, score: number })`.
  - `ModuleProgress({ states: Record<string, ModuleState> })` and exported `type ModuleState = { status: 'running' | 'done'; result?: ModuleResult }`.
  - `GraphView` unchanged props (`{ nodes, edges }`) but nodes colored by `type`.

- [ ] **Step 1: Write `src/components/RiskGauge.tsx`**

```tsx
import type { Severity } from '../types/osint';

const COLORS: Record<Severity, string> = {
  INFO: '#8ea0c9',
  LOW: '#3b82f6',
  MEDIUM: '#eab308',
  HIGH: '#ef4444',
  CRITICAL: '#d946ef',
};

function RiskGauge({ level, score }: { level: Severity; score: number }) {
  return (
    <div className="cyber-card flex flex-col items-center justify-center p-6">
      <p className="text-xs uppercase tracking-[0.2em] text-cyber-muted">Risk</p>
      <p className="text-4xl font-bold" style={{ color: COLORS[level] }}>{level}</p>
      <p className="text-sm text-slate-300">score {score}</p>
    </div>
  );
}

export default RiskGauge;
```

- [ ] **Step 2: Write `src/components/ModuleProgress.tsx`**

```tsx
import type { ModuleResult } from '../types/osint';

export type ModuleState = { status: 'running' | 'done'; result?: ModuleResult };

function ModuleProgress({ states }: { states: Record<string, ModuleState> }) {
  const entries = Object.entries(states);
  return (
    <div className="cyber-card p-4">
      <h2 className="mb-3 text-lg font-semibold text-cyan-100">Modules</h2>
      {entries.length === 0 ? (
        <p className="text-cyber-muted text-sm">Waiting for scan to start…</p>
      ) : (
        <ul className="space-y-1 text-sm">
          {entries.map(([name, s]) => (
            <li key={name} className="flex items-center justify-between">
              <span className="text-slate-200">{name}</span>
              <span
                className={
                  s.status === 'done'
                    ? s.result?.ok
                      ? 'text-emerald-400'
                      : 'text-rose-400'
                    : 'text-cyan-300'
                }
              >
                {s.status === 'running'
                  ? 'running…'
                  : s.result?.ok
                    ? `✓ ${s.result.findings.length}`
                    : `✗ ${s.result?.error ?? 'failed'}`}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default ModuleProgress;
```

- [ ] **Step 3: Color GraphView nodes by type**

In `src/graph/GraphView.tsx`, add a color map above the component and use it in `nodeCanvasObject`. Replace the existing `ctx.fillStyle = '#00ffa6';` line (the node-circle fill) with a type lookup:

```tsx
const NODE_COLORS: Record<string, string> = {
  target: '#00ffa6',
  ip: '#38bdf8',
  subdomain: '#a78bfa',
  tech: '#f472b6',
  port: '#f59e0b',
  endpoint: '#facc15',
  profile: '#34d399',
};
```

and inside `nodeCanvasObject`, change the circle fill to:

```tsx
          ctx.fillStyle = NODE_COLORS[n.type] ?? '#00ffa6';
```

(Keep the label-fill line `ctx.fillStyle = '#dbeafe';` for the text as-is.)

- [ ] **Step 4: Typecheck**

Run (from `osint-dashboard/frontend`): `npx tsc --noEmit`
Expected: no errors in the three files above (errors only in the not-yet-migrated `ResultsPage.tsx`/`InputPage.tsx` are acceptable until Task 6).

- [ ] **Step 5: Commit**

```bash
git add osint-dashboard/frontend/src/components/RiskGauge.tsx osint-dashboard/frontend/src/components/ModuleProgress.tsx osint-dashboard/frontend/src/graph/GraphView.tsx
git commit -m "feat(ui): RiskGauge, ModuleProgress, type-colored graph nodes"
```

---

### Task 6: Frontend pages — live stream consumer

**Files:**
- Modify: `osint-dashboard/frontend/src/App.tsx` (route `/results/:id` → `/results`)
- Modify: `osint-dashboard/frontend/src/pages/InputPage.tsx` (route to `/results?target=`)
- Rewrite: `osint-dashboard/frontend/src/pages/ResultsPage.tsx` (consume SSE stream)

**Interfaces:**
- Consumes: `openScanStream` (Task 4), `RiskGauge`/`ModuleProgress`/`ModuleState` (Task 5), `GraphView`, `SectionCard`, types (Task 4).

- [ ] **Step 1: Update the route in `src/App.tsx`**

Change the results route from `<Route path="/results/:id" element={<ResultsPage />} />` to:

```tsx
      <Route path="/results" element={<ResultsPage />} />
```

- [ ] **Step 2: Rewrite `src/pages/InputPage.tsx` submit handler**

Replace the whole file with:

```tsx
import { FormEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';

function InputPage() {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    const target = query.trim();
    if (!target) return;
    navigate(`/results?target=${encodeURIComponent(target)}`);
  };

  return (
    <main className="mx-auto flex min-h-screen max-w-4xl items-center px-4 py-10">
      <div className="cyber-card w-full p-8">
        <p className="mb-2 text-sm uppercase tracking-[0.2em] text-cyber-muted">OSINT Recon Engine</p>
        <h1 className="mb-6 text-3xl font-bold text-cyan-100">Target Input</h1>

        <form className="space-y-4" onSubmit={handleSubmit}>
          <input
            type="text"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Enter domain, email, username, or IP"
            className="w-full rounded-lg border border-cyan-900/60 bg-cyber-panelAlt px-4 py-3 text-slate-100 outline-none ring-cyan-500 focus:ring"
            required
          />
          <button
            type="submit"
            className="rounded-lg bg-cyan-500 px-5 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400"
          >
            Run OSINT Scan
          </button>
        </form>
      </div>
    </main>
  );
}

export default InputPage;
```

- [ ] **Step 3: Rewrite `src/pages/ResultsPage.tsx`**

Replace the whole file with:

```tsx
import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import ModuleProgress, { ModuleState } from '../components/ModuleProgress';
import RiskGauge from '../components/RiskGauge';
import SectionCard from '../components/SectionCard';
import GraphView from '../graph/GraphView';
import { openScanStream } from '../services/api';
import type { Finding, ReportPayload, Severity } from '../types/osint';

const SEV_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_COLOR: Record<Severity, string> = {
  INFO: 'text-slate-400',
  LOW: 'text-blue-400',
  MEDIUM: 'text-yellow-400',
  HIGH: 'text-red-400',
  CRITICAL: 'text-fuchsia-400',
};

function ResultsPage() {
  const [params] = useSearchParams();
  const target = params.get('target') ?? '';
  const [states, setStates] = useState<Record<string, ModuleState>>({});
  const [payload, setPayload] = useState<ReportPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!target) return undefined;
    setStates({});
    setPayload(null);
    setError(null);
    const es = openScanStream(target, {
      onModuleStarted: (m) => setStates((s) => ({ ...s, [m]: { status: 'running' } })),
      onModuleFinished: (r) => setStates((s) => ({ ...s, [r.module]: { status: 'done', result: r } })),
      onReport: (p) => setPayload(p),
      onError: (d) => setError(d),
    });
    return () => es.close();
  }, [target]);

  const findings: Finding[] = useMemo(
    () => Object.values(states).flatMap((s) => s.result?.findings ?? []),
    [states],
  );
  const sortedFindings = useMemo(
    () => [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)),
    [findings],
  );

  const report = payload?.report;
  const graph = payload?.graph ?? { nodes: [], edges: [] };
  const done = payload !== null;

  return (
    <main className="mx-auto min-h-screen max-w-6xl px-4 py-8">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-cyber-muted">Investigation</p>
          <h1 className="text-2xl font-bold text-cyan-100">{target || 'No target'}</h1>
          <p className="text-sm text-slate-300">{error ? `Error: ${error}` : done ? 'Complete' : 'Scanning…'}</p>
        </div>
        <Link to="/" className="rounded-md border border-cyan-800 px-3 py-2 text-sm text-cyan-200 hover:bg-cyan-900/30">
          New Scan
        </Link>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <ModuleProgress states={states} />
        {report ? <RiskGauge level={report.risk_level} score={report.risk_score} /> : (
          <div className="cyber-card flex items-center justify-center p-6 text-cyber-muted">Computing risk…</div>
        )}
        <SectionCard title="AI Summary">
          <p className="text-cyber-muted">Coming in Phase 2b.</p>
        </SectionCard>
      </div>

      <div className="mt-6">
        <h2 className="mb-3 text-xl font-semibold text-cyan-100">Findings</h2>
        <div className="cyber-card divide-y divide-cyan-900/30 p-2">
          {sortedFindings.length === 0 ? (
            <p className="p-3 text-cyber-muted">No findings yet.</p>
          ) : (
            sortedFindings.map((f, i) => (
              <div key={`${f.module}-${f.title}-${i}`} className="p-3">
                <p>
                  <span className={`mr-2 text-xs font-bold ${SEV_COLOR[f.severity]}`}>{f.severity}</span>
                  <span className="text-slate-400">[{f.module}]</span> <span className="text-slate-100">{f.title}</span>
                </p>
                {f.detail ? <pre className="mt-1 whitespace-pre-wrap text-xs text-slate-400">{f.detail}</pre> : null}
              </div>
            ))
          )}
        </div>
      </div>

      <div className="mt-6">
        <h2 className="mb-3 text-xl font-semibold text-cyan-100">Relationship Graph</h2>
        <GraphView nodes={graph.nodes} edges={graph.edges} />
      </div>
    </main>
  );
}

export default ResultsPage;
```

- [ ] **Step 4: Typecheck and build**

Run (from `osint-dashboard/frontend`): `npx tsc --noEmit`
Expected: **no errors anywhere now** (all files migrated).

Run: `npm run build`
Expected: Vite build succeeds, emits `dist/`.

- [ ] **Step 5: Commit**

```bash
git add osint-dashboard/frontend/src/App.tsx osint-dashboard/frontend/src/pages/InputPage.tsx osint-dashboard/frontend/src/pages/ResultsPage.tsx
git commit -m "feat(ui): live SSE-streaming results page + target routing"
```

---

### Task 7: End-to-end verification + run docs

**Files:**
- Create: `.claude/launch.json` (Vite dev server config for the preview tool)
- Modify: `README.md` (add a "Web dashboard" run section)

**Interfaces:** none (integration + docs).

- [ ] **Step 1: Confirm the full Python suite is green**

Run: `.venv/bin/pytest -q`
Expected: PASS (all backend tests green, no live network).

- [ ] **Step 2: Add a Vite launch config for the preview tool**

Create `.claude/launch.json`:

```json
{
  "version": "0.0.1",
  "configurations": [
    {
      "name": "osint-dashboard",
      "runtimeExecutable": "npm",
      "runtimeArgs": ["run", "dev"],
      "port": 5173,
      "cwd": "osint-dashboard/frontend"
    }
  ]
}
```

- [ ] **Step 3: Start the backend and run an end-to-end browser check**

Start the API in the background:
```bash
.venv/bin/osint serve --port 8000 &
```
Start the dev server via the preview tool (`preview_start` with name `osint-dashboard`), navigate to `http://localhost:5173`, enter `example.com`, submit, and verify in the browser:
- modules appear in the ModuleProgress list and flip from `running…` to `✓/✗`,
- findings stream in with severity colors,
- the RiskGauge shows a level + score after completion,
- the relationship graph renders nodes (target + subdomains/tech/etc.).

Capture a screenshot as proof. Check `read_console_messages` for errors (expect none; if CORS errors appear, confirm the API's `allow_origins` includes the dev origin). Stop the backend when done (`kill %1`).

- [ ] **Step 4: Add a "Web dashboard" section to `README.md`**

Insert after the existing "Usage" section:

```markdown
## Web dashboard (Phase 2a)

Two processes — the SSE API and the Vite dev server:

```bash
# 1. API (streams findings live)
osint serve                      # http://127.0.0.1:8000

# 2. Frontend
cd osint-dashboard/frontend
npm install && npm run dev       # http://localhost:5173
```

Open http://localhost:5173, enter a target, and watch modules stream in with a
live risk gauge and relationship graph. Set `VITE_API_BASE_URL` to point the
frontend at a non-default API origin.
```

- [ ] **Step 5: Commit**

```bash
git add .claude/launch.json README.md
git commit -m "docs: web dashboard run steps; add Vite launch config"
```

---

## Self-Review

**Spec coverage:**
- SSE `/scan` with `module_started`/`module_finished`/`report`/`error` events → Task 3 (+ orchestrator change Task 1). ✓
- Orchestrator `on_event` gains `result` → Task 1; CLI stays compatible → Task 1 (steps 4–5). ✓
- `build_graph(report)` derivation (target/ip/subdomain/tech/port/endpoint/profile, deduped, capped) → Task 2. ✓
- `/modules`, `/health`, CORS for :5173, `only/skip/no_nmap`, `osint serve`, fastapi+uvicorn deps → Task 3. ✓
- Frontend types mirror ScanReport; EventSource client → Task 4. ✓
- RiskGauge, ModuleProgress, type-colored graph → Task 5. ✓
- InputPage `/results?target=` routing, ResultsPage live consumer, App route change → Task 6. ✓
- Phase-2b placeholder cards (AI summary) present → Task 6 (SectionCard "Coming in Phase 2b"). ✓
- One schema / no adapter → Tasks 4+6 consume ScanReport directly. ✓
- No live network in Python tests (ASGITransport + FakeModule + unknown-target) → Task 3. ✓
- Frontend verified in browser, no FE unit framework → Task 7. ✓
- CLI still works after the change → Task 1 full-suite step + Task 7 (pytest includes CLI tests). ✓

**Placeholder scan:** No TBD/TODO. The "Coming in Phase 2b" card is deliberate deferred-feature UI, not an unfinished step. Every code step contains complete code.

**Type consistency:**
- `on_event(kind, module, result=None)` consistent across orchestrator (Task 1), API `on_event` (Task 3), and CLI callbacks (Task 1).
- `build_graph(report) -> {"nodes","edges"}` consumed by the API `report` event (Task 3) and the frontend `ReportPayload.graph` (Tasks 4, 6) — node shape `{id,type}`, edge shape `{source,target}` consistent with `GraphView` props (Task 5).
- SSE event names (`module_started`/`module_finished`/`report`/`error`) identical between the API emitter (Task 3) and the `openScanStream` listeners (Task 4).
- `ModuleState`/`openScanStream`/`ScanStreamHandlers` names consistent between Tasks 4, 5, 6.
- `report.model_dump_json()` → JSON object under `report` key; frontend `ReportPayload.report: ScanReport` matches field names (`risk_level`, `risk_score`, `modules`, `target`). ✓
