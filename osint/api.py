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
from osint.summary import summarize

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
                      skip: str | None = None, no_nmap: bool = False,
                      ai: bool = False):
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
        try:
            await task
            report = holder["report"]
            # summarize may make a blocking LLM call on the ?ai=true path — keep it off the event loop.
            summary = await asyncio.to_thread(summarize, report, ai)
            yield _sse("report", {"report": json.loads(report.model_dump_json()),
                                  "graph": build_graph(report),
                                  "summary": summary})
        except Exception as exc:  # noqa: BLE001 - surface any scan failure as an SSE error event, never a dead stream
            yield _sse("error", {"detail": str(exc) or exc.__class__.__name__})

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
