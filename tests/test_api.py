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


@pytest.mark.asyncio
async def test_scan_failure_emits_error_event(monkeypatch):
    async def boom(*args, **kwargs):
        raise RuntimeError("scan exploded")
    monkeypatch.setattr(api, "scan", boom)
    text = await _get_text("/scan?target=example.com")
    events = _parse_sse(text)
    assert events[-1]["event"] == "error"
    assert "exploded" in events[-1]["data"]["detail"]
