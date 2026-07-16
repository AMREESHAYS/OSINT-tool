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


class KeyErrorModule:
    name = "keyerror"
    applies_to = {"domain"}

    async def run(self, target, ctx):
        raise KeyError("unexpected bug")


@pytest.mark.asyncio
async def test_unexpected_exception_is_isolated():
    report = await scan("example.com", Settings(), [GoodModule(), KeyErrorModule()])
    by_name = {m.module: m for m in report.modules}
    assert by_name["good"].ok is True
    assert by_name["keyerror"].ok is False
    assert "unexpected bug" in by_name["keyerror"].error
