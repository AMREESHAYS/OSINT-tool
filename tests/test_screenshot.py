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
