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
    respx.get("https://github.com/octocat").mock(return_value=httpx.Response(200))
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))
    findings = await UsernameModule().run("octocat", ctx)
    joined = " ".join(f.title for f in findings)
    assert "GitHub" in joined


@pytest.mark.asyncio
async def test_email_extracts_domain(ctx, monkeypatch):
    # Fake the MX lookup so the test never touches the network (constraint:
    # no live DNS in the suite).
    fake_mx = type("R", (), {"exchange": "mail.example.com."})()
    monkeypatch.setattr("dns.resolver.resolve", lambda domain, rtype: [fake_mx])
    findings = await EmailModule().run("john@example.com", ctx)
    joined = " ".join(f.detail for f in findings)
    assert "example.com" in joined
    assert "mail.example.com." in joined


def test_registry_includes_2b_modules():
    from osint.modules.registry import all_modules
    names = {m.name for m in all_modules()}
    assert {"screenshot", "breach"} <= names
