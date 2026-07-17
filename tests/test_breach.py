import httpx
import pytest
import respx

from osint.core.models import Severity
from osint.core.settings import Settings
from osint.modules.base import Context
from osint.modules.breach import BreachModule


@pytest.fixture
async def ctx():
    async with httpx.AsyncClient() as client:
        yield Context(client=client, settings=Settings())


@pytest.mark.asyncio
async def test_breach_no_key_skips(monkeypatch, ctx):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    findings = await BreachModule().run("a@example.com", ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "skipped" in findings[0].title.lower()


@respx.mock
@pytest.mark.asyncio
async def test_breach_none_found(monkeypatch, ctx):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    respx.get(url__regex=r"https://haveibeenpwned\.com/api/v3/breachedaccount/.*").mock(
        return_value=httpx.Response(404))
    findings = await BreachModule().run("a@example.com", ctx)
    assert "no known breaches" in findings[0].title.lower()


@respx.mock
@pytest.mark.asyncio
async def test_breach_password_is_high(monkeypatch, ctx):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    body = [{"Name": "Acme", "BreachDate": "2019-01-01", "DataClasses": ["Email addresses", "Passwords"]}]
    respx.get(url__regex=r"https://haveibeenpwned\.com/api/v3/breachedaccount/.*").mock(
        return_value=httpx.Response(200, json=body))
    findings = await BreachModule().run("a@example.com", ctx)
    high = [f for f in findings if f.severity is Severity.HIGH]
    assert high and "Acme" in high[0].title
