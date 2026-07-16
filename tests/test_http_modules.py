import httpx
import pytest
import respx

from osint.core.settings import Settings
from osint.modules.base import Context
from osint.modules.headers import HeadersModule
from osint.modules.tech import TechModule
from osint.modules.crawler import CrawlerModule
from osint.modules.js_endpoints import JsEndpointsModule


@pytest.fixture
async def ctx():
    async with httpx.AsyncClient(follow_redirects=True) as client:
        yield Context(client=client, settings=Settings())


@respx.mock
@pytest.mark.asyncio
async def test_headers_flags_missing_csp(ctx):
    respx.get("https://example.com").mock(return_value=httpx.Response(200, headers={"Server": "nginx"}))
    findings = await HeadersModule().run("example.com", ctx)
    titles = [f.title for f in findings]
    assert any("Content-Security-Policy" in t for t in titles)


@respx.mock
@pytest.mark.asyncio
async def test_tech_reports_server(ctx):
    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, headers={"Server": "nginx", "X-Powered-By": "PHP/8"}))
    findings = await TechModule().run("example.com", ctx)
    joined = " ".join(f.detail for f in findings)
    assert "nginx" in joined and "PHP/8" in joined


@respx.mock
@pytest.mark.asyncio
async def test_crawler_extracts_links(ctx):
    html = '<a href="/about">a</a><a href="https://example.com/x">b</a>'
    respx.get("https://example.com").mock(return_value=httpx.Response(200, text=html))
    findings = await CrawlerModule().run("example.com", ctx)
    assert len(findings) >= 1


@respx.mock
@pytest.mark.asyncio
async def test_js_endpoints_flags_secret(ctx):
    html = '<script src="/app.js"></script>'
    js = 'const api_key = "abc123"; fetch("/api/v1/users")'
    # Register the more specific route first: respx's "https://example.com" pattern
    # has no Path constraint (matches any path on that host), so it must not be
    # registered ahead of the /app.js route or it will shadow it (first match wins).
    respx.get("https://example.com/app.js").mock(return_value=httpx.Response(200, text=js))
    respx.get("https://example.com").mock(return_value=httpx.Response(200, text=html))
    findings = await JsEndpointsModule().run("example.com", ctx)
    severities = [f.severity for f in findings]
    from osint.core.models import Severity
    assert Severity.HIGH in severities
