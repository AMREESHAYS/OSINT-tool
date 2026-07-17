import httpx
import pytest
import respx

from osint.core.models import Severity
from osint.core.settings import Settings
from osint.modules.base import Context
from osint.modules.dir_bruteforce import DirBruteforceModule
from osint.modules.subdomains import SubdomainsModule


@pytest.fixture
async def ctx():
    async with httpx.AsyncClient(follow_redirects=False) as client:
        yield Context(client=client, settings=Settings())


@respx.mock
@pytest.mark.asyncio
async def test_dir_bruteforce_flags_exposed_git(ctx):
    # Everything 404 except .git/config which returns 200.
    # respx matches routes in registration order, so the specific route
    # must be registered before the catch-all regex.
    respx.get("https://example.com/.git/config").mock(return_value=httpx.Response(200, text="[core]"))
    respx.get(url__regex=r"https://example\.com/.*").mock(return_value=httpx.Response(404))
    findings = await DirBruteforceModule().run("example.com", ctx)
    hits = {f.title: f.severity for f in findings}
    assert any(".git" in t for t in hits)
    assert Severity.HIGH in hits.values()


@respx.mock
@pytest.mark.asyncio
async def test_subdomains_handles_non_json(ctx):
    # crt.sh often rate-limits and returns a non-JSON body; the module must
    # degrade to an INFO finding, not raise.
    respx.get(url__regex=r"https://crt\.sh/.*").mock(
        return_value=httpx.Response(200, text="rate limited, try again"))
    findings = await SubdomainsModule().run("example.com", ctx)
    assert len(findings) == 1
    assert "unavailable" in findings[0].title
    assert findings[0].severity is Severity.INFO


@respx.mock
@pytest.mark.asyncio
async def test_subdomains_from_crtsh(ctx):
    payload = [{"name_value": "a.example.com\nb.example.com"}, {"name_value": "a.example.com"}]
    respx.get(url__regex=r"https://crt\.sh/.*").mock(return_value=httpx.Response(200, json=payload))
    findings = await SubdomainsModule().run("example.com", ctx)
    joined = " ".join(f.detail for f in findings)
    assert "a.example.com" in joined and "b.example.com" in joined
