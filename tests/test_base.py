import httpx
from osint.core.settings import Settings
from osint.modules.base import Context


def test_settings_defaults():
    s = Settings()
    assert s.timeout == 10.0
    assert s.concurrency == 20
    assert s.nmap_enabled is True


def test_context_holds_client_and_settings():
    client = httpx.AsyncClient()
    ctx = Context(client=client, settings=Settings())
    assert ctx.client is client
    assert ctx.settings.concurrency == 20
