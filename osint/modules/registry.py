from osint.modules.base import Module
from osint.modules.crawler import CrawlerModule
from osint.modules.headers import HeadersModule
from osint.modules.js_endpoints import JsEndpointsModule
from osint.modules.tech import TechModule


def all_modules() -> list[Module]:
    return [HeadersModule(), TechModule(), CrawlerModule(), JsEndpointsModule()]
