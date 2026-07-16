from osint.modules.base import Module
from osint.modules.crawler import CrawlerModule
from osint.modules.dir_bruteforce import DirBruteforceModule
from osint.modules.dns_records import DnsModule
from osint.modules.email import EmailModule
from osint.modules.headers import HeadersModule
from osint.modules.js_endpoints import JsEndpointsModule
from osint.modules.ports import PortsModule
from osint.modules.subdomains import SubdomainsModule
from osint.modules.tech import TechModule
from osint.modules.username import UsernameModule


def all_modules() -> list[Module]:
    return [
        DnsModule(), SubdomainsModule(), HeadersModule(), TechModule(),
        CrawlerModule(), JsEndpointsModule(), DirBruteforceModule(),
        PortsModule(), UsernameModule(), EmailModule(),
    ]
