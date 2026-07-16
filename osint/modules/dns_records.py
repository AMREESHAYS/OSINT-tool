import asyncio

import dns.resolver

from osint.core.models import Finding
from osint.modules.base import Context


def _resolve(domain: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            out[rtype] = [str(r) for r in dns.resolver.resolve(domain, rtype)]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                dns.exception.Timeout):
            out[rtype] = []
    return out


class DnsModule:
    name = "dns"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        records = await asyncio.to_thread(_resolve, target)
        findings = []
        for rtype, values in records.items():
            if values:
                findings.append(Finding(module=self.name, title=f"{rtype} records",
                                        detail="\n".join(values), data={rtype: values}))
        return findings
