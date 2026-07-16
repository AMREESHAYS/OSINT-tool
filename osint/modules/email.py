import asyncio

import dns.resolver

from osint.core.models import Finding, Severity
from osint.modules.base import Context


class EmailModule:
    name = "email"
    applies_to = {"email"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        domain = target.rsplit("@", 1)[-1]
        findings = [Finding(module=self.name, title="Email domain",
                            detail=domain, data={"domain": domain})]

        def _mx():
            try:
                return [str(r.exchange) for r in dns.resolver.resolve(domain, "MX")]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                return []

        mx = await asyncio.to_thread(_mx)
        if mx:
            findings.append(Finding(module=self.name, title=f"{len(mx)} MX records",
                                    detail="\n".join(mx), data={"mx": mx}))
        else:
            findings.append(Finding(module=self.name, title="No MX records",
                                    detail=f"{domain} has no MX records (may not receive mail).",
                                    severity=Severity.LOW))
        return findings
