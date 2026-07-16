from osint.core.models import Finding
from osint.modules.base import Context
from osint.modules.headers import _url


class TechModule:
    name = "tech"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        resp = await ctx.client.get(_url(target))
        findings = []
        for header in ("Server", "X-Powered-By", "X-AspNet-Version"):
            value = resp.headers.get(header)
            if value:
                findings.append(Finding(module=self.name, title=f"{header}: {value}",
                                        detail=value, data={header: value}))
        return findings
