from osint.core.models import Finding, Severity
from osint.modules.base import Context


class SubdomainsModule:
    name = "subdomains"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        resp = await ctx.client.get(f"https://crt.sh/?q=%25.{target}&output=json")
        try:
            entries = resp.json()
        except ValueError:
            # crt.sh frequently rate-limits or returns a non-JSON body; report it
            # honestly instead of failing the whole module.
            return [Finding(module=self.name, title="crt.sh unavailable",
                            detail="crt.sh returned no parseable JSON (rate-limited or down).")]
        subs: set[str] = set()
        for entry in entries:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name:
                    subs.add(name)
        if not subs:
            return []
        sev = Severity.MEDIUM if len(subs) > 20 else Severity.INFO
        subs_sorted = sorted(subs)
        return [Finding(module=self.name, title=f"{len(subs_sorted)} subdomains (crt.sh)",
                        detail="\n".join(subs_sorted), severity=sev, data={"subdomains": subs_sorted})]
