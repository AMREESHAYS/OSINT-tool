from selectolax.parser import HTMLParser

from osint.core.models import Finding
from osint.modules.base import Context
from osint.modules.headers import _url


class CrawlerModule:
    name = "crawler"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        resp = await ctx.client.get(_url(target))
        tree = HTMLParser(resp.text)
        links = {a.attributes.get("href") for a in tree.css("a[href]")}
        links.discard(None)
        links = sorted(links)[:50]
        if not links:
            return []
        return [Finding(module=self.name, title=f"{len(links)} links found",
                        detail="\n".join(links), data={"links": links})]
