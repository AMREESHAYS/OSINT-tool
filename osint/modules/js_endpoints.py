import re

from selectolax.parser import HTMLParser

from osint.core.models import Finding, Severity
from osint.modules.base import Context
from osint.modules.headers import _url

_ENDPOINT_RE = re.compile(r"[\"'](/[a-zA-Z0-9_./-]{2,})[\"']")
_SECRET_RE = re.compile(r"(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']{6,}", re.I)


class JsEndpointsModule:
    name = "js_endpoints"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        base = _url(target)
        resp = await ctx.client.get(base)
        tree = HTMLParser(resp.text)
        js_urls = [s.attributes.get("src") for s in tree.css("script[src]") if s.attributes.get("src")]
        findings = []
        for src in js_urls[:10]:
            url = src if src.startswith("http") else f"{base}{src if src.startswith('/') else '/' + src}"
            try:
                js = (await ctx.client.get(url)).text
            except Exception:  # noqa: BLE001 - one bad script must not sink the module
                continue
            endpoints = sorted(set(_ENDPOINT_RE.findall(js)))[:30]
            if endpoints:
                findings.append(Finding(module=self.name, title=f"{len(endpoints)} endpoints in {src}",
                                        detail="\n".join(endpoints), data={"endpoints": endpoints}))
            if _SECRET_RE.search(js):
                findings.append(Finding(module=self.name, title=f"Possible secret in {src}",
                                        detail="A hardcoded credential pattern was found in JavaScript.",
                                        severity=Severity.HIGH))
        return findings
