import asyncio
from importlib import resources

from osint.core.models import Finding, Severity
from osint.modules.base import Context
from osint.modules.headers import _url

_HIGH_RISK = (".git", ".env", ".svn", "backup", "phpinfo")


def _load_wordlist() -> list[str]:
    text = resources.files("osint.data").joinpath("wordlist.txt").read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


class DirBruteforceModule:
    name = "dir_bruteforce"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        base = _url(target)
        words = _load_wordlist()
        sem = asyncio.Semaphore(ctx.settings.concurrency)

        async def probe(path: str):
            async with sem:
                try:
                    resp = await ctx.client.get(f"{base}/{path}")
                except Exception:  # noqa: BLE001 - one dead path must not sink the sweep
                    return None
                if resp.status_code in (200, 301, 403):
                    return path, resp.status_code
                return None

        results = [r for r in await asyncio.gather(*(probe(w) for w in words)) if r]
        findings = []
        for path, code in results:
            sev = Severity.HIGH if any(h in path for h in _HIGH_RISK) else Severity.LOW
            findings.append(Finding(module=self.name, title=f"/{path} [{code}]",
                                    detail=f"{base}/{path} returned HTTP {code}", severity=sev))
        return findings
