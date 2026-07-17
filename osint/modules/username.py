import asyncio

from osint.core.models import Finding, Severity
from osint.modules.base import Context

PLATFORMS = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Reddit": "https://www.reddit.com/user/{u}",
    "Instagram": "https://www.instagram.com/{u}",
    "X": "https://x.com/{u}",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "Medium": "https://medium.com/@{u}",
    "Keybase": "https://keybase.io/{u}",
    "Telegram": "https://t.me/{u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "HackerNews": "https://news.ycombinator.com/user?id={u}",
    "DevTo": "https://dev.to/{u}",
    "Pastebin": "https://pastebin.com/u/{u}",
    "YouTube": "https://www.youtube.com/@{u}",
}


class UsernameModule:
    name = "username"
    applies_to = {"username"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        sem = asyncio.Semaphore(ctx.settings.concurrency)

        async def check(platform: str, url: str):
            async with sem:
                try:
                    resp = await ctx.client.get(url.format(u=target))
                except Exception:  # noqa: BLE001 - one dead platform must not sink the sweep
                    return None
                return platform if resp.status_code == 200 else None

        hits = [r for r in await asyncio.gather(
            *(check(p, u) for p, u in PLATFORMS.items())) if r]
        return [Finding(module=self.name, title=f"Found on {p}",
                        detail=PLATFORMS[p].format(u=target), severity=Severity.INFO) for p in hits]
