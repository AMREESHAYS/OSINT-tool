import base64

from osint.core.models import Finding
from osint.modules.base import Context


async def _capture(url: str, timeout: float) -> bytes:
    # Lazy-import so Playwright stays an optional dependency.
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        try:
            page = await browser.new_page(viewport={"width": 1280, "height": 800})
            await page.goto(url, timeout=int(timeout * 1000))
            return await page.screenshot(type="png")
        finally:
            await browser.close()


class ScreenshotModule:
    name = "screenshot"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        url = f"https://{target}"
        try:
            png = await _capture(url, ctx.settings.timeout)
        except Exception:  # noqa: BLE001 - Playwright/browser absent or capture failed → degrade, never raise
            return [Finding(module=self.name, title="Screenshots unavailable",
                            detail="Capture failed or Playwright not installed. "
                                   "Enable with: pip install 'osint[screenshots]' && playwright install chromium.")]
        uri = "data:image/png;base64," + base64.b64encode(png).decode("ascii")
        return [Finding(module=self.name, title="Homepage screenshot",
                        detail="Homepage captured.", data={"image": uri})]
