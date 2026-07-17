import os
from urllib.parse import quote

from osint.core.models import Finding, Severity
from osint.modules.base import Context

_PASSWORD_CLASSES = {"passwords", "password hints", "security questions and answers"}


class BreachModule:
    name = "breach"
    applies_to = {"email"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        key = os.environ.get("HIBP_API_KEY")
        if not key:
            return [Finding(module=self.name, title="Breach check skipped",
                            detail="Set HIBP_API_KEY to enable HaveIBeenPwned breach lookups.")]

        account = quote(target, safe="")
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{account}?truncateResponse=false"
        headers = {"hibp-api-key": key, "User-Agent": "osint-recon"}
        resp = await ctx.client.get(url, headers=headers)

        if resp.status_code == 404:
            return [Finding(module=self.name, title="No known breaches",
                            detail=f"{target} not found in HaveIBeenPwned.")]
        if resp.status_code != 200:
            return [Finding(module=self.name, title="Breach check failed",
                            detail=f"HaveIBeenPwned returned HTTP {resp.status_code}.")]

        findings = []
        for b in resp.json():
            classes = [c.lower() for c in b.get("DataClasses", [])]
            sev = Severity.HIGH if any(c in _PASSWORD_CLASSES for c in classes) else Severity.MEDIUM
            findings.append(Finding(module=self.name,
                                    title=f"Breach: {b.get('Name')} ({b.get('BreachDate')})",
                                    detail="Exposed: " + ", ".join(b.get("DataClasses", [])),
                                    severity=sev, data=b))
        return findings
