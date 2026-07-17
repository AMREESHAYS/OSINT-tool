from osint.core.models import Finding, Severity
from osint.modules.base import Context

_SECURITY_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", Severity.MEDIUM),
    "x-frame-options": ("X-Frame-Options", Severity.LOW),
    "strict-transport-security": ("HSTS (Strict-Transport-Security)", Severity.MEDIUM),
    "x-content-type-options": ("X-Content-Type-Options", Severity.LOW),
}


def _url(target: str) -> str:
    return target if target.startswith(("http://", "https://")) else f"https://{target}"


class HeadersModule:
    name = "headers"
    applies_to = {"domain"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        resp = await ctx.client.get(_url(target))
        present = {k.lower() for k in resp.headers}
        findings = []
        for key, (label, sev) in _SECURITY_HEADERS.items():
            if key not in present:
                findings.append(Finding(module=self.name, title=f"Missing {label}",
                                        detail=f"Response for {target} does not set {label}.", severity=sev))
        return findings
