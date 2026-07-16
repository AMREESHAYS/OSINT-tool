import asyncio
import re

from osint.core.models import Finding, Severity
from osint.modules.base import Context

_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.M)


class PortsModule:
    name = "ports"
    applies_to = {"domain", "ip"}

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        if not ctx.settings.nmap_enabled:
            return [Finding(module=self.name, title="Port scan skipped",
                            detail="Port scanning disabled via --no-nmap.")]
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-F", target,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
        except FileNotFoundError:
            return [Finding(module=self.name, title="nmap not installed",
                            detail="nmap binary not found on PATH; port scan skipped.")]
        findings = []
        for port, service in _PORT_RE.findall(stdout.decode(errors="ignore")):
            findings.append(Finding(module=self.name, title=f"Port {port}/tcp open ({service})",
                                    detail=f"{service} on {port}/tcp", severity=Severity.LOW,
                                    data={"port": int(port), "service": service}))
        return findings
