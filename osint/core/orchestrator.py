import asyncio
import time
from datetime import datetime, timezone

import httpx

from osint.core.classify import classify
from osint.core.models import ModuleResult, ScanReport
from osint.core.settings import Settings
from osint.modules.base import Context, Module
from osint.modules.risk import evaluate as _score


async def _run_one(module: Module, target: str, ctx: Context, sem, on_event) -> ModuleResult:
    async with sem:
        if on_event:
            on_event("module_started", module.name)
        start = time.perf_counter()
        try:
            findings = await asyncio.wait_for(module.run(target, ctx), timeout=ctx.settings.timeout * 3)
            result = ModuleResult(
                module=module.name, ok=True,
                duration_ms=int((time.perf_counter() - start) * 1000), findings=findings,
            )
        except (httpx.HTTPError, asyncio.TimeoutError, OSError, ValueError) as exc:
            result = ModuleResult(
                module=module.name, ok=False, error=str(exc) or exc.__class__.__name__,
                duration_ms=int((time.perf_counter() - start) * 1000), findings=[],
            )
        except Exception as exc:  # noqa: BLE001 - total module isolation: no module may abort the scan
            result = ModuleResult(
                module=module.name, ok=False, error=str(exc) or exc.__class__.__name__,
                duration_ms=int((time.perf_counter() - start) * 1000), findings=[],
            )
        if on_event:
            on_event("module_finished", module.name)
        return result


async def scan(target: str, settings: Settings, modules: list[Module], on_event=None) -> ScanReport:
    target_type = classify(target)
    started = datetime.now(timezone.utc)
    selected = [m for m in modules if target_type in m.applies_to]
    sem = asyncio.Semaphore(settings.concurrency)

    async with httpx.AsyncClient(
        timeout=settings.timeout,
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
    ) as client:
        ctx = Context(client=client, settings=settings)
        results = await asyncio.gather(*(_run_one(m, target, ctx, sem, on_event) for m in selected))

    all_findings = [f for r in results for f in r.findings]
    score, level = _score(all_findings)
    return ScanReport(
        target=target, target_type=target_type,
        started_at=started, finished_at=datetime.now(timezone.utc),
        modules=list(results), risk_score=score, risk_level=level,
    )
