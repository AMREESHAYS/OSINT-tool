from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import httpx

from osint.core.models import Finding
from osint.core.settings import Settings


@dataclass
class Context:
    client: httpx.AsyncClient
    settings: Settings


@runtime_checkable
class Module(Protocol):
    name: str
    applies_to: set[str]

    async def run(self, target: str, ctx: Context) -> list[Finding]:
        ...
