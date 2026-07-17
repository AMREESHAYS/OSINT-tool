from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    module: str
    title: str
    detail: str
    severity: Severity = Severity.INFO
    data: dict = Field(default_factory=dict)


class ModuleResult(BaseModel):
    module: str
    ok: bool
    error: str | None = None
    duration_ms: int
    findings: list[Finding] = Field(default_factory=list)


class ScanReport(BaseModel):
    target: str
    target_type: str
    started_at: datetime
    finished_at: datetime
    modules: list[ModuleResult] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: Severity = Severity.INFO
