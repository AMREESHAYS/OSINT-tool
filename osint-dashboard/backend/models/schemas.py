from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class InputType(str, Enum):
    """Supported investigation input categories."""

    email = "email"
    domain = "domain"
    username = "username"


class AnalyzeRequest(BaseModel):
    """Incoming request payload for analysis."""

    query: str = Field(..., min_length=1, max_length=320, description="Email, domain, or username")


class AnalyzeResponse(BaseModel):
    """Step-1 response object that classifies the input."""

    request_id: str
    normalized_query: str
    input_type: InputType
    message: str
    next_steps: list[str]


class StoredResult(BaseModel):
    """Placeholder result model for future modules."""

    request_id: str
    query: str
    input_type: InputType
    status: str = "queued"
    details: Optional[dict] = None
