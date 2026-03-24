"""Input analyzer service for classifying user-provided investigation targets."""

from __future__ import annotations

import re
from uuid import uuid4

from models.schemas import AnalyzeResponse, InputType, StoredResult

# Practical regexes for a first-pass classification. These can be hardened later.
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{3,32}$")


class InputAnalyzer:
    """Classify and normalize analysis input values."""

    @staticmethod
    def classify(raw_query: str) -> AnalyzeResponse:
        normalized = raw_query.strip().lower()
        if not normalized:
            raise ValueError("Query cannot be empty.")

        if EMAIL_PATTERN.match(normalized):
            input_type = InputType.email
        elif DOMAIN_PATTERN.match(normalized):
            input_type = InputType.domain
        elif USERNAME_PATTERN.match(normalized):
            input_type = InputType.username
        else:
            raise ValueError(
                "Input is not a valid email, domain, or username in the current validation rules."
            )

        request_id = str(uuid4())
        return AnalyzeResponse(
            request_id=request_id,
            normalized_query=normalized,
            input_type=input_type,
            message="Input accepted and classified successfully.",
            next_steps=[
                "domain_intelligence",
                "email_osint",
                "username_footprint",
                "metadata_extraction",
                "graph_builder",
            ],
        )


class InMemoryResultStore:
    """Temporary store for step-by-step development.

    In production, replace with PostgreSQL/Redis.
    """

    def __init__(self) -> None:
        self._results: dict[str, StoredResult] = {}

    def save(self, result: StoredResult) -> None:
        self._results[result.request_id] = result

    def get(self, request_id: str) -> StoredResult | None:
        return self._results.get(request_id)
