"""Email intelligence module (mock breach detection for Step 3)."""

from __future__ import annotations

import re
from typing import Any

# Basic email validation for the mocked breach module.
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

# Simulated breach intelligence source keyed by email provider/domain.
MOCK_BREACH_DB: dict[str, list[dict[str, Any]]] = {
    "gmail.com": [
        {
            "name": "Collection #1",
            "date": "2019-01-07",
            "data_exposed": ["email", "password", "username"],
        },
        {
            "name": "LinkedIn 2016",
            "date": "2016-05-18",
            "data_exposed": ["email", "password"],
        },
    ],
    "yahoo.com": [
        {
            "name": "Yahoo 2013",
            "date": "2013-08-01",
            "data_exposed": ["email", "password", "security_questions"],
        }
    ],
}


def get_email_intelligence(email: str) -> dict[str, list[dict[str, Any]]]:
    """Return mocked breach intelligence for the supplied email address.

    Raises:
        ValueError: If the incoming email format is invalid.
    """

    normalized_email = email.strip().lower()
    if not EMAIL_PATTERN.match(normalized_email):
        raise ValueError("Invalid email supplied for breach lookup.")

    # Split email into local part and provider domain.
    _, email_domain = normalized_email.rsplit("@", 1)
    breaches = MOCK_BREACH_DB.get(email_domain, [])

    # Always return structured JSON with an explicit breaches list.
    return {"breaches": breaches}
