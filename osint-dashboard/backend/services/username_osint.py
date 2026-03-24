"""Username intelligence module (mock platform footprint scanning)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Match Step 1 constraints for username classification.
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{3,32}$")

PLATFORMS: list[tuple[str, str]] = [
    ("GitHub", "https://github.com/{username}"),
    ("Twitter", "https://twitter.com/{username}"),
    ("Reddit", "https://www.reddit.com/user/{username}"),
    ("Instagram", "https://www.instagram.com/{username}"),
]


def _mock_found_status(platform: str, username: str) -> bool:
    """Deterministically simulate whether a profile exists.

    We use a stable hash so repeated requests return consistent results
    for the same (platform, username) pair without network calls.
    """

    digest = hashlib.sha256(f"{platform}:{username}".encode("utf-8")).hexdigest()
    return int(digest[-1], 16) % 2 == 0


def get_username_intelligence(username: str) -> dict[str, list[dict[str, Any]]]:
    """Return mocked username footprint across common social/dev platforms.

    Raises:
        ValueError: If username format is invalid.
    """

    normalized_username = username.strip().lower()
    if not USERNAME_PATTERN.match(normalized_username):
        raise ValueError("Invalid username supplied for username intelligence lookup.")

    profiles: list[dict[str, Any]] = []
    for platform, url_template in PLATFORMS:
        profile_url = url_template.format(username=normalized_username)
        profiles.append(
            {
                "platform": platform,
                "url": profile_url,
                "found": _mock_found_status(platform, normalized_username),
            }
        )

    return {"profiles": profiles}
