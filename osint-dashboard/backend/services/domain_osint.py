"""Domain intelligence module for DNS and WHOIS enrichment."""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

import dns.exception
import dns.resolver
import whois

# Domain validation is intentionally strict for production-like hygiene.
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)


def _normalize_whois_value(value: Any) -> Any:
    """Convert WHOIS values into JSON-serializable primitives."""

    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, list):
        return [_normalize_whois_value(item) for item in value]
    return value


def _resolve_dns_records(domain: str, record_type: str) -> list[str]:
    """Resolve a specific DNS record type and return string values."""

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    answers = resolver.resolve(domain, record_type)
    return [answer.to_text().strip('"') for answer in answers]


def get_domain_intelligence(domain: str) -> dict[str, dict[str, Any]]:
    """Fetch domain intelligence including DNS and WHOIS.

    Raises:
        ValueError: If `domain` does not pass basic validation.
    """

    normalized_domain = domain.strip().lower()
    if not DOMAIN_PATTERN.match(normalized_domain):
        raise ValueError("Invalid domain supplied for domain intelligence lookup.")

    dns_section: dict[str, Any] = {"a": [], "mx": [], "txt": [], "errors": {}}
    whois_section: dict[str, Any] = {"data": {}, "errors": {}}

    # Resolve record types independently to avoid failing the entire DNS section.
    for label, record_type in (("a", "A"), ("mx", "MX"), ("txt", "TXT")):
        try:
            dns_section[label] = _resolve_dns_records(normalized_domain, record_type)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as exc:
            dns_section["errors"][label] = str(exc)
        except dns.exception.DNSException as exc:
            dns_section["errors"][label] = f"DNS lookup failed: {exc}"

    try:
        raw_whois = whois.whois(normalized_domain)
        # Some whois libs return custom dict-like objects; cast safely.
        whois_data = dict(raw_whois) if raw_whois else {}
        whois_section["data"] = {
            key: _normalize_whois_value(value) for key, value in whois_data.items()
        }
    except Exception as exc:  # noqa: BLE001 - defensive boundary around third-party whois parser.
        whois_section["errors"]["lookup"] = f"WHOIS lookup failed: {exc}"

    return {"dns": dns_section, "whois": whois_section}
