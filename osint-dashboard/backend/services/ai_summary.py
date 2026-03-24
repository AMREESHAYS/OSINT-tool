"""Rule-based AI summary generator for OSINT investigation results."""

from __future__ import annotations

from typing import Any


def generate_summary(result: dict[str, Any]) -> str:
    """Generate a human-readable intelligence summary from OSINT findings.

    This is intentionally rule-based for now (no external LLM/API calls),
    while preserving a clean interface for future AI-provider integration.
    """

    query = str(result.get("query", "target")).strip()
    input_type = str(result.get("input_type", "")).strip().lower()
    details = result.get("details", {}) or {}

    summary_parts: list[str] = [f"Investigation summary for {query}."]

    # Email intelligence summary and risk signal.
    email_intel = details.get("email_intelligence", {})
    breaches = email_intel.get("breaches", []) if isinstance(email_intel, dict) else []
    if breaches:
        summary_parts.append(
            f"Email breach intelligence indicates {len(breaches)} known breach record(s), which elevates account takeover risk."
        )
    elif input_type == "email":
        summary_parts.append("No mock breach records were identified for this email target.")

    # Domain intelligence summary (DNS + WHOIS).
    domain_intel = details.get("domain_intelligence", {})
    dns_data = domain_intel.get("dns", {}) if isinstance(domain_intel, dict) else {}
    whois_data = domain_intel.get("whois", {}) if isinstance(domain_intel, dict) else {}
    if input_type == "domain" or dns_data or whois_data:
        a_count = len(dns_data.get("a", [])) if isinstance(dns_data.get("a", []), list) else 0
        mx_count = len(dns_data.get("mx", [])) if isinstance(dns_data.get("mx", []), list) else 0
        txt_count = len(dns_data.get("txt", [])) if isinstance(dns_data.get("txt", []), list) else 0
        whois_fields = len(whois_data.get("data", {})) if isinstance(whois_data.get("data", {}), dict) else 0
        summary_parts.append(
            f"Domain intelligence returned DNS records (A: {a_count}, MX: {mx_count}, TXT: {txt_count}) and {whois_fields} WHOIS field(s)."
        )

    # Username footprint summary.
    username_intel = details.get("username_intelligence", {})
    profiles = username_intel.get("profiles", []) if isinstance(username_intel, dict) else []
    if profiles:
        found_count = sum(1 for profile in profiles if profile.get("found") is True)
        summary_parts.append(
            f"Username footprint analysis found {found_count} profile(s) out of {len(profiles)} checked platforms."
        )
    elif input_type == "username":
        summary_parts.append("No platform footprint data was identified for this username target.")

    # Graph summary gives analysts quick context on relationship model size.
    graph = details.get("graph", {})
    if isinstance(graph, dict):
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        if isinstance(nodes, list) and isinstance(edges, list):
            summary_parts.append(
                f"Relationship graph contains {len(nodes)} node(s) and {len(edges)} edge(s)."
            )

    return " ".join(summary_parts)
