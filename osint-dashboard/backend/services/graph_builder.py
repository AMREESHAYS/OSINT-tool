"""Graph builder module for converting OSINT results into node/edge structures."""

from __future__ import annotations

from typing import Any


def build_graph(result: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    """Build a simple relationship graph from enriched result payloads.

    The function is intentionally lightweight and extendable so future
    OSINT entities (IP, org, documents, metadata) can be added without
    changing the output contract.
    """

    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    node_ids: set[str] = set()
    edge_ids: set[tuple[str, str]] = set()

    def add_node(node_id: str, node_type: str) -> None:
        if node_id not in node_ids:
            node_ids.add(node_id)
            nodes.append({"id": node_id, "type": node_type})

    def add_edge(source: str, target: str) -> None:
        edge_key = (source, target)
        if edge_key not in edge_ids:
            edge_ids.add(edge_key)
            edges.append({"source": source, "target": target})

    root_value = str(result.get("query", "")).strip().lower()
    root_type = str(result.get("input_type", "")).strip().lower()
    details = result.get("details", {}) or {}

    if root_value and root_type:
        add_node(root_value, root_type)

    if root_type == "email":
        email_intel = details.get("email_intelligence", {})
        breaches = email_intel.get("breaches", []) if isinstance(email_intel, dict) else []
        for breach in breaches:
            breach_name = str(breach.get("name", "")).strip()
            if not breach_name:
                continue
            breach_id = f"breach:{breach_name}"
            add_node(breach_id, "breach")
            add_edge(root_value, breach_id)

    elif root_type == "domain":
        domain_intel = details.get("domain_intelligence", {})
        dns_data = domain_intel.get("dns", {}) if isinstance(domain_intel, dict) else {}

        for record_type in ("a", "mx", "txt"):
            records = dns_data.get(record_type, [])
            if not isinstance(records, list):
                continue
            for record_value in records:
                record_text = str(record_value).strip()
                if not record_text:
                    continue
                dns_node_id = f"dns:{record_type}:{record_text}"
                add_node(dns_node_id, f"dns_{record_type}")
                add_edge(root_value, dns_node_id)

    elif root_type == "username":
        username_intel = details.get("username_intelligence", {})
        profiles = username_intel.get("profiles", []) if isinstance(username_intel, dict) else []
        for profile in profiles:
            platform = str(profile.get("platform", "")).strip()
            url = str(profile.get("url", "")).strip()
            if not platform or not url:
                continue
            profile_id = f"profile:{platform.lower()}:{url}"
            add_node(profile_id, "profile")
            add_edge(root_value, profile_id)

    return {"nodes": nodes, "edges": edges}
