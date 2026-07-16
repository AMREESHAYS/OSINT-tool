from datetime import datetime, timezone

from osint.core.models import Finding, ModuleResult, ScanReport, Severity
from osint.graph import build_graph


def _report(findings_by_module):
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)
    modules = [
        ModuleResult(module=m, ok=True, duration_ms=1, findings=fs)
        for m, fs in findings_by_module.items()
    ]
    return ScanReport(target="example.com", target_type="domain",
                      started_at=now, finished_at=now, modules=modules,
                      risk_score=0, risk_level=Severity.INFO)


def test_graph_has_target_root_and_typed_nodes():
    report = _report({
        "subdomains": [Finding(module="subdomains", title="2 subdomains", detail="",
                               data={"subdomains": ["a.example.com", "b.example.com"]})],
        "tech": [Finding(module="tech", title="Server: nginx", detail="nginx", data={"Server": "nginx"})],
        "ports": [Finding(module="ports", title="Port 443/tcp open", detail="",
                          data={"port": 443, "service": "https"})],
    })
    graph = build_graph(report)
    nodes = {(n["id"], n["type"]) for n in graph["nodes"]}
    assert ("example.com", "target") in nodes
    assert ("a.example.com", "subdomain") in nodes
    assert ("b.example.com", "subdomain") in nodes
    assert ("443/tcp", "port") in nodes
    assert any(t == "tech" for _, t in nodes)
    # every edge originates from the target root
    assert all(e["source"] == "example.com" for e in graph["edges"])
    # a subdomain edge exists
    assert {"source": "example.com", "target": "a.example.com"} in graph["edges"]


def test_graph_dedupes_nodes():
    report = _report({
        "tech": [Finding(module="tech", title="Server: nginx", detail="nginx", data={"Server": "nginx"}),
                 Finding(module="tech", title="Server: nginx", detail="nginx", data={"Server": "nginx"})],
    })
    graph = build_graph(report)
    ids = [n["id"] for n in graph["nodes"]]
    assert len(ids) == len(set(ids))
