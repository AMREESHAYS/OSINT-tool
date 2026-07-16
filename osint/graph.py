from osint.core.models import ScanReport


def build_graph(report: ScanReport) -> dict:
    root = report.target
    nodes: dict[str, str] = {root: "target"}  # id -> type
    edges: list[dict] = []

    def link(node_id: str, node_type: str):
        if node_id and node_id not in nodes:
            nodes[node_id] = node_type
        if node_id:
            edge = {"source": root, "target": node_id}
            if edge not in edges:
                edges.append(edge)

    for mod in report.modules:
        for f in mod.findings:
            if mod.module == "dns":
                for ip in f.data.get("A", [])[:10]:
                    link(ip, "ip")
            elif mod.module == "subdomains":
                for sub in f.data.get("subdomains", [])[:50]:
                    link(sub, "subdomain")
            elif mod.module == "tech":
                link(f.detail or f.title, "tech")
            elif mod.module == "ports":
                port = f.data.get("port")
                if port is not None:
                    link(f"{port}/tcp", "port")
            elif mod.module == "js_endpoints":
                for ep in f.data.get("endpoints", [])[:40]:
                    link(ep, "endpoint")
            elif mod.module == "username":
                # username findings are titled "Found on <platform>"
                link(f.title.replace("Found on ", ""), "profile")

    return {"nodes": [{"id": i, "type": t} for i, t in nodes.items()], "edges": edges}
