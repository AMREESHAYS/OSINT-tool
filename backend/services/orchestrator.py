from core.analyzer import classify
from modules.domain import get_dns, get_subdomains
from modules.scan import scan_ports
from modules.username import check_username


def run(query):
    qtype = classify(query)
    result = {"type": qtype}

    if qtype == "domain":
        result["dns"] = get_dns(query)
        result["subdomains"] = get_subdomains(query)
        result["ports"] = scan_ports(query)

    elif qtype == "username":
        result["profiles"] = check_username(query)

    return result
