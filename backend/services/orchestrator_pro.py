from core.analyzer import classify
from modules.domain import get_dns, get_subdomains
from modules.scan import scan_ports
from modules.username import check_username
from modules.crawler import crawl
from modules.tech import detect_tech
from modules.dir_bruteforce import brute_dirs
from modules.email import email_lookup
from modules.security import analyze_headers
from modules.risk_engine import evaluate
import asyncio

async def run(query):
    qtype = classify(query)
    result = {"type": qtype}

    if qtype == "domain":
        tasks = await asyncio.gather(
            asyncio.to_thread(get_dns, query),
            asyncio.to_thread(get_subdomains, query),
            asyncio.to_thread(scan_ports, query),
            asyncio.to_thread(crawl, f"http://{query}"),
            asyncio.to_thread(detect_tech, f"http://{query}"),
            asyncio.to_thread(brute_dirs, query),
            asyncio.to_thread(analyze_headers, f"http://{query}")
        )

        result["dns"] = tasks[0]
        result["subdomains"] = tasks[1]
        result["ports"] = tasks[2]
        result["links"] = tasks[3]
        result["tech"] = tasks[4]
        result["directories"] = tasks[5]
        result["security"] = tasks[6]

        result["risk"] = evaluate(result)

    elif qtype == "username":
        result["profiles"] = check_username(query)

    elif qtype == "email":
        result["email"] = email_lookup(query)

    return result
