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
from modules.js_endpoints import extract_js_endpoints
from modules.screenshot import take_screenshot
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
            asyncio.to_thread(analyze_headers, f"http://{query}"),
            asyncio.to_thread(extract_js_endpoints, f"http://{query}"),
            asyncio.to_thread(take_screenshot, f"http://{query}")
        )

        result.update({
            "dns": tasks[0],
            "subdomains": tasks[1],
            "ports": tasks[2],
            "links": tasks[3],
            "tech": tasks[4],
            "directories": tasks[5],
            "security": tasks[6],
            "js_files": tasks[7],
            "screenshot": tasks[8]
        })

        result["risk"] = evaluate(result)

    elif qtype == "username":
        result["profiles"] = check_username(query)

    elif qtype == "email":
        result["email"] = email_lookup(query)

    return result
