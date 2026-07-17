import ipaddress
import re

_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")
_DOMAIN = re.compile(r"^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")
_USERNAME = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")


def classify(query: str) -> str:
    query = query.strip()
    if not query:
        return "unknown"
    try:
        ipaddress.ip_address(query)
        return "ip"
    except ValueError:
        pass
    if _EMAIL.match(query):
        return "email"
    if _DOMAIN.match(query):
        return "domain"
    if _USERNAME.match(query):
        return "username"
    return "unknown"
