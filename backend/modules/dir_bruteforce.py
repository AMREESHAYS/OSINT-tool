import requests

COMMON_PATHS = ["admin", "login", "dashboard", "api", "test"]

def brute_dirs(domain):
    found = []
    for path in COMMON_PATHS:
        url = f"http://{domain}/{path}"
        try:
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                found.append(url)
        except:
            pass
    return found
