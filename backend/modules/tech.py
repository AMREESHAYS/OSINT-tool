import requests

def detect_tech(url):
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers
        return {
            "server": headers.get("Server"),
            "powered_by": headers.get("X-Powered-By")
        }
    except:
        return {}
