import requests

def analyze_headers(url):
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers

        return {
            "server": headers.get("Server"),
            "security_headers": {
                "x_frame_options": headers.get("X-Frame-Options"),
                "content_security_policy": headers.get("Content-Security-Policy"),
                "x_xss_protection": headers.get("X-XSS-Protection")
            }
        }
    except:
        return {"error": "request failed"}
