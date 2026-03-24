import requests

PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "Reddit": "https://reddit.com/user/{}"
}


def check_username(username):
    results = {}
    for name, url in PLATFORMS.items():
        try:
            res = requests.get(url.format(username), timeout=5)
            results[name] = res.status_code == 200
        except:
            results[name] = False
    return results
