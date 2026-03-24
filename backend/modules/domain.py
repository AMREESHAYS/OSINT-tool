import dns.resolver
import requests

def get_dns(domain):
    data = {}
    try:
        data['A'] = [str(r) for r in dns.resolver.resolve(domain, 'A')]
    except:
        data['A'] = []
    return data


def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = set()
    try:
        res = requests.get(url, timeout=10)
        data = res.json()
        for entry in data:
            subs.update(entry['name_value'].split("\n"))
    except:
        pass
    return list(subs)
