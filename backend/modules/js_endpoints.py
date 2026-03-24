import requests
import re

def extract_js_endpoints(url):
    try:
        res = requests.get(url, timeout=5)
        js_files = re.findall(r"src=\"(.*?\.js)\"", res.text)
        return js_files
    except:
        return []
