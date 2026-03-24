import requests
from bs4 import BeautifulSoup

def crawl(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        return list(set(links))[:50]
    except:
        return []
