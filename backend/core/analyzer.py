import re

def classify(query: str):
    query = query.strip()

    if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', query):
        return "email"
    elif re.match(r'^(?!:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,}$', query):
        return "domain"
    elif re.match(r'^[a-zA-Z0-9._]{3,30}$', query):
        return "username"
    return "unknown"
