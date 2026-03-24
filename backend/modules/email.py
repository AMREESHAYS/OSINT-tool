def email_lookup(email):
    domain = email.split("@")[-1] if "@" in email else "unknown"
    return {
        "email": email,
        "domain": domain,
        "search": "https://www.google.com/search?q=" + email,
        "note": "Basic OSINT without API"
    }
