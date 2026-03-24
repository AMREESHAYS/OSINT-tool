def evaluate(data):
    score = 0

    if data.get("ports"):
        score += 2
    if data.get("directories"):
        score += 2
    if data.get("subdomains"):
        score += 1

    if score >= 4:
        level = "HIGH"
    elif score >= 2:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level}
