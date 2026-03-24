from fastapi import FastAPI
from services.orchestrator_async import run

app = FastAPI(title="OSINT Recon Engine")

@app.get("/")
def root():
    return {"message": "OSINT Tool Running"}

@app.post("/analyze")
async def analyze(data: dict):
    query = data.get("query")
    if not query:
        return {"error": "No query provided"}
    return await run(query)
