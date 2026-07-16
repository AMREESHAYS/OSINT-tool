from pydantic import BaseModel


class Settings(BaseModel):
    timeout: float = 10.0
    concurrency: int = 20
    user_agent: str = "osint-recon/1.0"
    nmap_enabled: bool = True
