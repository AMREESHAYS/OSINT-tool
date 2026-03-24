# OSINT Intelligence Dashboard

A full-stack OSINT investigation platform (React + FastAPI) for cybersecurity analysts.

## Current Progress

- ✅ Step 1 completed: Backend setup and Input Analyzer.
- ✅ Step 2 completed: Domain Intelligence (DNS A/MX/TXT + WHOIS).
- ✅ Step 3 completed: Email OSINT (mock breach intelligence).
- ✅ Step 4 completed: Username OSINT (mock platform footprint).
- ✅ Step 5 completed: Graph builder (nodes/edges for visualization).
- ✅ Step 6 completed: Frontend dashboard (React + Tailwind + Force Graph).
- ✅ Step 7 completed: Rule-based AI summary module.
- ⏳ Next: Metadata extraction.

## Quick Start (Backend)

```bash
cd osint-dashboard/backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/docs` for Swagger UI.

## Quick Start (Frontend)

```bash
cd osint-dashboard/frontend
npm install
npm run dev
```

Frontend runs by default on `http://127.0.0.1:5173`.

## Ethical Disclaimer

This tool is for educational and ethical OSINT purposes only.
