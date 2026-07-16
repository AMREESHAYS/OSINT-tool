# 🕵️ OSINT Recon Engine

A fast, async **Open Source Intelligence** reconnaissance tool — **no paid API required**.
Built for security learners, bug-bounty hunters, and researchers.

> ⚠️ Only scan targets you own or are explicitly authorized to test.

## Install

```bash
pipx install .        # or: uvx --from . osint
```

Docker (bundles nmap):

```bash
docker build -t osint . && docker run --rm osint scan example.com
```

## Usage

```bash
osint scan example.com                 # full domain recon, live panel
osint scan example.com --html report.html
osint scan user@example.com            # email recon
osint scan octocat                     # username footprint (~15 platforms)
osint scan 8.8.8.8 --only ports        # single module
osint modules                          # list modules
```

Flags: `--json/--md/--html <path>`, `--only`, `--skip`, `--no-nmap`,
`--concurrency`, `--timeout`, `-q/--quiet`.

## Web dashboard (Phase 2a)

A live dashboard that streams findings in as each module finishes, with a risk
gauge and a relationship graph. Two processes — the SSE API and the Vite dev server:

```bash
# 1. API (streams findings live over SSE)
osint serve                      # http://127.0.0.1:8000

# 2. Frontend
cd osint-dashboard/frontend
npm install && npm run dev       # http://localhost:5173
```

Open http://localhost:5173, enter a target, and watch modules stream in with a
live risk gauge and relationship graph. Set `VITE_API_BASE_URL` to point the
frontend at a non-default API origin.

## Modules

DNS · subdomains (crt.sh) · ports (nmap, optional) · security headers ·
tech fingerprint · crawler · directory bruteforce · JS endpoint/secret
extraction · username footprint · email/MX · heuristic risk scoring.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Roadmap

Phase 2: FastAPI SSE API + React dashboard, entity correlation graph, optional AI summary.
