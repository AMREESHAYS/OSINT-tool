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

### Optional enrichments (Phase 2b)

All degrade gracefully; none are required, and the default path stays paid-API-free.

```bash
pip install 'osint[ai,screenshots]'   # optional extras
playwright install chromium           # for screenshots
export ANTHROPIC_API_KEY=...           # AI summary via Claude (else heuristic)
export HIBP_API_KEY=...                # email breach lookups (else skipped)
```

- **AI summary** — `osint scan <t> --ai` (or `?ai=true` on the API); a free heuristic narrative without a key.
- **Screenshots** — homepage capture on domain scans; an "unavailable" notice if Playwright isn't installed.
- **Breaches** — HaveIBeenPwned on email scans; a "skipped" notice without a key.

## Modules

DNS · subdomains (crt.sh) · ports (nmap, optional) · security headers ·
tech fingerprint · crawler · directory bruteforce · JS endpoint/secret
extraction · username footprint · email/MX · screenshots (optional) ·
breach lookups (optional) · heuristic risk scoring.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Roadmap

Shipped: Phase 1 (async core + CLI + reports), Phase 2a (SSE API + live dashboard + graph),
Phase 2b (AI summary, screenshots, breach lookups).
