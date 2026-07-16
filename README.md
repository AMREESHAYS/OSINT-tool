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
