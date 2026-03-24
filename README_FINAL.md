# 🕵️ OSINT Recon Engine (No API Required)

A professional **Open Source Intelligence (OSINT) reconnaissance tool** designed for cybersecurity learners, bug bounty hunters, and researchers.

This tool performs **real-world reconnaissance without relying on paid APIs**, using public data sources and system-level scanning.

---

# 🚀 Features

## 🔍 Input Intelligence
- Detects input type:
  - Domain
  - Username
  - Email (⚠️ Limited support)

## 🌐 Domain Recon
- DNS Records
- Subdomain Enumeration (crt.sh)
- Port Scanning (Nmap)
- Web Crawling
- Technology Detection
- Directory Bruteforce

## 👤 Username OSINT
- GitHub
- Reddit

## ⚡ Performance
- Async parallel execution

---

# ⚠️ EMAIL LIMITATION

Email OSINT is **not fully implemented** because:
- Real breach APIs are paid
- Tool is designed for no-API usage

---

# 🛠️ QUICK START (NO CONFUSION)

```bash
git clone https://github.com/AMREESHAYS/OSINT-tool
cd OSINT-tool/backend

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

sudo pacman -S nmap   # or apt install nmap

uvicorn main:app --reload
```

Open:
http://127.0.0.1:8000/docs

---

# ⚠️ COMMON ERRORS

## pip error (Arch Linux)
Use virtual environment

## main import error
Run inside backend folder

## no results for email
Email module not implemented yet

---

# ⚠️ DISCLAIMER

For educational use only.

---

# 📜 LICENSE
MIT

---

# 👨‍💻 AUTHOR
Amreesh Agrahari

---

🚀 Built for real OSINT without API keys.
