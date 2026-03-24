# 🕵️ OSINT Recon Engine (No API Required)

A powerful **Open Source Intelligence (OSINT) reconnaissance tool** built for cybersecurity learners, bug bounty hunters, and researchers. This tool performs real-world reconnaissance without relying on paid APIs.

---

# 🚀 Features

## 🔍 Input Intelligence
- Detects input type:
  - Domain
  - Username
  - Email (basic handling)

## 🌐 Domain Recon
- DNS Records (A)
- Subdomain Enumeration (crt.sh)
- Port Scanning (Nmap)
- Web Crawling (link extraction)
- Technology Detection (headers)
- Directory Bruteforce (common paths)

## 👤 Username OSINT
- Checks username presence on:
  - GitHub
  - Reddit

## ⚡ Performance
- Parallel scanning using `asyncio`
- Fast recon pipeline

## 📊 Visualization Ready
- Structured output for graph-based visualization

---

# 🧠 How It Works

```
User Input
   ↓
Analyzer (detect type)
   ↓
Recon Modules
   ├── DNS
   ├── Subdomains
   ├── Ports (nmap)
   ├── Crawling
   ├── Tech Detection
   └── Directory Bruteforce
   ↓
Data Aggregation (Async Engine)
   ↓
Structured Output (JSON)
```

---

# 🛠️ Requirements

## System Requirements
- Python 3.10+
- Linux (recommended)

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Install Nmap (Required)

```bash
sudo pacman -S nmap   # Arch Linux
sudo apt install nmap # Ubuntu/Debian
```

---

# ⚙️ Setup & Usage

## Run Backend

```bash
cd backend
uvicorn main:app --reload
```

## API Endpoint

### POST /analyze

```json
{
  "query": "example.com"
}
```

---

# 📊 Example Output

```json
{
  "type": "domain",
  "dns": {...},
  "subdomains": [...],
  "ports": "...",
  "links": [...],
  "tech": {...},
  "directories": [...]
}
```

---

# ⚠️ Disclaimer

This tool is intended **for educational and ethical purposes only**.

Do NOT use this tool for:
- Unauthorized scanning
- Privacy invasion
- Illegal activities

The developer is not responsible for misuse.

---

# 🔐 Security Note

- No API keys required
- Uses only public and open data
- Fully offline recon capability (except crawling)

---

# 💡 Future Improvements

- Vulnerability detection
- Screenshot capture
- Advanced crawling
- Risk scoring system

---

# 👨‍💻 Author

**Amreesh Agrahari**

- Cybersecurity Enthusiast
- Bug Bounty Learner
- Full-Stack Developer

---

# 📜 License

MIT License

---

# ⭐ Support

If you like this project:
- Star ⭐ the repo
- Share it with others

---

🚀 Built for learning, hacking, and exploring the internet safely.
