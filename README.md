# 🕵️ OSINT Intelligence Dashboard

> A full-stack OSINT (Open Source Intelligence) investigation platform built for cybersecurity analysts, bug bounty hunters, and researchers.

---

## 🚀 Overview

The **OSINT Intelligence Dashboard** is a modern cybersecurity tool that collects, analyzes, and visualizes intelligence data from various sources such as emails, domains, and usernames.

It simulates real-world OSINT workflows used in:
- 🔐 Cybersecurity investigations  
- 🕵️ Threat intelligence  
- 🐞 Bug bounty reconnaissance  
- 🔎 Digital footprint analysis  

---

## ✨ Features

### 🔍 Input Intelligence
- Detects and classifies:
  - Email
  - Domain
  - Username

---

### 🌐 Domain Intelligence
- DNS Records:
  - A, MX, TXT
- WHOIS Lookup
- Structured output for analysis

---

### 📧 Email Intelligence
- Breach detection (mock system)
- Data exposure insights
- Risk indication

---

### 👤 Username OSINT
- Searches across platforms:
  - GitHub
  - Twitter
  - Reddit
  - Instagram
- Profile discovery simulation

---

### 📊 Graph Visualization (🔥 Key Feature)
- Interactive relationship graph
- Node-edge intelligence mapping
- Inspired by real OSINT tools like Maltego

---

### 🧠 AI Summary Engine
- Generates human-readable intelligence reports
- Summarizes:
  - Risk signals
  - Domain data
  - User footprint
  - Graph insights

---

## 🧱 Architecture

```text
User Input
   ↓
Input Analyzer
   ↓
OSINT Modules
 ├── Domain Intelligence
 ├── Email Intelligence
 └── Username Intelligence
   ↓
Graph Builder (Nodes & Relationships)
   ↓
AI Summary Engine
   ↓
API Response
   ↓
Frontend Dashboard (Visualization)
```
---

###🛠️ Tech Stack Backend

⚡ FastAPI (Python)
🧠 Modular OSINT services
📡 REST API architecture
Frontend
⚛️ React + TypeScript
🎨 Tailwind CSS
📊 react-force-graph

🔹 Input Dashboard
🔹 Results Panel
🔹 Graph Visualization
🌐 Live Demo

🚧 Coming Soon (after deployment)
---

###⚙️ Installation
🔧 Backend
```
cd osint-dashboard/backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```
👉 Open: http://127.0.0.1:8000/docs

💻 Frontend
```
cd osint-dashboard/frontend
npm install
npm run dev
```
👉 Open: http://127.0.0.1:5173

---

###📡 API Endpoints
POST /analyze

Analyze input (email/domain/username)
```
{
  "query": "example@gmail.com"
}
GET /results/{id}
```

Fetch processed intelligence

---

###🧠 Example Output

Breach Intelligence
DNS + WHOIS Data
Username Profiles
Graph Relationships
AI Summary

##⚠️ Ethical Disclaimer

**This tool is intended for educational and ethical OSINT purposes only.**
Do not use this tool for:
Unauthorized surveillance
Privacy violations
Illegal activities

---

###🚀 Future Improvements
🔗 Real API integrations (HaveIBeenPwned, Shodan, etc.)
👤 User authentication system
📄 Export reports (PDF/JSON)
📊 Risk scoring engine
🗄️ Database integration
🌐 Deployment & scaling

---

##💼 Author
**Amreesh Agrahari**

💻 Cybersecurity Enthusiast
🛡️ Bug Bounty Learner
⚙️ Full-Stack Developer
🤝 Contribution

Contributions are welcome!
---

###If you’d like to improve this project:

Fork the repo
Create a new branch
Submit a pull request
⭐ Support

If you found this project useful:

👉 Give it a ⭐ on GitHub
👉 Share it with others
---

###💡 Note

This project is designed to demonstrate:

System design skills
Cybersecurity knowledge
Full-stack development
OSINT workflows

🚀 Built with passion for cybersecurity and intelligent systems.
