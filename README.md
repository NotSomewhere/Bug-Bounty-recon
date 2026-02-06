# 🚀 Bug Bounty Recon Automation Suite

🛠️ **Automated reconnaissance pipeline** for **AUTHORIZED security testing** and bug bounty programs.

This tool automates real-world recon workflows by chaining **industry-standard tools**
into a single, repeatable pipeline — perfect for **VPS**, **CI**, and **scheduled recon**.

---

## ✨ Features

### 🔍 Passive Recon
- Subdomain enumeration using:
  - subfinder
  - assetfinder
  - crt.sh (certificate transparency)

### 🌐 Alive Host Detection
- httpx (preferred)
- Python requests fallback if httpx is unavailable

### 🧠 Smart Page Classification
- Detects:
  - 🔐 login pages
  - 🛡️ admin panels
  - 📊 dashboards
  - 📚 documentation
  - 🔗 APIs

### 🔓 Port Scanning
- ⚡ Nmap quick scan (Top 1000 TCP ports)
- 🎯 Automatic detection of interesting ports
- 🔬 Targeted full Nmap scan (-sV -p-) only where it matters

### 🧪 Vulnerability Scanning
- Nuclei with severity filtering:
  - low / medium / high / critical
- Intelligent target generation from alive hosts and ports

### 🧬 Technology Fingerprinting
- Extracts tech stack from httpx JSON output

### 📸 EyeWitness Integration (Optional)
- Screenshots of alive web targets
- Minimal ZIP export for reporting

### 🔁 State-Based Diffing
- Tracks changes between runs
- Detects:
  - ➕ new subdomains
  - ➕ new open ports
  - ➕ new nuclei findings

### 🔔 Discord Webhook Notifications
- Sends only new results
- Optional file attachments (diffs, screenshots)

---

## 🎯 Purpose

Many public recon scripts are incomplete or unreliable.

This project focuses on:
- ✅ realistic bug bounty workflows
- ✅ clean automation
- ✅ safe execution
- ✅ repeatable recon on VPS / CI systems

---

## 📦 Requirements

### 🖥️ System
- Linux or WSL2 (recommended)
- Python 3.9+
- Go 1.20+

### 🐍 Python Dependency
pip3 install requests

### 🧰 External Tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest

sudo apt install -y nmap

### 🧠 Nuclei Templates (Required)
nuclei -ut

Ensure Go binaries are in PATH:
export PATH="$PATH:$HOME/go/bin"

---

## 🛠️ Installation

git clone https://github.com/NotSomewhere/Bug-Bounty-recon.git
cd Bug-Bounty-recon

---

## ▶️ Usage

python3 recon.py example.com -o out

### 🔔 With Discord Webhook
python3 recon.py example.com -o out --webhook https://discord.com/api/webhooks/XXXX/XXXX

### ⚙️ Options
domain        Target domain (example.com)
-o / --out    Output directory (default: out)
--no-crtsh    Skip crt.sh enumeration
--no-httpx   Skip httpx even if installed
--webhook    Discord webhook URL (optional)

---

## 📁 Output Structure

out/
  subdomains.txt
  alive_urls.txt
  alive_hosts.txt
  httpx.jsonl
  tech_summary.txt
  nmap_quick.txt
  nmap_full.txt
  interesting_ports.txt
  nuclei.txt
  nuclei_targets.txt
  eyewitness/
  eyewitness.zip
  state.json

---

## 🔄 State Tracking

Results are stored in state.json.

Each run compares current output with the previous state
and reports **ONLY new changes**.

Ideal for:
- ⏰ scheduled recon
- 📡 continuous monitoring
- ☁️ VPS automation

---

## ⚠️ Legal Disclaimer

🚨 **This project is for educational purposes and AUTHORIZED security testing only.**

You may only use this tool on:
- assets you own
- targets explicitly allowed by a bug bounty program
- systems you have written permission to test

❌ **DO NOT scan random domains or infrastructure.**

The author is **NOT responsible** for misuse of this software.

---

## 📜 License

MIT License.  
Use responsibly.
