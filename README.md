# Bug Bounty Recon Automation Suite

Automated recon pipeline for authorized security testing and bug bounty programs. The script chains common tools into a repeatable workflow for VPS, CI, or scheduled runs.

## Features
- Passive subdomain collection via subfinder, assetfinder, and crt.sh
- Alive host probing with httpx (or Python requests fallback)
- Page type detection (login, admin, docs, status, api)
- Optional EyeWitness screenshots
- Nmap quick scan and optional targeted full scan
- Nuclei scan with severity filtering
- Tech fingerprinting from httpx JSON output
- State-based diffing between runs
- Optional Discord webhook notifications with attachments

## Requirements
- Python 3.9+
- Go 1.20+ (for external tools)
- Linux, macOS, or Windows (WSL recommended for full toolchain)

Python dependency:
```bash
pip3 install requests
```

External tools:
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
```

Nmap:
```bash
sudo apt-get install -y nmap
```

Nuclei templates:
```bash
nuclei -ut
```

Make sure Go binaries are in PATH:
```bash
export PATH="$PATH:$HOME/go/bin"
```

## Installation
```bash
git clone https://github.com/NotSomewhere/Bug-Bounty-recon.git
cd Bug-Bounty-recon
pip3 install -e .
```

## Usage
```bash
bbr example.com -o out
```

Authorized active scanning:
```bash
bbr example.com -o out --i-am-authorized
```

Discord webhook:
```bash
bbr example.com -o out --i-am-authorized --webhook https://discord.com/api/webhooks/XXXX/XXXX
```

Config init:
```bash
bbr init
```

Run with config:
```bash
bbr example.com
```

## Options
- `domain` Target domain (example.com)
- `-o, --out` Output directory (default: out)
- `--no-crtsh` Skip crt.sh enumeration
- `--no-httpx` Skip httpx even if installed
- `--no-nmap-full` Skip full nmap scan
- `--no-eyewitness` Skip EyeWitness
- `--no-nuclei` Skip Nuclei
- `--webhook` Discord webhook URL (optional)
- `--user-agent` HTTP user-agent (default: bug-bounty-recon/1.0)
- `--http-timeout` HTTP timeout in seconds (default: 8)
- `--max-body` Max bytes read per page for page-type detection (default: 200000)
- `--eyewitness-path` Path to EyeWitness directory (optional)
- `--i-am-authorized` Required for active probing and scanning
- `--config` Path to config file (default: bbr.json)

## Output Structure
```text
out/
  subdomains.txt
  alive_urls.txt
  alive_hosts.txt
  httpx.jsonl
  tech_summary.txt
  page_types.txt
  nmap_quick.txt
  nmap_full.txt
  interesting_ports.txt
  nuclei.txt
  nuclei_targets.txt
  eyewitness/
  eyewitness.zip
  state.json
```

## State Tracking
The script keeps `state.json` and reports only new changes across runs.

## Legal Disclaimer
This project is for educational purposes and authorized security testing only. Use it only on assets you own or are explicitly permitted to test. Do not scan random domains or infrastructure. The author is not responsible for misuse.

## License
MIT License.
