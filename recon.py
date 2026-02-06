#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BUG BOUNTY RECON AUTOMATION SUITE (ethical / authorized use only)

Features:
- Passive subdomain collection: subfinder, assetfinder, crt.sh
- Alive probing: httpx (preferred) or requests fallback
- Page type detection (login/admin/docs/status/api)
- Optional EyeWitness screenshots
- Nmap quick + optional full scan
- Nuclei scan
- Optional Discord webhook diff updates (state.json)

Safety:
- Active actions require explicit flag: --i-am-authorized
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple, Dict
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests. Install: pip3 install requests", file=sys.stderr)
    sys.exit(1)

GREEN = "\x1b[32m"
RED = "\x1b[31m"
YELLOW = "\x1b[33m"
BOLD = "\x1b[1m"
CYAN = "\x1b[36m"
RESET = "\x1b[0m"

DISCORD_MAX_FILE = 8 * 1024 * 1024
DEFAULT_UA = "bug-bounty-recon/1.0"

# ----------------------------
# pretty prints
# ----------------------------

def print_banner() -> None:
    width = 60
    top = "+" + "-" * width + "+"
    title = "BUG BOUNTY RECON AUTOMATION SUITE"
    subtitle = "Automating subdomain discovery & scanning"
    line1 = "| " + title.ljust(width - 1) + "|"
    line2 = "| " + subtitle.ljust(width - 1) + "|"
    print("", flush=True)
    print(f"{GREEN}{top}{RESET}", flush=True)
    print(f"{GREEN}{line1}{RESET}", flush=True)
    print(f"{GREEN}{line2}{RESET}", flush=True)
    print(f"{GREEN}{top}{RESET}", flush=True)
    print("", flush=True)

def print_info(msg: str) -> None:
    print(f"{GREEN}{msg}{RESET}", flush=True)

def print_good(msg: str) -> None:
    print(f"{GREEN}{msg}{RESET}", flush=True)

def print_bad(msg: str) -> None:
    print(f"{RED}{msg}{RESET}", flush=True)

def print_emph(msg: str) -> None:
    print(f"{YELLOW}{BOLD}{msg}{RESET}", flush=True)

def print_summary(msg: str) -> None:
    print(f"{CYAN}{msg}{RESET}", flush=True)

# ----------------------------
# utils
# ----------------------------

def tool_install_hint(name: str) -> str:
    system = platform.system().lower()
    hints = {
        "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
        "nmap": "sudo apt-get install -y nmap" if system == "linux" else (
            "brew install nmap" if system == "darwin" else "choco install nmap"
        ),
        "eyewitness": "git clone https://github.com/FortyNorthSecurity/EyeWitness ~/EyeWitness",
    }
    return hints.get(name, "")

def which(bin_name: str) -> Optional[str]:
    return shutil.which(bin_name)

def run_cmd(cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout after {timeout}s: {' '.join(cmd)}"

def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for line in lines:
            f.write(str(line).rstrip() + "\n")

def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip()]

def uniq_sorted(items: Iterable[str]) -> List[str]:
    return sorted(set(i for i in items if i))

def make_headers(user_agent: str) -> dict:
    return {"User-Agent": user_agent}

def normalize_subdomain(s: str) -> str:
    s = s.strip().lower()
    s = s.lstrip("*.")                  # wildcard
    s = re.sub(r"^https?://", "", s)     # scheme
    s = s.split("/")[0]                 # path
    s = s.split(":")[0]                 # port
    return s.strip(".")

def only_in_scope(subs: Iterable[str], domain: str) -> List[str]:
    domain = domain.lower().strip(".")
    out: List[str] = []
    for s in subs:
        s2 = normalize_subdomain(s)
        if s2 == domain or s2.endswith("." + domain):
            out.append(s2)
    return out

def urls_to_hosts(urls: Iterable[str]) -> List[str]:
    hosts: Set[str] = set()
    for u in urls:
        u = u.strip()
        if not u:
            continue
        if "://" not in u:
            u = "http://" + u
        p = urlparse(u)
        if p.hostname:
            hosts.add(p.hostname.lower())
    return sorted(hosts)

def normalize_nmap_host(host: str) -> str:
    host = host.strip()
    host = re.sub(r"\s*\([^)]*\)\s*$", "", host)
    return host.strip()

def normalize_alive_urls(urls: Iterable[str]) -> List[str]:
    cleaned: Set[str] = set()
    for url in urls:
        url = url.strip()
        if not url:
            continue
        if "://" not in url:
            url = "http://" + url
        p = urlparse(url)
        scheme = (p.scheme or "http").lower()
        host = (p.hostname or "").lower()
        if not host:
            continue
        port = p.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = host
        elif port:
            netloc = f"{host}:{port}"
        else:
            netloc = host

        path = p.path or "/"
        if not path.startswith("/"):
            path = "/" + path

        cleaned.add(f"{scheme}://{netloc}{path}")
    return sorted(cleaned)

def group_hits_by_host(hits: List[str]) -> List[str]:
    grouped: Dict[str, Set[str]] = {}
    for hp in hits:
        if ":" not in hp:
            continue
        host, port = hp.rsplit(":", 1)
        grouped.setdefault(host, set()).add(port)

    lines: List[str] = []
    for host in sorted(grouped):
        ports = ", ".join(sorted(grouped[host], key=lambda x: int(x) if x.isdigit() else 99999))
        lines.append(f"{host}: {ports}")
    return lines

def classify_page(url: str, body: str) -> Optional[str]:
    text = (url + " " + body).lower()
    checks = [
        ("admin", ["admin", "administrator", "dashboard", "control panel", "wp-admin"]),
        ("login", ["login", "log in", "sign in", "signin", "wp-login", "user/password"]),
        ("docs",  ["documentation", "docs", "swagger", "openapi", "api docs", "redoc"]),
        ("status", ["status", "health", "uptime", "status page"]),
        ("api",   ["api reference", "graphql", "/api/", "api explorer"]),
    ]
    for label, keys in checks:
        for key in keys:
            if key in text:
                return label
    return None

def load_state(path: Path) -> dict:
    if not path.exists():
        return {"subdomains": [], "ports": [], "findings": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"subdomains": [], "ports": [], "findings": []}

def save_state(path: Path, state: dict) -> None:
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")

def to_set(lines: List[str]) -> Set[str]:
    return set(ln.strip() for ln in lines if ln.strip())

def zip_eyewitness_minimal(ew_dir: Path, zip_path: Path) -> None:
    screens = ew_dir / "screens"
    report = ew_dir / "report.html"
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if screens.exists():
            for path in screens.rglob("*"):
                if path.is_file():
                    zf.write(path, str(path.relative_to(ew_dir)))
        if report.exists() and report.is_file():
            zf.write(report, str(report.relative_to(ew_dir)))

# ----------------------------
# passive collectors
# ----------------------------

def collect_subfinder(domain: str, out_dir: Path) -> List[str]:
    binp = which("subfinder")
    if not binp:
        hint = tool_install_hint("subfinder")
        msg = "[!] subfinder not found -> skipping"
        if hint:
            msg += f" (install: {hint})"
        print_bad(msg)
        return []
    print_info("[*] Running Subfinder")
    rc, stdout, stderr = run_cmd([binp, "-d", domain, "-silent"], timeout=600)
    if rc != 0 and stderr:
        print_bad(f"[!] subfinder rc={rc}: {stderr.strip()[:200]}")
    raw = stdout.splitlines()
    write_lines(out_dir / "raw_subfinder.txt", raw)
    return raw

def collect_assetfinder(domain: str, out_dir: Path) -> List[str]:
    binp = which("assetfinder")
    if not binp:
        hint = tool_install_hint("assetfinder")
        msg = "[!] assetfinder not found -> skipping"
        if hint:
            msg += f" (install: {hint})"
        print_bad(msg)
        return []
    print_info("[*] Running Assetfinder")
    rc, stdout, stderr = run_cmd([binp, "--subs-only", domain], timeout=300)
    if rc != 0 and stderr:
        print_bad(f"[!] assetfinder rc={rc}: {stderr.strip()[:200]}")
    raw = stdout.splitlines()
    write_lines(out_dir / "raw_assetfinder.txt", raw)
    return raw

def collect_crtsh(domain: str, out_dir: Path, headers: dict, timeout: int) -> List[str]:
    # gentle pacing for crt.sh
    time.sleep(1.0)
    try:
        print_info("[*] Querying crt.sh")
        r = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout,
            headers=headers,
        )
        if r.status_code != 200:
            return []
        try:
            data = r.json()
        except Exception:
            print_bad("[!] crt.sh did not return valid JSON")
            return []
    except Exception:
        return []
    raw: List[str] = []
    for row in data:
        nv = row.get("name_value", "")
        raw.extend(nv.splitlines())
    write_lines(out_dir / "raw_crtsh.txt", raw)
    return raw

# ----------------------------
# alive probing
# ----------------------------

def probe_httpx(subdomains_file: Path, out_dir: Path) -> Tuple[Path, Path]:
    """Use httpx if available -> httpx.jsonl + alive_urls.txt"""
    binp = which("httpx")
    jsonl = out_dir / "httpx.jsonl"
    alive_urls = out_dir / "alive_urls.txt"

    if not binp:
        hint = tool_install_hint("httpx")
        if hint:
            print_bad(f"[!] httpx not found -> skipping (install: {hint})")
        return jsonl, alive_urls

    print_info("[*] Probing alive hosts (httpx)")
    cmd = [
        binp,
        "-l", str(subdomains_file),
        "-silent",
        "-follow-redirects",
        "-timeout", "8",
        "-retries", "1",
        "-ports", "80,443,3000,5000,7001,7002,8000,8008,8080,8081,8088,8181,8443,8444,8888,9000,9443",
        "-status-code",
        "-title",
        "-tech-detect",
        "-json",
        "-o", str(jsonl),
    ]
    rc, _, stderr = run_cmd(cmd, timeout=900)
    if rc != 0 and stderr:
        print_bad(f"[!] httpx rc={rc}: {stderr.strip()[:200]}")

    urls: List[str] = []
    if jsonl.exists():
        for line in read_lines(jsonl):
            try:
                obj = json.loads(line)
                u = obj.get("url")
                if u:
                    urls.append(u.split("#")[0].split("?")[0])
            except Exception:
                pass

    urls = uniq_sorted(urls)
    write_lines(alive_urls, urls)
    return jsonl, alive_urls

def probe_fallback_requests(subs: List[str], out_dir: Path, headers: dict, timeout: int) -> Path:
    """Fallback if httpx not installed: tries https then http HEAD/GET."""
    alive_urls = out_dir / "alive_urls.txt"
    urls: Set[str] = set()
    for host in subs:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                r = requests.head(url, timeout=timeout, allow_redirects=True, headers=headers)
                if r.status_code < 600:
                    urls.add(r.url if r.url else url)
                    break
            except Exception:
                try:
                    r = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers)
                    if r.status_code < 600:
                        urls.add(r.url if r.url else url)
                        break
                except Exception:
                    continue
    out = sorted(urls)
    write_lines(alive_urls, out)
    return alive_urls

def fetch_body_limited(url: str, headers: dict, timeout: int, limit: int) -> Tuple[str, str]:
    r = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers, stream=True)
    if r.status_code >= 600:
        return r.url, ""
    chunks: List[bytes] = []
    size = 0
    for chunk in r.iter_content(chunk_size=8192):
        if not chunk:
            continue
        chunks.append(chunk)
        size += len(chunk)
        if size >= limit:
            break
    body = b"".join(chunks).decode("utf-8", errors="ignore")
    return r.url, body

def detect_login_admin(alive_urls_file: Path, out_dir: Path, headers: dict, timeout: int, limit: int) -> List[str]:
    hits: List[str] = []
    urls = read_lines(alive_urls_file)
    if not urls:
        return hits
    print_info("[*] Checking page types (login/admin/docs)")
    out_path = out_dir / "page_types.txt"
    for url in urls:
        try:
            final_url, body = fetch_body_limited(url, headers, timeout, limit)
            if not body:
                continue
            marker = classify_page(final_url, body)
            if marker:
                hits.append(f"{final_url} ({marker})")
        except Exception:
            continue
    write_lines(out_path, hits)
    return hits

def parse_httpx_tech(httpx_jsonl: Path, out_dir: Path) -> Path:
    out_path = out_dir / "tech_summary.txt"
    if not httpx_jsonl.exists():
        return out_path
    url_map: List[str] = []
    for line in read_lines(httpx_jsonl):
        try:
            obj = json.loads(line)
            url = obj.get("url")
            techs = obj.get("tech") or obj.get("techs") or obj.get("technologies") or []
            if url and techs:
                url_map.append(f"{url} -> {', '.join(techs)}")
        except Exception:
            continue
    write_lines(out_path, url_map)
    return out_path

def resolve_eyewitness_paths(root: Optional[Path]) -> Tuple[Optional[Path], Optional[Path]]:
    candidates: List[Path] = []
    if root:
        candidates.append(root)
    candidates.append(Path.home() / "EyeWitness")
    candidates.append(Path.cwd() / "EyeWitness")

    py_candidates: List[Path] = []
    venv_candidates: List[Path] = []

    for base in candidates:
        py_candidates.extend([
            base / "Python" / "EyeWitness.py",
            base / "EyeWitness.py",
        ])
        venv_candidates.extend([
            base / "venv" / "bin" / "python",
            base / "venv" / "Scripts" / "python.exe",
        ])

    ew_py = next((p for p in py_candidates if p.exists()), None)
    venv_py = next((p for p in venv_candidates if p.exists()), None)
    return ew_py, venv_py

def run_eyewitness(alive_urls_file: Path, out_dir: Path, root: Optional[Path]) -> Path:
    ew_py, venv_py = resolve_eyewitness_paths(root)
    out_path = out_dir / "eyewitness"

    urls = read_lines(alive_urls_file)
    if not urls:
        print_bad("[!] no alive URLs for eyewitness -> skipping")
        return out_path

    if not ew_py:
        hint = tool_install_hint("eyewitness")
        msg = "[!] EyeWitness not found -> skipping"
        if hint:
            msg += f" (install: {hint})"
        print_bad(msg)
        return out_path

    python_bin = str(venv_py) if venv_py else (which("python3") or sys.executable or "python3")
    print_info("[*] EyeWitness screenshots (python)")
    out_path.mkdir(parents=True, exist_ok=True)

    cmd = [
        python_bin, str(ew_py),
        "--web",
        "-f", str(alive_urls_file),
        "-d", str(out_path),
        "--no-prompt",
    ]
    rc, _, stderr = run_cmd(cmd, timeout=3600)
    if rc != 0 and stderr:
        print_bad(f"[!] eyewitness rc={rc}: {stderr.strip()[:200]}")
    return out_path

# ----------------------------
# scanning (nmap)
# ----------------------------

def run_nmap_quick(alive_hosts_file: Path, out_dir: Path) -> Path:
    binp = which("nmap")
    out_path = out_dir / "nmap_quick.txt"
    if not binp:
        hint = tool_install_hint("nmap")
        msg = "[!] nmap not found -> skipping"
        if hint:
            msg += f" (install: {hint})"
        print_bad(msg)
        return out_path

    hosts = read_lines(alive_hosts_file)
    if not hosts:
        print_bad("[!] no alive hosts for nmap -> skipping")
        return out_path

    print_info("[*] Nmap scan (top 1000 TCP ports)")
    cmd = [
        binp,
        "-sT",
        "-iL", str(alive_hosts_file),
        "-T3",
        "-Pn",
        "--top-ports", "1000",
        "-oN", str(out_path),
    ]
    rc, _, stderr = run_cmd(cmd, timeout=1800)
    if rc != 0 and stderr:
        print_bad(f"[!] nmap rc={rc}: {stderr.strip()[:200]}")
    return out_path

def run_nmap_full(hosts_file: Path, out_dir: Path) -> Path:
    binp = which("nmap")
    out_path = out_dir / "nmap_full.txt"
    if not binp:
        hint = tool_install_hint("nmap")
        msg = "[!] nmap not found -> skipping"
        if hint:
            msg += f" (install: {hint})"
        print_bad(msg)
        return out_path

    hosts = read_lines(hosts_file)
    if not hosts:
        print_bad("[!] no hosts for full nmap -> skipping")
        return out_path

    print_info("[*] Nmap scan (full scan -sV -p-)")
    cmd = [
        binp,
        "-iL", str(hosts_file),
        "-sV",
        "-T3",
        "-Pn",
        "-p-",
        "-oN", str(out_path),
    ]
    rc, _, stderr = run_cmd(cmd, timeout=3600)
    if rc != 0 and stderr:
        print_bad(f"[!] nmap rc={rc}: {stderr.strip()[:200]}")
    return out_path

def find_interesting_ports(nmap_output: Path) -> List[str]:
    interesting = {
        "21", "23", "25", "53", "110", "111", "135", "139", "143", "389", "445",
        "465", "587", "636", "993", "995", "1433", "1521", "2049", "2375", "2379",
        "2380", "27017", "27018", "27019", "3306", "3389", "5432", "5601", "5900",
        "5985", "5986", "6379", "7001", "7002", "8000", "8008", "8080", "8081",
        "8088", "8181", "8443", "8880", "8888", "9000", "9001", "9042", "9200",
        "9300", "9443", "10443", "11211", "15672", "15692",
        "3000", "3001", "3002", "3003", "4000", "4040", "4200", "5000", "5001",
        "6006", "7000", "7070", "8001", "9002",
    }

    hits: List[str] = []
    current_host = ""

    for line in read_lines(nmap_output):
        if line.startswith("Nmap scan report for "):
            raw_host = line.replace("Nmap scan report for ", "").strip()
            current_host = normalize_nmap_host(raw_host)
            continue

        if "/tcp" in line and " open " in line:
            port = line.split("/")[0].strip()
            if port in interesting and current_host:
                hits.append(f"{current_host}:{port}")

    return hits

def summarize_open_ports(nmap_output: Path) -> List[str]:
    summaries: List[str] = []
    current_host = ""
    ports: List[str] = []

    for line in read_lines(nmap_output):
        if line.startswith("Nmap scan report for "):
            if current_host and ports:
                summaries.append(f"{current_host}: {', '.join(ports)}")

            raw_host = line.replace("Nmap scan report for ", "").strip()
            current_host = normalize_nmap_host(raw_host)
            ports = []
            continue

        if "/tcp" in line and " open " in line:
            port = line.split("/")[0].strip()
            if port:
                ports.append(port)

    if current_host and ports:
        summaries.append(f"{current_host}: {', '.join(ports)}")

    return summaries

# ----------------------------
# nuclei
# ----------------------------

def build_nuclei_targets_from_hits(hits: List[str], out_dir: Path) -> Path:
    hosts: Set[str] = set()
    targets: List[str] = []

    for item in hits:
        if ":" not in item:
            continue
        host, port = item.rsplit(":", 1)
        host = normalize_nmap_host(host)
        if not host or not port:
            continue
        hosts.add(host)
        targets.append(f"http://{host}:{port}")
        targets.append(f"https://{host}:{port}")

    for host in sorted(hosts):
        targets.append(f"http://{host}")
        targets.append(f"https://{host}")

    targets_file = out_dir / "nuclei_targets.txt"
    write_lines(targets_file, uniq_sorted(targets))
    return targets_file

def run_nuclei(targets_file: Path, out_dir: Path) -> Path:
    binp = which("nuclei")
    out_path = out_dir / "nuclei.txt"
    if not binp:
        hint = tool_install_hint("nuclei")
        msg = "[!] nuclei not found -> skipping"
        if hint:
            msg += f" (install: {hint})"
        print_bad(msg)
        return out_path

    urls = read_lines(targets_file)
    if not urls:
        print_bad("[!] no nuclei targets -> skipping")
        return out_path

    print_info("[*] Nuclei scan (low/medium/high/critical)")
    cmd = [
        binp,
        "-l", str(targets_file),
        "-severity", "low,medium,high,critical",
        "-silent",
        "-o", str(out_path),
    ]
    rc, _, stderr = run_cmd(cmd, timeout=1800)
    if rc != 0 and stderr:
        print_bad(f"[!] nuclei rc={rc}: {stderr.strip()[:200]}")
    return out_path

def summarize_nuclei_findings(nuclei_output: Path) -> List[str]:
    findings = read_lines(nuclei_output)
    by_host: Dict[str, List[str]] = {}

    for line in findings:
        parts = line.split()
        url = ""
        for part in reversed(parts):
            if part.startswith("http://") or part.startswith("https://"):
                url = part
                break
        if not url:
            continue
        host = urlparse(url).netloc or url
        by_host.setdefault(host, []).append(line)

    summary: List[str] = []
    for host in sorted(by_host):
        summary.append(f"{host} ({len(by_host[host])})")
    return summary

# ----------------------------
# webhook
# ----------------------------

def send_webhook_with_files(webhook_url: str, content: str, file_paths: List[Path]) -> None:
    if not webhook_url:
        return

    files: dict[str, tuple[str, object]] = {}
    opened = []
    sent = 0
    skipped = 0

    try:
        i = 0
        for p in file_paths:
            if not p or not p.exists() or not p.is_file():
                continue
            if p.stat().st_size > DISCORD_MAX_FILE:
                skipped += 1
                continue
            f = p.open("rb")
            opened.append(f)
            files[f"files[{i}]"] = (p.name, f)
            i += 1
            sent += 1

        if skipped:
            content += f"\nSkipped files (too large): {skipped}"
        content += f"\nFiles sent: {sent}"

        resp = requests.post(webhook_url, data={"content": content}, files=files, timeout=30)
        if resp.status_code >= 300:
            print_bad(f"[!] webhook HTTP {resp.status_code}: {resp.text[:200]}")

    except Exception as e:
        print_bad(f"[!] webhook failed: {e}")
    finally:
        for f in opened:
            try:
                f.close()
            except Exception:
                pass

# ----------------------------
# main
# ----------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("domain", help="domain (e.g. example.com)")
    ap.add_argument("-o", "--out", default="out", help="output directory (default: out)")

    ap.add_argument("--no-crtsh", action="store_true", help="skip crt.sh")
    ap.add_argument("--no-httpx", action="store_true", help="skip httpx even if installed")

    ap.add_argument("--no-nmap-full", action="store_true", help="skip full nmap scan")
    ap.add_argument("--no-eyewitness", action="store_true", help="skip EyeWitness")
    ap.add_argument("--no-nuclei", action="store_true", help="skip Nuclei")

    ap.add_argument("--webhook", default=os.getenv("DISCORD_WEBHOOK", ""), help="discord webhook url (optional)")
    ap.add_argument("--user-agent", default=os.getenv("RECON_USER_AGENT", DEFAULT_UA), help="http user-agent")
    ap.add_argument("--http-timeout", type=int, default=8, help="http timeout in seconds")
    ap.add_argument("--max-body", type=int, default=200000, help="max bytes to read per page")
    ap.add_argument("--eyewitness-path", default="", help="path to EyeWitness directory (optional)")

    # SAFETY: require explicit acknowledgment for active actions
    ap.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="REQUIRED for active probing/scanning. Only run on authorized scope.",
    )

    args = ap.parse_args(argv)

    domain = args.domain.strip().lower().strip(".")
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    headers = make_headers(args.user_agent)

    print_banner()
    print_info(f"[+] Target: {domain}")
    print_info("[*] Setting up directories")

    # Passive recon is allowed without --i-am-authorized
    print_emph("[*] Starting subdomain enumeration (passive)")
    subs: List[str] = []
    subs += collect_subfinder(domain, out_dir)
    subs += collect_assetfinder(domain, out_dir)
    if not args.no_crtsh:
        subs += collect_crtsh(domain, out_dir, headers, args.http_timeout)

    subs = uniq_sorted(only_in_scope(subs, domain))
    subs_file = out_dir / "subdomains.txt"
    write_lines(subs_file, subs)
    print_summary(f"[+] {len(subs)} subdomains wurden gefunden.")

    # Nothing else to do without authorization
    if not args.i_am_authorized:
        print_emph("[!] Active probing/scanning is DISABLED.")
        print_emph("[!] Re-run with --i-am-authorized ONLY if you have explicit permission/scope.")
        return 0

    # Alive probing
    alive_urls_file: Path
    if not args.no_httpx and which("httpx"):
        _, alive_urls_file = probe_httpx(subs_file, out_dir)
        if not alive_urls_file.exists() or not read_lines(alive_urls_file):
            alive_urls_file = probe_fallback_requests(subs, out_dir, headers, args.http_timeout)
    else:
        alive_urls_file = probe_fallback_requests(subs, out_dir, headers, args.http_timeout)

    alive_urls = normalize_alive_urls(read_lines(alive_urls_file))
    alive_urls_file = out_dir / "alive_urls.txt"
    write_lines(alive_urls_file, alive_urls)
    print_summary(f"[+] {len(alive_urls)} subdomains sind alive.")

    login_hits = detect_login_admin(alive_urls_file, out_dir, headers, args.http_timeout, args.max_body)
    if login_hits:
        print_emph("[*] Page Types gefunden:")
        for item in login_hits[:50]:
            print_summary(f"[+] {item}")
        if len(login_hits) > 50:
            print_summary("[+] ...")

    tech_out = parse_httpx_tech(out_dir / "httpx.jsonl", out_dir)
    if tech_out.exists() and read_lines(tech_out):
        print_good("[+] Tech summary gespeichert.")

    # Hosts list for nmap
    alive_hosts_file = out_dir / "alive_hosts.txt"
    write_lines(alive_hosts_file, urls_to_hosts(alive_urls))

    # Nmap quick
    nmap_quick_out = run_nmap_quick(alive_hosts_file, out_dir)
    if nmap_quick_out.exists():
        print_good("[+] nmap quick scan abgeschlossen.")

    hits: List[str] = []
    if nmap_quick_out.exists():
        hits = find_interesting_ports(nmap_quick_out)

    if hits:
        print_emph("[*] Interesting ports gefunden:")
        for item in hits[:50]:
            print_summary(f"[+] {item}")
        if len(hits) > 50:
            print_summary("[+] ...")

    # Nmap full (optional)
    nmap_full_out = out_dir / "nmap_full.txt"
    summaries: List[str] = []
    if hits and not args.no_nmap_full:
        full_hosts_file = out_dir / "interesting_hosts.txt"
        write_lines(full_hosts_file, sorted({h.split(":", 1)[0] for h in hits}))
        nmap_full_out = run_nmap_full(full_hosts_file, out_dir)
        if nmap_full_out.exists():
            print_good("[+] nmap full scan abgeschlossen.")
            summaries = summarize_open_ports(nmap_full_out)
            if summaries:
                print_emph("[*] Offene Ports (Full Scan):")
                for line in summaries[:50]:
                    print_summary(f"[+] {line}")
                if len(summaries) > 50:
                    print_summary("[+] ...")

    # Nuclei (optional)
    findings: List[str] = []
    if not args.no_nuclei:
        nuclei_targets = alive_urls_file
        if hits:
            nuclei_targets = build_nuclei_targets_from_hits(hits, out_dir)
        nuclei_out = run_nuclei(nuclei_targets, out_dir)
        if nuclei_out.exists():
            findings = read_lines(nuclei_out)
            if findings:
                print_emph(f"[*] Nuclei Findings: {len(findings)}")
                summary = summarize_nuclei_findings(nuclei_out)
                for line in summary[:20]:
                    print_summary(f"[+] {line}")
            else:
                print_good("[+] Nuclei: keine Findings.")

    # EyeWitness (optional)
    eye_out = out_dir / "eyewitness"
    if not args.no_eyewitness:
        root = Path(args.eyewitness_path).expanduser().resolve() if args.eyewitness_path else None
        eye_out = run_eyewitness(alive_urls_file, out_dir, root)
        if eye_out.exists():
            print_good("[+] EyeWitness screenshots gespeichert.")

    # Write interesting ports file for state tracking
    if hits:
        interesting_txt = out_dir / "interesting_ports.txt"
        write_lines(interesting_txt, group_hits_by_host(hits))

    # Diff state + webhook
    state_path = out_dir / "state.json"
    old = load_state(state_path)

    current_subs = read_lines(out_dir / "subdomains.txt")
    current_ports = read_lines(out_dir / "interesting_ports.txt") if (out_dir / "interesting_ports.txt").exists() else []
    current_findings = read_lines(out_dir / "nuclei.txt") if (out_dir / "nuclei.txt").exists() else []

    old_subs = to_set(old.get("subdomains", []))
    old_ports = to_set(old.get("ports", []))
    old_findings = to_set(old.get("findings", []))

    new_subs = sorted(to_set(current_subs) - old_subs)
    new_ports = sorted(to_set(current_ports) - old_ports)
    new_findings = sorted(to_set(current_findings) - old_findings)

    save_state(state_path, {
        "subdomains": sorted(to_set(current_subs)),
        "ports": sorted(to_set(current_ports)),
        "findings": sorted(to_set(current_findings)),
    })

    if not (new_subs or new_ports or new_findings):
        print_good("[+] No new changes -> no Discord message sent.")
        return 0

    content = (
        f"Recon update for {domain}\n"
        f"New subdomains: {len(new_subs)}\n"
        f"New ports: {len(new_ports)}\n"
        f"New nuclei findings: {len(new_findings)}"
    )

    if new_subs:
        content += "\nNew subdomains:\n" + "\n".join(new_subs[:20])
        if len(new_subs) > 20:
            content += "\n..."

    if new_ports:
        content += "\n\nNew ports:\n" + "\n".join(new_ports[:20])
        if len(new_ports) > 20:
            content += "\n..."

    if new_findings:
        content += "\n\nNew nuclei:\n" + "\n".join(new_findings[:10])
        if len(new_findings) > 10:
            content += "\n..."

    files_to_send: List[Path] = []
    if new_subs:
        p = out_dir / "new_subdomains.txt"
        write_lines(p, new_subs)
        files_to_send.append(p)
    if new_ports:
        p = out_dir / "new_ports.txt"
        write_lines(p, new_ports)
        files_to_send.append(p)
    if new_findings:
        p = out_dir / "new_nuclei.txt"
        write_lines(p, new_findings)
        files_to_send.append(p)

    if eye_out.exists() and not args.no_eyewitness:
        eyewitness_zip = out_dir / "eyewitness.zip"
        zip_eyewitness_minimal(eye_out, eyewitness_zip)
        files_to_send.append(eyewitness_zip)

    send_webhook_with_files(args.webhook, content, files_to_send)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
