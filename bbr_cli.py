#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

import recon

DEFAULT_CONFIG = {
    "out": "out",
    "no_crtsh": False,
    "no_httpx": False,
    "no_nmap_full": False,
    "no_eyewitness": False,
    "no_nuclei": False,
    "webhook": "",
    "user_agent": "bug-bounty-recon/1.0",
    "http_timeout": 8,
    "max_body": 200000,
    "eyewitness_path": "",
    "i_am_authorized": False,
}

CONFIG_KEYS = set(DEFAULT_CONFIG.keys())


def parse_init_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="bbr init")
    ap.add_argument("-c", "--config", default="bbr.json", help="config file path")
    ap.add_argument("--force", action="store_true", help="overwrite if exists")
    return ap.parse_args(argv)


def load_config(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if k in CONFIG_KEYS}
    except Exception:
        pass
    return {}


def write_default_config(path: Path, force: bool) -> int:
    if path.exists() and not force:
        print(f"[!] Config already exists: {path}")
        return 1
    path.write_text(json.dumps(DEFAULT_CONFIG, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[+] Wrote config: {path}")
    return 0


def arg_present(argv: List[str], flag: str) -> bool:
    return flag in argv or any(a.startswith(flag + "=") for a in argv)


def config_to_argv(cfg: dict, argv: List[str]) -> List[str]:
    out: List[str] = []

    if "out" in cfg and not arg_present(argv, "-o") and not arg_present(argv, "--out"):
        out += ["-o", str(cfg["out"])]

    if cfg.get("no_crtsh") and not arg_present(argv, "--no-crtsh"):
        out.append("--no-crtsh")
    if cfg.get("no_httpx") and not arg_present(argv, "--no-httpx"):
        out.append("--no-httpx")
    if cfg.get("no_nmap_full") and not arg_present(argv, "--no-nmap-full"):
        out.append("--no-nmap-full")
    if cfg.get("no_eyewitness") and not arg_present(argv, "--no-eyewitness"):
        out.append("--no-eyewitness")
    if cfg.get("no_nuclei") and not arg_present(argv, "--no-nuclei"):
        out.append("--no-nuclei")

    if cfg.get("webhook") and not arg_present(argv, "--webhook"):
        out += ["--webhook", str(cfg["webhook"])]
    if cfg.get("user_agent") and not arg_present(argv, "--user-agent"):
        out += ["--user-agent", str(cfg["user_agent"])]
    if cfg.get("http_timeout") and not arg_present(argv, "--http-timeout"):
        out += ["--http-timeout", str(cfg["http_timeout"])]
    if cfg.get("max_body") and not arg_present(argv, "--max-body"):
        out += ["--max-body", str(cfg["max_body"])]
    if cfg.get("eyewitness_path") and not arg_present(argv, "--eyewitness-path"):
        out += ["--eyewitness-path", str(cfg["eyewitness_path"])]

    if cfg.get("i_am_authorized") and not arg_present(argv, "--i-am-authorized"):
        out.append("--i-am-authorized")

    return out


def cli(argv: Optional[List[str]] = None) -> int:
    argv = list(argv) if argv is not None else sys.argv[1:]
    if not argv:
        print("Usage: bbr <domain> [options] | bbr init [-c bbr.json]")
        return 1

    if argv[0] == "init":
        args = parse_init_args(argv[1:])
        return write_default_config(Path(args.config), args.force)

    config_path = Path("bbr.json")
    if "--config" in argv:
        idx = argv.index("--config")
        if idx + 1 >= len(argv):
            print("[!] --config requires a value")
            return 1
        config_path = Path(argv[idx + 1])
        argv = argv[:idx] + argv[idx + 2 :]

    cfg = load_config(config_path)
    cfg_args = config_to_argv(cfg, argv)
    final_argv = cfg_args + argv
    return recon.main(final_argv)


if __name__ == "__main__":
    raise SystemExit(cli())
