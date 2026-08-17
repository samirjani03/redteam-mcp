"""
Subfinder / Amass / httpx output parser.

These tools emit one JSON object per line with -json flag:
  subfinder: {"host": "api.example.com", "source": "certsh"}
  amass:     {"name": "api.example.com", "addresses": [...]}
  httpx:     {"url": "https://api.example.com", "host": "api.example.com", ...}

Also handles plain-text output (one hostname per line).
"""

from __future__ import annotations

import json
import logging

from .base import ScanResult, Subdomain

logger = logging.getLogger("redteam.parsers.subfinder")


def parse_subfinder(stdout: str, target: str = "") -> ScanResult:
    """
    Parse subfinder/amass/httpx JSON-lines output into a ScanResult
    with typed Subdomain objects. Falls back to plain-text parsing.
    """
    subdomains: list[Subdomain] = []
    seen: set[str] = set()

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        host = ""
        ip   = ""
        source = ""

        if line.startswith("{"):
            try:
                obj = json.loads(line)
                # subfinder format
                host   = obj.get("host", "")
                # amass format
                if not host:
                    host = obj.get("name", "")
                # httpx format
                if not host:
                    host = obj.get("input", "") or obj.get("host", "")
                source = obj.get("source", "") or obj.get("sources", [""])[0] if isinstance(obj.get("sources"), list) else ""
                # IP from httpx
                ip = obj.get("host", "") if "." in obj.get("host", "") and obj.get("host", "").replace(".", "").isdigit() else ""
            except json.JSONDecodeError:
                host = line
        else:
            # Plain hostname per line
            host = line

        host = host.strip().lower().rstrip(".")
        if host and host not in seen:
            seen.add(host)
            subdomains.append(Subdomain(host=host, ip=ip, source=source))

    return ScanResult(
        tool="subfinder_enum",
        target=target,
        subdomains=subdomains,
        raw_stdout=stdout,
    )
