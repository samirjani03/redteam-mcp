"""
Gobuster / ffuf output parser.

Gobuster plain-text output (dir mode):
  /admin                (Status: 200) [Size: 1234]
  /login                (Status: 301) [Size: 0] [--> /login/]

ffuf JSON output (with -json flag):
  {"results": [{"url": "http://...", "status": 200, "length": 1234, "words": 10, ...}]}
"""

from __future__ import annotations

import json
import re

from .base import Finding, ScanResult


def parse_gobuster(stdout: str, target: str = "") -> ScanResult:
    """Parse gobuster dir or ffuf -json output into typed Finding objects."""
    findings: list[Finding] = []

    # ── Try ffuf JSON first ──────────────────────────────────────────── #
    try:
        data = json.loads(stdout)
        results = data.get("results", [])
        if isinstance(results, list):
            for r in results:
                url    = r.get("url", "")
                status = r.get("status", 0)
                size   = r.get("length", 0)
                severity = _status_to_severity(status)
                findings.append(Finding(
                    severity=severity,
                    title=f"HTTP {status} — {url}",
                    description=f"Size: {size} bytes",
                    url=url,
                ))
            return ScanResult(tool="gobuster_dir", target=target,
                              findings=findings, raw_stdout=stdout)
    except (json.JSONDecodeError, AttributeError):
        pass

    # ── Gobuster plain-text ──────────────────────────────────────────── #
    # Pattern: /path  (Status: 200) [Size: 1234] [--> redirect]
    pat = re.compile(
        r"^(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\](?:\s+\[-->\s*(\S+)\])?",
        re.IGNORECASE,
    )
    for line in stdout.splitlines():
        m = pat.match(line.strip())
        if not m:
            continue
        path     = m.group(1)
        status   = int(m.group(2))
        size     = m.group(3)
        redirect = m.group(4) or ""
        severity = _status_to_severity(status)
        desc = f"Size: {size} bytes"
        if redirect:
            desc += f" → {redirect}"
        url = (target.rstrip("/") + path) if target else path
        findings.append(Finding(
            severity=severity,
            title=f"HTTP {status} — {path}",
            description=desc,
            url=url,
        ))

    return ScanResult(tool="gobuster_dir", target=target,
                      findings=findings, raw_stdout=stdout)


def _status_to_severity(status: int) -> str:
    if status in (200, 201, 204):
        return "medium"
    if status in (301, 302, 307, 308):
        return "info"
    if status in (401, 403):
        return "low"
    if status == 500:
        return "high"
    return "info"
