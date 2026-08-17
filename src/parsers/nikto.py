"""
Nikto output parser.

Nikto plain-text output lines look like:
  + Server: Apache/2.4.49 (Unix)
  + /: The anti-clickjacking X-Frame-Options header is not present.
  + OSVDB-3233: /icons/: Directory indexing found.
  + /admin/: This might be interesting.

Nikto also supports -Format json:
  {"host": "...", "ip": "...", "vulnerabilities": [{"id": "...", "method": "GET", "description": "..."}]}
"""

from __future__ import annotations

import json
import re

from .base import Finding, ScanResult

# Map common OSVDB/keyword patterns to severity
_HIGH_PATTERNS = re.compile(
    r"(sql\s*inject|remote\s*code|RCE|command\s*inject|path\s*traversal|"
    r"directory\s*traversal|LFI|RFI|upload|webshell|OSVDB-397|shellshock)",
    re.IGNORECASE,
)
_MEDIUM_PATTERNS = re.compile(
    r"(OSVDB|XSS|cross.site|csrf|clickjack|x-frame|x-content-type|"
    r"default\s+password|default\s+login|admin|backup|config|\.bak|\.swp)",
    re.IGNORECASE,
)
_LOW_PATTERNS = re.compile(
    r"(server\s+banner|version\s+disclosure|index\s+of|directory\s+listing)",
    re.IGNORECASE,
)


def _classify(text: str) -> str:
    if _HIGH_PATTERNS.search(text):
        return "high"
    if _MEDIUM_PATTERNS.search(text):
        return "medium"
    if _LOW_PATTERNS.search(text):
        return "low"
    return "info"


def parse_nikto(stdout: str, target: str = "") -> ScanResult:
    """Parse nikto plain-text or JSON output into typed Finding objects."""
    findings: list[Finding] = []

    # ── Try JSON first (-Format json) ───────────────────────────────── #
    try:
        data = json.loads(stdout)
        vulns = data.get("vulnerabilities", [])
        if isinstance(vulns, list):
            for v in vulns:
                desc = v.get("description", "") or v.get("msg", "")
                url  = v.get("url", "") or v.get("uri", "")
                severity = _classify(desc)
                findings.append(Finding(
                    severity=severity,
                    title=desc[:120],
                    description=desc,
                    url=(target.rstrip("/") + url) if url else target,
                ))
            return ScanResult(tool="nikto_scan", target=target,
                              findings=findings, raw_stdout=stdout)
    except (json.JSONDecodeError, AttributeError):
        pass

    # ── Plain-text ───────────────────────────────────────────────────── #
    for line in stdout.splitlines():
        line = line.strip()
        # Lines starting with "+ " are findings
        if not line.startswith("+ "):
            continue
        content = line[2:].strip()
        if not content:
            continue
        # Skip header/footer boilerplate
        if content.startswith("Target IP") or content.startswith("Start Time") or \
           content.startswith("End Time") or content.startswith("1 host"):
            continue
        severity = _classify(content)
        # Extract URL from content if present (after ": " or at start)
        url = ""
        m = re.match(r"^(/[^\s:]+)", content)
        if m:
            url = (target.rstrip("/") + m.group(1)) if target else m.group(1)
        findings.append(Finding(
            severity=severity,
            title=content[:120],
            description=content,
            url=url,
        ))

    return ScanResult(tool="nikto_scan", target=target,
                      findings=findings, raw_stdout=stdout)
