"""
httpx probe output parser.

httpx -json emits one JSON object per line:
{
  "url": "https://api.example.com",
  "input": "api.example.com",
  "status-code": 200,
  "title": "API Dashboard",
  "webserver": "nginx/1.18",
  "tech": ["Bootstrap:4.6.0", "jQuery:3.5.1"],
  "content-length": 4321,
  "host": "1.2.3.4"
}
"""

from __future__ import annotations

import json

from .base import Finding, ScanResult, Subdomain


def parse_httpx(stdout: str, target: str = "") -> ScanResult:
    """
    Parse httpx -json output into a ScanResult with:
    - Subdomains (live hosts)
    - Findings (interesting status codes, server versions, technologies)
    """
    subdomains: list[Subdomain] = []
    findings: list[Finding] = []
    seen_hosts: set[str] = set()

    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        url    = obj.get("url", "")
        host   = obj.get("input", "") or obj.get("host", "")
        status = obj.get("status-code", 0)
        title  = obj.get("title", "")
        server = obj.get("webserver", "") or obj.get("server", "")
        techs  = obj.get("tech", []) or obj.get("technologies", [])
        ip     = obj.get("host", "") if "." in obj.get("host", "") else ""

        # Track as live subdomain
        clean_host = host.strip().lower().rstrip(".")
        if clean_host and clean_host not in seen_hosts:
            seen_hosts.add(clean_host)
            subdomains.append(Subdomain(host=clean_host, ip=ip, source="httpx"))

        # Live host finding
        tech_str = ", ".join(techs[:8]) if techs else ""
        desc = f"Status {status}"
        if title:
            desc += f' | Title: "{title}"'
        if server:
            desc += f" | Server: {server}"
        if tech_str:
            desc += f" | Tech: {tech_str}"

        severity = _status_severity(status)
        findings.append(Finding(
            severity=severity,
            title=f"Live: {url or host} [{status}]",
            description=desc,
            url=url,
        ))

        # Flag interesting server headers for version disclosure
        if server:
            findings.append(Finding(
                severity="info",
                title=f"Server header: {server}",
                description=f"Version disclosure via Server header on {url}",
                url=url,
            ))

    return ScanResult(
        tool="httpx_probe",
        target=target,
        subdomains=subdomains,
        findings=findings,
        raw_stdout=stdout,
    )


def _status_severity(status: int) -> str:
    if status == 200:
        return "info"
    if status in (401, 403):
        return "low"
    if status == 500:
        return "medium"
    if status in (301, 302):
        return "info"
    return "info"
