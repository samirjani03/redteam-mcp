"""
CVE Matcher — cross-reference nmap service versions against the CVE database.

Given a list of Port objects from parse_nmap(), queries CveStore for each
service/version combination and enriches the ScanResult with typed Finding
objects that contain CVE IDs, CVSS scores, and descriptions.

This runs automatically inside the agent loop when nmap discovers services
with version information (-sV flag).

Usage:
    from parsers.cve_matcher import enrich_with_cves

    scan = parse_nmap(stdout, target)
    scan = await enrich_with_cves(scan, cve_store)
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from parsers.base import Finding, Port, ScanResult

if TYPE_CHECKING:
    from memory.cve_store import CveStore

logger = logging.getLogger("redteam.cve_matcher")


# ---------------------------------------------------------------------------
# Service name normalisation map
# Maps nmap service names → NVD/CPE vendor strings
# ---------------------------------------------------------------------------

_SERVICE_VENDOR_MAP: dict[str, str] = {
    # Web servers
    "http":         "apache",
    "https":        "apache",
    "http-alt":     "apache",
    "ssl/http":     "apache",
    # SSH
    "ssh":          "openssh",
    # FTP
    "ftp":          "vsftpd",
    # Mail
    "smtp":         "postfix",
    "pop3":         "dovecot",
    "imap":         "dovecot",
    # Database
    "mysql":        "mysql",
    "postgresql":   "postgresql",
    "ms-sql-s":     "microsoft:sql_server",
    "oracle":       "oracle",
    "redis":        "redis",
    "mongodb":      "mongodb",
    # Other
    "smb":          "microsoft:windows",
    "netbios-ssn":  "microsoft:windows",
    "rdp":          "microsoft:windows",
    "vnc":          "realvnc",
    "telnet":       "telnet",
    "dns":          "isc:bind",
    "ldap":         "openldap",
    "nfs":          "sun:nfs",
}

# Regex to extract version number from nmap version string
# e.g. "Apache httpd 2.4.49" → "2.4.49"
#       "OpenSSH 8.2p1"       → "8.2"
_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)")


def _extract_version(version_str: str) -> str:
    """Pull the first version number from a nmap version string."""
    m = _VERSION_RE.search(version_str)
    return m.group(1) if m else ""


def _extract_vendor_product(port: Port) -> tuple[str, str]:
    """
    Derive a (vendor, product) pair from a Port's service + version fields.
    Returns ("", "") if we can't determine a vendor.
    """
    svc = port.service.lower().strip()
    ver = port.version

    # Try to get product name from version string (first word usually is product)
    # e.g. "Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1l)"
    # → product = "apache httpd"
    product = ""
    if ver:
        # Strip parenthetical extras
        ver_clean = re.sub(r"\s*\(.*?\)", "", ver).strip()
        words = ver_clean.split()
        if len(words) >= 2:
            product = f"{words[0].lower()} {words[1].lower()}"
        elif words:
            product = words[0].lower()

    # Map service to vendor
    vendor = _SERVICE_VENDOR_MAP.get(svc, svc)

    # Special handling for nginx/apache explicit in version string
    if "nginx" in ver.lower():
        vendor, product = "nginx", "nginx"
    elif "apache" in ver.lower():
        vendor, product = "apache", "http_server"
    elif "openssh" in ver.lower():
        vendor, product = "openssh", "openssh"
    elif "mysql" in ver.lower():
        vendor, product = "oracle", "mysql"
    elif "iis" in ver.lower():
        vendor, product = "microsoft", "iis"

    return vendor, product


async def enrich_with_cves(scan: ScanResult, store: "CveStore", max_per_port: int = 5) -> ScanResult:
    """
    Query the CVE database for each open port with version info and add
    matched CVEs as Finding objects to the ScanResult.

    Args:
        scan:         ScanResult from parse_nmap() (must have ports with versions)
        store:        Initialised CveStore instance
        max_per_port: Max CVEs to attach per port (avoids flooding)

    Returns:
        The same ScanResult with additional Finding objects appended.
    """
    if not scan.ports:
        return scan

    tasks = [
        _lookup_port(port, store, max_per_port)
        for port in scan.ports
        if port.version  # only ports with version info
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            scan.findings.extend(result)
        elif isinstance(result, Exception):
            logger.debug("CVE lookup error: %s", result)

    if scan.findings:
        # Sort by severity: critical first
        _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        scan.findings.sort(key=lambda f: _sev_order.get(f.severity, 5))

    return scan


async def _lookup_port(port: Port, store: "CveStore", limit: int) -> list[Finding]:
    """Run CVE lookup for a single port and return Finding objects."""
    vendor, product = _extract_vendor_product(port)
    version = _extract_version(port.version)

    if not vendor:
        return []

    query = f"{vendor} {product} {version}".strip()
    logger.debug("CVE lookup: port=%s service=%s query=%r", port.port, port.service, query)

    try:
        cves = await store.for_service(vendor, version=version, limit=limit)
    except Exception as exc:
        logger.warning("CVE query failed for %s: %s", query, exc)
        return []

    findings: list[Finding] = []
    for cve in cves:
        severity = cve.get("severity", "unknown")
        if severity not in ("critical", "high", "medium", "low", "info", "unknown"):
            severity = "unknown"
        findings.append(Finding(
            severity=severity,
            title=f"{cve['cve_id']} — {port.service} {version} (CVSS {cve['cvss_score']:.1f})",
            description=cve.get("description", ""),
            url=f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}",
            template_id=cve["cve_id"],
        ))

    return findings


def quick_match(service: str, version: str) -> list[dict]:
    """
    Synchronous offline match using known high-profile CVEs.
    Used as a fallback when the CVE database hasn't been synced yet.

    Returns a list of minimal CVE dicts.
    """
    findings: list[dict] = []
    ver = version.lower()
    svc = service.lower()

    # Hard-coded known critical CVEs for common services
    known = [
        # Apache
        {"svc": "http", "ver_prefix": "2.4.49", "cve": "CVE-2021-41773", "score": 9.8,
         "sev": "critical", "desc": "Apache 2.4.49 Path Traversal / RCE (no auth required)"},
        {"svc": "http", "ver_prefix": "2.4.50", "cve": "CVE-2021-42013", "score": 9.8,
         "sev": "critical", "desc": "Apache 2.4.50 RCE via mod_cgi"},
        # Log4Shell
        {"svc": "",     "ver_prefix": "2.0",    "cve": "CVE-2021-44228", "score": 10.0,
         "sev": "critical", "desc": "Log4Shell — Log4j 2.0-2.14.1 RCE via JNDI injection"},
        # OpenSSH
        {"svc": "ssh",  "ver_prefix": "7.",      "cve": "CVE-2023-38408", "score": 9.8,
         "sev": "critical", "desc": "OpenSSH 7.x ssh-agent remote code execution"},
        # ProxyShell
        {"svc": "https","ver_prefix": "",         "cve": "CVE-2021-34473", "score": 9.8,
         "sev": "critical", "desc": "Microsoft Exchange ProxyShell RCE"},
        # vsftpd backdoor
        {"svc": "ftp",  "ver_prefix": "2.3.4",   "cve": "CVE-2011-2523", "score": 10.0,
         "sev": "critical", "desc": "vsftpd 2.3.4 backdoor command execution"},
        # Shellshock
        {"svc": "http", "ver_prefix": "",         "cve": "CVE-2014-6271", "score": 10.0,
         "sev": "critical", "desc": "Shellshock — bash remote code execution via env variable"},
        # EternalBlue
        {"svc": "smb",  "ver_prefix": "",         "cve": "CVE-2017-0144", "score": 9.8,
         "sev": "critical", "desc": "EternalBlue — SMBv1 remote code execution (WannaCry)"},
    ]

    for entry in known:
        if entry["svc"] and entry["svc"] not in svc:
            continue
        if entry["ver_prefix"] and not ver.startswith(entry["ver_prefix"]):
            continue
        findings.append({
            "cve_id":      entry["cve"],
            "severity":    entry["sev"],
            "cvss_score":  entry["score"],
            "description": entry["desc"],
            "products":    [],
            "published":   "",
        })

    return findings
