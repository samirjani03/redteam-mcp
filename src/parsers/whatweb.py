"""
WhatWeb output parser.

WhatWeb --log-json=- emits one JSON object per URL:
[
  {
    "target": "http://example.com",
    "http_status": 200,
    "plugins": {
      "Apache": {"version": ["2.4.49"], "string": ["Apache"]},
      "PHP":    {"version": ["7.4.3"]},
      "WordPress": {}
    }
  }
]

The output is an array (one entry per redirect hop) OR a plain JSON object.
"""

from __future__ import annotations

import json
import re

from .base import Finding, ScanResult

# Technologies that indicate high-value attack surface
_HIGH_VALUE = {
    "wordpress", "drupal", "joomla", "magento", "prestashop",
    "phpbb", "mediawiki", "struts", "spring", "rails",
    "django", "laravel", "symfony",
}

_VERSION_CVE_HINTS = {
    # format: lowercase tech → list of (version_prefix, severity, note)
    "apache":     [("2.4.49", "critical", "CVE-2021-41773 Path Traversal/RCE"),
                   ("2.4.50", "critical", "CVE-2021-42013 RCE")],
    "php":        [("5.", "high", "PHP 5.x EOL — many known RCEs"),
                   ("7.0", "medium", "PHP 7.0 EOL"),
                   ("7.1", "medium", "PHP 7.1 EOL")],
    "jquery":     [("1.", "low", "jQuery 1.x XSS vulnerabilities"),
                   ("2.", "low", "jQuery 2.x XSS vulnerabilities")],
    "bootstrap":  [("3.", "info", "Bootstrap 3.x XSS in tooltip")],
    "openssl":    [("1.0", "high", "OpenSSL 1.0.x EOL")],
}


def parse_whatweb(stdout: str, target: str = "") -> ScanResult:
    """Parse WhatWeb --log-json output into typed Finding objects."""
    findings: list[Finding] = []
    techs: list[str] = []

    # WhatWeb can emit a JSON array or a single object
    try:
        raw = json.loads(stdout)
        if isinstance(raw, dict):
            raw = [raw]
    except json.JSONDecodeError:
        # Fallback: try line-by-line JSON
        raw = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("{") or line.startswith("["):
                try:
                    raw.extend(json.loads(line) if line.startswith("[") else [json.loads(line)])
                except json.JSONDecodeError:
                    pass

    for entry in raw:
        if not isinstance(entry, dict):
            continue
        plugins: dict = entry.get("plugins", {})
        url: str = entry.get("target", target)

        for tech_name, tech_data in plugins.items():
            versions: list[str] = tech_data.get("version", []) if isinstance(tech_data, dict) else []
            version_str = ", ".join(versions) if versions else ""
            tech_label = f"{tech_name}" + (f" {version_str}" if version_str else "")
            techs.append(tech_label)

            # Version-specific CVE hints
            tech_lower = tech_name.lower()
            hints = _VERSION_CVE_HINTS.get(tech_lower, [])
            for ver_prefix, sev, note in hints:
                for v in versions:
                    if v.startswith(ver_prefix):
                        findings.append(Finding(
                            severity=sev,
                            title=f"{tech_name} {v} — {note}",
                            description=f"Detected {tech_name} version {v} on {url}. {note}",
                            url=url,
                        ))

            # Flag high-value CMS/frameworks
            if tech_lower in _HIGH_VALUE:
                findings.append(Finding(
                    severity="medium",
                    title=f"CMS/Framework detected: {tech_label}",
                    description=f"{tech_name} detected on {url}. Target for CMS-specific vuln scanning.",
                    url=url,
                ))

    # Attach technology list as an info finding for the report
    if techs:
        findings.append(Finding(
            severity="info",
            title=f"Technologies: {', '.join(techs[:15])}",
            description="Full technology fingerprint from WhatWeb.",
            url=target,
        ))

    return ScanResult(tool="whatweb_scan", target=target,
                      findings=findings, raw_stdout=stdout)
