"""
Nuclei output parser.

Nuclei emits one JSON object per line with -json flag:
{
  "template-id": "CVE-2021-41773",
  "info": {"name": "Apache RCE", "severity": "critical"},
  "matched-at": "http://example.com/cgi-bin/test.cgi"
}
"""

from __future__ import annotations

import json
import logging

from .base import Finding, ScanResult

logger = logging.getLogger("redteam.parsers.nuclei")

_SEVERITY_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    "unknown":  "unknown",
}


def parse_nuclei(stdout: str, target: str = "") -> ScanResult:
    """
    Parse nuclei JSON-lines output into a ScanResult with typed Finding objects.
    """
    findings: list[Finding] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Skipping non-JSON nuclei line: %s", line[:80])
            continue

        info        = obj.get("info", {})
        template_id = obj.get("template-id", "")
        name        = info.get("name", template_id)
        severity    = _SEVERITY_MAP.get(info.get("severity", "").lower(), "unknown")
        matched_at  = obj.get("matched-at", "")
        description = info.get("description", "")

        if not name:
            continue

        findings.append(Finding(
            severity=severity,  # type: ignore[arg-type]
            title=name,
            description=description,
            url=matched_at,
            template_id=template_id,
        ))

    return ScanResult(tool="nuclei_scan", target=target, findings=findings, raw_stdout=stdout)
