"""
Base Pydantic models for typed, structured tool output.

All parsers return a ScanResult containing lists of typed findings
instead of raw text — this is what gets stored in memory and fed
back to the LLM as a structured summary.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class Port(BaseModel):
    """A single open port discovered by nmap."""
    port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""

    def __str__(self) -> str:
        svc = f" {self.service}" if self.service else ""
        ver = f" ({self.version})" if self.version else ""
        return f"{self.port}/{self.protocol}{svc}{ver}"


class Subdomain(BaseModel):
    """A discovered subdomain/host."""
    host: str
    ip: str = ""
    source: str = ""

    def __str__(self) -> str:
        return self.host


class Finding(BaseModel):
    """A vulnerability or notable security finding."""
    severity: Literal["critical", "high", "medium", "low", "info", "unknown"] = "unknown"
    title: str
    description: str = ""
    url: str = ""
    template_id: str = ""

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.title}"


class ScanResult(BaseModel):
    """
    Normalised output from any single tool run.
    Stored in memory, fed as structured summaries to the LLM.
    """
    tool: str
    target: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ports: list[Port] = []
    subdomains: list[Subdomain] = []
    findings: list[Finding] = []
    raw_stdout: str = ""
    returncode: int = 0

    @property
    def summary(self) -> str:
        """One-line human-readable summary of the scan result."""
        parts: list[str] = [f"[{self.tool}] target={self.target}"]
        if self.ports:
            parts.append(f"{len(self.ports)} open ports: {', '.join(str(p) for p in self.ports[:10])}")
        if self.subdomains:
            parts.append(f"{len(self.subdomains)} subdomains found")
        if self.findings:
            crit = sum(1 for f in self.findings if f.severity in ("critical", "high"))
            parts.append(f"{len(self.findings)} findings ({crit} high/critical)")
        if not (self.ports or self.subdomains or self.findings):
            preview = self.raw_stdout[:200].replace("\n", " ")
            parts.append(f"output: {preview}")
        return " | ".join(parts)
