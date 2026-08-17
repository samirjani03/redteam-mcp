"""
Nmap output parser.

Parses nmap's plain-text (-oN) output into typed Port objects.
Example input line:
  80/tcp   open  http    Apache httpd 2.4.49
  22/tcp   open  ssh     OpenSSH 8.2p1
"""

from __future__ import annotations

import re

from .base import Port, ScanResult


def parse_nmap(stdout: str, target: str = "") -> ScanResult:
    """
    Parse nmap plain-text stdout into a ScanResult with typed Port objects.
    """
    ports: list[Port] = []

    for line in stdout.splitlines():
        line = line.strip()
        # Match: 80/tcp   open  http    Apache httpd 2.4.49
        m = re.match(
            r"^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)(?:\s+(.*))?$",
            line,
            re.IGNORECASE,
        )
        if not m:
            continue

        port_num  = int(m.group(1))
        protocol  = m.group(2).lower()
        state     = m.group(3).lower()
        service   = m.group(4).lower()
        version   = (m.group(5) or "").strip()

        # Only include open/open|filtered ports
        if "open" not in state:
            continue

        ports.append(Port(
            port=port_num,
            protocol=protocol,  # type: ignore[arg-type]
            state=state,
            service=service,
            version=version,
        ))

    return ScanResult(tool="nmap_scan", target=target, ports=ports, raw_stdout=stdout)
