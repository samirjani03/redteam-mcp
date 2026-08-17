"""
Security layer: audit logging + target allowlist + rate limiting.

Every tool call in server.py runs through validate_target() before
executing and logs to AuditLog after returning.

Configuration via environment variables:
  REDTEAM_ALLOWED_TARGETS   Comma-separated IPs/CIDRs/domains that are
                            permitted targets. If empty, all targets are
                            allowed (useful for CTF/lab environments).
  REDTEAM_AUDIT_LOG         Path to the audit log file.
                            Default: /app/data/audit.log
  REDTEAM_RATE_LIMIT        Max tool calls per minute (0 = unlimited).
                            Default: 0
"""

from __future__ import annotations

import collections
import ipaddress
import json
import logging
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("redteam.security")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_ALLOWED_TARGETS_ENV = os.getenv("REDTEAM_ALLOWED_TARGETS", "")
_AUDIT_LOG_PATH = Path(os.getenv("REDTEAM_AUDIT_LOG", "/app/data/audit.log"))
_RATE_LIMIT = int(os.getenv("REDTEAM_RATE_LIMIT", "0"))   # calls/min; 0 = unlimited

# Parse allowed targets once at module load
_ALLOWED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_ALLOWED_DOMAINS:  list[str] = []

if _ALLOWED_TARGETS_ENV:
    for entry in _ALLOWED_TARGETS_ENV.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            _ALLOWED_NETWORKS.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            # Not an IP/CIDR — treat as domain pattern
            _ALLOWED_DOMAINS.append(entry.lower())


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class AuditLog:
    """
    Append-only JSONL audit log for every tool call.

    Usage:
        audit = AuditLog()
        audit.log("nmap_scan", target="192.168.1.1", args={"ports": "80"}, result_code=0)
    """

    def __init__(self, path: Path = _AUDIT_LOG_PATH) -> None:
        self.path = path

    def log(
        self,
        tool: str,
        target: str = "",
        args: dict[str, Any] | None = None,
        result_code: int = 0,
        error: str = "",
    ) -> None:
        """Append a single audit record to the log file."""
        record = {
            "ts":     datetime.now(timezone.utc).isoformat(),
            "tool":   tool,
            "target": target,
            "args":   args or {},
            "rc":     result_code,
        }
        if error:
            record["error"] = error

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError as exc:
            # Never let audit failure break a tool call
            logger.warning("Audit log write failed: %s", exc)


# Module-level singleton used by server.py
_audit = AuditLog()


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimitError(RuntimeError):
    """Raised when the caller exceeds the configured tool-call rate."""


class _RateLimiter:
    """
    Simple sliding-window rate limiter.
    Tracks timestamps of recent calls; rejects if count > limit within window.
    """

    def __init__(self, max_calls: int = 0, window_seconds: int = 60) -> None:
        self.max_calls = max_calls          # 0 = disabled
        self.window    = window_seconds
        self._calls: collections.deque[float] = collections.deque()

    def check(self) -> None:
        """Raise RateLimitError if rate is exceeded; otherwise record this call."""
        if not self.max_calls:
            return   # rate limiting disabled

        now = time.monotonic()
        cutoff = now - self.window

        # Remove timestamps older than the window
        while self._calls and self._calls[0] < cutoff:
            self._calls.popleft()

        if len(self._calls) >= self.max_calls:
            wait = round(self._calls[0] - cutoff, 1)
            raise RateLimitError(
                f"Rate limit exceeded: max {self.max_calls} calls/"
                f"{self.window}s. Try again in ~{wait}s."
            )

        self._calls.append(now)


_rate_limiter = _RateLimiter(max_calls=_RATE_LIMIT)


def log_tool_call(
    tool: str,
    target: str = "",
    args: dict[str, Any] | None = None,
    result_code: int = 0,
    error: str = "",
) -> None:
    """Convenience wrapper — use this in server.py tool functions."""
    _audit.log(tool, target=target, args=args, result_code=result_code, error=error)


# ---------------------------------------------------------------------------
# Target allowlist validation
# ---------------------------------------------------------------------------

class TargetNotAllowedError(ValueError):
    """Raised when a target is not in the allowlist."""


def validate_target(target: str, tool: str = "") -> None:
    """
    Validate that `target` is permitted.

    - If REDTEAM_ALLOWED_TARGETS is empty → all targets allowed (open lab mode).
    - If set → target must match one of the IPs/CIDRs/domains in the list.

    Raises TargetNotAllowedError if rejected.
    """
    if not _ALLOWED_TARGETS_ENV:
        # No restrictions configured — allow everything
        return

    target_clean = target.strip().split(":")[0]  # strip port if present

    # Try as IP address
    try:
        addr = ipaddress.ip_address(target_clean)
        for net in _ALLOWED_NETWORKS:
            if addr in net:
                return
        # IP not in any allowed network
        raise TargetNotAllowedError(
            f"Target '{target}' is not in REDTEAM_ALLOWED_TARGETS. "
            "Set the env var to permit this target."
        )
    except ValueError:
        pass  # not an IP — fall through to domain check

    # Try as hostname/domain
    target_lower = target_clean.lower()
    for allowed in _ALLOWED_DOMAINS:
        # Exact match or subdomain match
        if target_lower == allowed or target_lower.endswith("." + allowed):
            return

    # Try resolving the hostname and check the resulting IP
    try:
        resolved_ip = ipaddress.ip_address(socket.gethostbyname(target_clean))
        for net in _ALLOWED_NETWORKS:
            if resolved_ip in net:
                return
    except (socket.gaierror, ValueError):
        pass

    raise TargetNotAllowedError(
        f"Target '{target}' is not in REDTEAM_ALLOWED_TARGETS. "
        "Set the env var or add the target to permit it."
    )


# ---------------------------------------------------------------------------
# Decorator for server.py tool functions
# ---------------------------------------------------------------------------

def guarded(tool_name: str):
    """
    Decorator factory.  Use on MCP tool functions that accept a `target` arg:

        @mcp.tool()
        @guarded("nmap_scan")
        async def nmap_scan(target: str, ...) -> str:
            ...

    Validates target allowlist and writes an audit record before + after.
    """
    import functools

    def decorator(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            # ── Rate limit ─────────────────────────────────────────────
            try:
                _rate_limiter.check()
            except RateLimitError as exc:
                return json.dumps({"error": str(exc), "tool": tool_name})

            # Extract target from args or kwargs
            target = kwargs.get("target") or kwargs.get("url") or \
                     kwargs.get("host") or kwargs.get("domain") or \
                     (args[0] if args else "")

            try:
                validate_target(str(target), tool=tool_name)
            except TargetNotAllowedError as exc:
                log_tool_call(tool_name, target=str(target), error=str(exc))
                return json.dumps({"error": str(exc), "tool": tool_name})

            result = await fn(*args, **kwargs)

            # Parse returncode from JSON result if possible
            rc = 0
            try:
                rc = json.loads(result).get("returncode", 0)
            except Exception:
                pass

            log_tool_call(tool_name, target=str(target),
                          args={**kwargs}, result_code=rc)
            return result

        return wrapper
    return decorator
