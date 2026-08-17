"""
Shell executor and output formatter.

Provides:
  run_shell(cmd, timeout)  — async subprocess runner
  fmt_output(result, tool) — truncate + format for LLM context
  execute_tool(name, args) — dynamically call a tool from server.py
"""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import os
import sys
from typing import Any

logger = logging.getLogger("redteam.executor")

# Max stdout chars fed to the LLM — prevents context window saturation
_MAX_STDOUT = 8_000


async def run_shell(cmd: str, timeout: int = 120) -> dict:
    """
    Execute a shell command inside the Kali container and return
    {"stdout": str, "stderr": str, "returncode": int}.
    """
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return {"stdout": "", "stderr": f"Timed out after {timeout}s", "returncode": -1}

    return {
        "stdout": stdout.decode(errors="replace").strip(),
        "stderr": stderr.decode(errors="replace").strip(),
        "returncode": proc.returncode,
    }


def fmt_output(result: dict, tool: str) -> str:
    """
    Format a shell result dict as a JSON string safe to return to the LLM.
    Truncates stdout to _MAX_STDOUT chars to avoid context overflow.
    """
    stdout = result.get("stdout", "")
    original_len = len(stdout)
    if original_len > _MAX_STDOUT:
        stdout = stdout[:_MAX_STDOUT] + f"\n... [truncated — {original_len} total chars]"

    return json.dumps({
        "tool": tool,
        "stdout": stdout,
        "stderr": result.get("stderr", "")[:2_000],
        "returncode": result.get("returncode"),
    })


async def execute_tool(tool_name: str, args: dict[str, Any]) -> str:
    """
    Dynamically call a tool function defined in server.py.

    server.py registers tools as plain async functions decorated with
    @mcp.tool() — they are still importable and callable directly, which
    lets the agent invoke them without going through the MCP transport.
    """
    src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    try:
        server_mod = importlib.import_module("server")
        func = getattr(server_mod, tool_name, None)
        if func is None:
            return json.dumps({"error": f"Tool '{tool_name}' not found in server.py"})
        return await func(**args)
    except Exception as exc:
        logger.exception("execute_tool failed: %s(%s)", tool_name, args)
        return json.dumps({"error": str(exc)})
