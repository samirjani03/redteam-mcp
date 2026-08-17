"""
PentestAgent — the Ollama-powered agentic loop.

Flow:
  1. Receive a natural-language goal.
  2. Send goal + conversation history to Ollama.
  3. Parse the JSON action from the model's reply.
  4. Execute the requested tool via tools.executor.execute_tool().
  5. Parse tool output into a typed ScanResult.
  6. Persist the result to memory (if store is provided).
  7. Feed the structured summary back to the model.
  8. Repeat until the model says "done" or MAX_STEPS is reached.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
from typing import Any

import ollama
from pydantic import BaseModel

from tools.registry import TOOL_REGISTRY
from tools.executor import execute_tool
from parsers import parse_nmap, parse_nuclei, parse_subfinder
from parsers import parse_gobuster, parse_nikto, parse_whatweb, parse_httpx
from parsers.base import ScanResult
from agent.prompts import build_system_prompt

logger = logging.getLogger("redteam.agent")

# ---------------------------------------------------------------------------
# Config (read at import time; can be overridden via env before import)
# ---------------------------------------------------------------------------

OLLAMA_HOST: str  = os.getenv("OLLAMA_HOST",      "https://api.ollama.com")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL",      "minimax-m3:cloud")
OLLAMA_API_KEY: str = os.getenv("OLLAMA_API_KEY",  "")
MAX_STEPS: int    = int(os.getenv("MAX_AGENT_STEPS", "20"))


# ---------------------------------------------------------------------------
# Public Pydantic models (re-exported by src/agent/__init__.py)
# ---------------------------------------------------------------------------

class ToolCall(BaseModel):
    tool: str
    args: dict[str, Any]
    reason: str


class AgentStep(BaseModel):
    step: int
    tool_call: ToolCall
    raw_output: str
    summary: str
    found_ports: list[str] = []
    found_subdomains: list[str] = []
    found_vulns: list[str] = []


class AgentResult(BaseModel):
    goal: str
    model: str
    steps_taken: int
    steps: list[AgentStep]
    final_summary: str


# ---------------------------------------------------------------------------
# Ollama client factory
# ---------------------------------------------------------------------------

def _make_client() -> ollama.Client:
    kwargs: dict[str, Any] = {"host": OLLAMA_HOST}
    if OLLAMA_API_KEY:
        kwargs["headers"] = {"Authorization": f"Bearer {OLLAMA_API_KEY}"}
    return ollama.Client(**kwargs)


# ---------------------------------------------------------------------------
# Output post-processing — dispatch to the right typed parser
# ---------------------------------------------------------------------------

def _parse_output(tool_name: str, raw: str) -> ScanResult:
    """
    Route raw tool output to the appropriate typed parser.
    Falls back to a bare ScanResult for unrecognised tools.
    """
    try:
        data = json.loads(raw)
        stdout = data.get("stdout", raw)
        rc = data.get("returncode", 0)
    except Exception:
        stdout = raw
        rc = 0

    target = ""  # target not available here; enriched later if needed

    if tool_name == "nmap_scan":
        result = parse_nmap(stdout, target)
        # CVE enrichment happens after _parse_output returns (in the async run() method)
    elif tool_name == "nuclei_scan":
        result = parse_nuclei(stdout, target)
    elif tool_name in ("subfinder_enum", "amass_enum"):
        result = parse_subfinder(stdout, target)
    elif tool_name == "httpx_probe":
        result = parse_httpx(stdout, target)
    elif tool_name in ("gobuster_dir", "ffuf_fuzz"):
        result = parse_gobuster(stdout, target)
    elif tool_name == "nikto_scan":
        result = parse_nikto(stdout, target)
    elif tool_name == "whatweb_scan":
        result = parse_whatweb(stdout, target)
    else:
        result = ScanResult(tool=tool_name, target=target, raw_stdout=stdout, returncode=rc)

    result.returncode = rc
    return result


# ---------------------------------------------------------------------------
# Main agent class
# ---------------------------------------------------------------------------

class PentestAgent:
    """
    Stateful agentic loop. One instance per user request.

    Args:
        model:  Ollama model name (defaults to OLLAMA_MODEL env var)
        store:  Optional MemoryStore instance for persistence
    """

    def __init__(
        self,
        model: str = OLLAMA_MODEL,
        store: Any | None = None,   # MemoryStore | None — avoid circular import
    ) -> None:
        self.model = model
        self.store = store
        self.client = _make_client()
        self.messages: list[dict] = []
        self.steps: list[AgentStep] = []
        self._system_prompt = build_system_prompt()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _parse_action(self, text: str) -> dict | None:
        """Extract a JSON action block from the model's reply."""
        # Prefer ```json … ``` fenced block
        m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        # Fallback: first bare { … }
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
        return None

    def _chat(self, user_message: str) -> str:
        """Append user message, call Ollama, return assistant reply."""
        self.messages.append({"role": "user", "content": user_message})
        response = self.client.chat(
            model=self.model,
            messages=[{"role": "system", "content": self._system_prompt}]
            + self.messages,
        )
        reply: str = response.message.content
        self.messages.append({"role": "assistant", "content": reply})
        return reply

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def run(self, goal: str) -> AgentResult:
        """
        Run the agentic loop for the given natural-language goal.
        Returns a fully structured AgentResult.
        """
        logger.info("Agent starting | model=%s | goal=%s", self.model, goal)
        self.messages = []
        self.steps = []

        reply = self._chat(
            f"Security testing goal: {goal}\n\nBegin planning and executing."
        )

        for step_num in range(1, MAX_STEPS + 1):
            logger.info("Step %d/%d", step_num, MAX_STEPS)

            action = self._parse_action(reply)
            if action is None:
                logger.warning("Could not parse JSON action — asking model to retry")
                reply = self._chat(
                    "I could not parse your response as valid JSON. "
                    "Please respond with ONLY the JSON action block, no prose."
                )
                continue

            # ── Done ──────────────────────────────────────────────────── #
            if action.get("action") == "done":
                logger.info("Agent done at step %d", step_num)
                return AgentResult(
                    goal=goal,
                    model=self.model,
                    steps_taken=len(self.steps),
                    steps=self.steps,
                    final_summary=action.get("summary", "No summary provided."),
                )

            # ── Validate ──────────────────────────────────────────────── #
            if action.get("action") != "call_tool":
                reply = self._chat("Invalid action. Use 'call_tool' or 'done'.")
                continue

            tool_name = action.get("tool", "")
            tool_args = {k: v for k, v in action.get("args", {}).items() if v is not None}
            reason    = action.get("reason", "")

            if tool_name not in TOOL_REGISTRY:
                reply = self._chat(
                    f"Tool '{tool_name}' does not exist. "
                    f"Available: {', '.join(TOOL_REGISTRY)}"
                )
                continue

            # ── Execute ───────────────────────────────────────────────── #
            logger.info("Calling %s(%s) — %s", tool_name, tool_args, reason)
            raw_output = await execute_tool(tool_name, tool_args)

            # ── Parse ─────────────────────────────────────────────────── #
            scan = _parse_output(tool_name, raw_output)

            # ── CVE enrichment (nmap only, async) ─────────────────────── #
            if tool_name == "nmap_scan" and scan.ports:
                try:
                    from memory.cve_store import CveStore
                    from parsers.cve_matcher import enrich_with_cves, quick_match
                    from parsers.base import Finding
                    cve_store = CveStore()
                    await cve_store.init()
                    try:
                        stats_data = await cve_store.stats()
                        if stats_data["total_cves"] > 0:
                            scan = await enrich_with_cves(scan, cve_store)
                        else:
                            # Offline fallback — hard-coded known criticals
                            for port in scan.ports:
                                if port.version:
                                    for cve in quick_match(port.service, port.version):
                                        scan.findings.append(Finding(
                                            severity=cve["severity"],
                                            title=f"{cve['cve_id']} — {port.service} {port.version}",
                                            description=cve["description"],
                                            url=f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}",
                                            template_id=cve["cve_id"],
                                        ))
                    finally:
                        await cve_store.close()
                except Exception as _cve_exc:
                    logger.debug("CVE enrichment skipped: %s", _cve_exc)

            step = AgentStep(
                step=step_num,
                tool_call=ToolCall(tool=tool_name, args=tool_args, reason=reason),
                raw_output=raw_output,
                summary=scan.summary,
                found_ports=[str(p) for p in scan.ports],
                found_subdomains=[str(s) for s in scan.subdomains],
                found_vulns=[str(f) for f in scan.findings],
            )
            self.steps.append(step)

            # ── Persist ───────────────────────────────────────────────── #
            if self.store is not None:
                try:
                    await self.store.save_scan(goal, scan)
                except Exception:
                    logger.warning("Memory store save failed — continuing without persistence")

            # ── Feed summary back to model ─────────────────────────────── #
            try:
                parsed_data = json.loads(raw_output)
                stdout_preview = parsed_data.get("stdout", raw_output)[:2_000]
            except Exception:
                stdout_preview = raw_output[:2_000]

            reply = self._chat(
                f"Tool '{tool_name}' completed.\n"
                f"Structured summary: {scan.summary}\n\n"
                f"Raw output preview (first 2000 chars):\n{stdout_preview}\n\n"
                "Based on these results, what is the next step? "
                "Respond with a call_tool JSON or a done JSON."
            )

        # Max steps exhausted
        logger.warning("Reached MAX_STEPS=%d", MAX_STEPS)
        return AgentResult(
            goal=goal,
            model=self.model,
            steps_taken=len(self.steps),
            steps=self.steps,
            final_summary=(
                f"Reached maximum step limit ({MAX_STEPS}). "
                "Partial findings collected — see steps for details."
            ),
        )
