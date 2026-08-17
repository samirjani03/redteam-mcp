"""
Backward-compatible shim.

All logic has moved to src/agent/planner.py.
This file exists so any existing scripts or references to
`from ollama_agent import PentestAgent` keep working.

Standalone CLI usage (for quick testing outside MCP):
    python src/ollama_agent.py "scan ports on 10.0.0.1"
"""

from __future__ import annotations

import asyncio
import sys

# Re-export everything from the new location
from agent.planner import (  # noqa: F401
    PentestAgent,
    AgentResult,
    AgentStep,
    ToolCall,
    OLLAMA_HOST,
    OLLAMA_MODEL,
    MAX_STEPS,
)


async def _main() -> None:
    if len(sys.argv) < 2:
        print('Usage: python src/ollama_agent.py "<goal>"', file=sys.stderr)
        print('Example: python src/ollama_agent.py "scan ports on 10.0.0.1"', file=sys.stderr)
        sys.exit(1)

    goal = " ".join(sys.argv[1:])
    print(f"\n[*] Goal  : {goal}")
    print(f"[*] Model : {OLLAMA_MODEL}  Host: {OLLAMA_HOST}\n")

    agent = PentestAgent()
    result = await agent.run(goal)

    print("\n" + "=" * 60)
    print("AGENT RESULT")
    print("=" * 60)
    print(f"Goal        : {result.goal}")
    print(f"Model       : {result.model}")
    print(f"Steps taken : {result.steps_taken}")
    print()
    for step in result.steps:
        print(f"--- Step {step.step}: {step.tool_call.tool} ---")
        print(f"  Reason : {step.tool_call.reason}")
        print(f"  Summary: {step.summary}")
        print()
    print("FINAL SUMMARY:")
    print(result.final_summary)


if __name__ == "__main__":
    asyncio.run(_main())
