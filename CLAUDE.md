# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

`redteam-mcp` is a **penetration-testing MCP (Model Context Protocol) server** that exposes 23 Kali Linux security tools as callable functions and (for agent-style use) drives them with a local Ollama LLM. It runs inside a Kali Linux Docker container; the IDE connects to it via `docker exec -i redteam-mcp /app/.venv/bin/python /app/src/server.py` over stdio.

**Graph analysis** (288 nodes, 492 edges, 17 communities):
- **God nodes** (core abstractions): `ScanResult` (26 edges), `fmt_output()` (25), `run_shell()` (25), `Finding` (21), `MemoryStore` (20), `CveStore` (19), `PentestAgent` (13), `_parse_output()` (11), `Subdomain` (9), `Port` (9)
- **Key communities**: Agent/Planner (Community 0), All 23 Tools in server.py (Community 1), CVE Store (Community 2), SQLite Memory (Community 3), Audit/Security (Community 4), Port/CVE Matcher (Community 5), Report Export (Community 6), Tool Registry (Community 7)

Two usage modes:
- **Single-tool mode** — the LLM/IDE calls one of the 23 `@mcp.tool()` functions directly (`nmap_scan`, `nuclei_scan`, …).
- **Autonomous mode** — the LLM calls `pentest_target(goal)` / `generate_report(goal)` / `export_report(goal)`, and the in-process `PentestAgent` plans a multi-step attack chain, invokes the right tools, parses their output into typed models, persists them to SQLite, and feeds structured summaries back to the model until it returns `{"action": "done"}` or `MAX_AGENT_STEPS` is reached.

## Common commands

All commands assume the working directory is the repo root.

### Build the image (one-time, ~10–20 min)
```bash
./build.sh                  # Linux/macOS
# or: DOCKER_BUILDKIT=1 docker build -t redteam-mcp:latest .
```

### Start the container
```bash
./run.sh                                          # Linux/macOS
.\run.ps1                                         # Windows
.\run.ps1 -AllowedTargets "10.0.0.0/8,192.168.1.0/24"   # restricted mode
.\run.ps1 -Cloud -Model gpt-oss:120b-cloud        # use Ollama cloud
```

### Verify the MCP server is reachable
```bash
python test_mcp.py            # spawns docker exec, sends initialize + tools/list
```

### Quick agent test (no IDE)
```bash
docker exec redteam-mcp /app/.venv/bin/python /app/src/ollama_agent.py "scan scanme.nmap.org"
```

### CLI helper (no IDE — routes through the MCP server, so audit log + allowlist still apply)
```powershell
.\mcp-helper.ps1 "scan ports on 10.0.0.1"
.\mcp-helper.ps1 "full pentest http://testphp.vulnweb.com"
.\mcp-helper.ps1 "what CVEs affect apache 2.4.49"
.\mcp-helper.ps1 -Interactive
```

### Container lifecycle
```bash
docker stop redteam-mcp
docker restart redteam-mcp
docker logs redteam-mcp
docker exec -it redteam-mcp /bin/bash
docker rm -f redteam-mcp && ./build.sh && ./run.sh   # full reset
```

There is no formal test suite or linter. `test_mcp.py` is a hand-rolled JSON-RPC smoke test (initialize + tools/list); running it against a running container is the de-facto "does it work" check.

## High-level architecture

```
LLM (Cursor / Kiro / Claude Desktop)
  │  MCP stdio  →  docker exec -i redteam-mcp python /app/src/server.py
  ��
src/server.py          FastMCP app — 23 tool functions + 6 agent tools + 3 CVE tools
  │
  ├── src/tools/executor.py    run_shell() subprocess runner, fmt_output() (caps stdout at 8 KB)
  │       └── execute_tool()   dynamic dispatch back into server.py for the agent
  ├── src/tools/registry.py    TOOL_REGISTRY — single source of truth (used by prompt + agent)
  ├── src/agent/planner.py     PentestAgent — Ollama chat loop, JSON action parsing, parser dispatch
  │       └── src/agent/prompts.py  phase-aware system prompt (5 pentest phases, 15 branching rules)
  ├── src/parsers/*            raw tool output → typed Pydantic models (Port, Subdomain, Finding, ScanResult)
  ├── src/memory/store.py      aiosqlite — sessions / scans / findings (persistence + search)
  ├── src/memory/cve_store.py  NVD 2.0 feed → SQLite + FTS5 (sync_cve_db, find_cves)
  ├── src/reporting/{markdown,html}.py   generate_*_report(AgentResult)
  └── src/security/audit.py    @guarded() decorator — allowlist + rate-limit + JSONL audit log
```

### The tool-call flow (autonomous mode)

1. `pentest_target(goal)` → `PentestAgent.run(goal)` in `src/agent/planner.py`.
2. Sends goal + system prompt to Ollama. Parses reply as JSON `{"action": "call_tool", "tool": ..., "args": ..., "reason": ...}` (or `{"action": "done", "summary": ...}`).
3. `tools.executor.execute_tool(name, args)` dynamically `importlib`s `src.server` and calls the matching `@mcp.tool()` function directly (no MCP transport — the tool functions are plain async Python).
4. Raw output goes through the matching parser in `src/parsers/` to produce a `ScanResult` with typed `Port` / `Subdomain` / `Finding` lists.
5. **CVE enrichment hook**: if tool is `nmap_scan` and ports have version strings, `parsers/cve_matcher.py` queries `memory/cve_store.py` (or falls back to a hard-coded list of ~8 known criticals) and appends `Finding` objects.
6. `MemoryStore.save_scan(goal, scan)` persists ports/subs/vulns to SQLite (`/app/data/redteam.db`).
7. The structured `ScanResult.summary` + first 2 KB of raw stdout is sent back to the model, which picks the next step until `done` or `MAX_AGENT_STEPS` (default 20).

### Key conventions to preserve when editing

- **Tool functions in `server.py` are the agent's API surface** — they are decorated with `@mcp.tool()` AND called directly via `importlib` from the agent. Don't add side effects that only work in MCP transport (e.g., don't depend on `Context` injection unless you also wire it through `execute_tool`).
- **`src/tools/registry.py` is the single source of truth** for tool metadata. The system prompt (`agent/prompts.py`) and the agent's `TOOL_REGISTRY` membership check both read from it. When you add a tool to `server.py`, you must also add it to `TOOL_REGISTRY` or the agent won't know about it.
- **Every parser must return a `ScanResult`** (see `src/parsers/base.py`). Add a new branch to `_parse_output()` in `agent/planner.py` when introducing a new parser.
- **`@guarded(tool_name)` from `security/audit.py`** enforces the `REDTEAM_ALLOWED_TARGETS` allowlist, the `REDTEAM_RATE_LIMIT` sliding window, and writes one JSONL record per call to `/app/data/audit.log`. New tool functions that take a target arg should be wrapped with it.
- **Shell commands are built with `shlex.quote()`** for every interpolated value. Don't drop this — it is the only protection against target-string injection into `nmap`, `curl`, etc.
- **Ollama config is read at import time** in `agent/planner.py` (`OLLAMA_HOST`, `OLLAMA_MODEL`, `OLLAMA_API_KEY`, `MAX_STEPS`). Set env vars before starting the container; `run.ps1 -Cloud -Model ...` does this for you.
- **Container is kept alive with `tail -f /dev/null`**; the IDE reaches the server via `docker exec -i`. The named volumes `redteam-data` (SQLite) and `redteam-reports` (exported reports) persist across container restarts. The bind mount `-v $(pwd)/src:/app/src:ro` means local edits to `src/` are picked up on the next `docker restart redteam-mcp` (Python reloads, no rebuild needed unless `Dockerfile` / `requirements.txt` changed).
- **Container capabilities**: `--cap-add=NET_RAW` and `--cap-add=NET_ADMIN` are required for nmap raw-socket scans, masscan, etc. Resource limits (`--memory`, `--cpus`) default to 4 GB / 2 CPUs and are configurable via `run.ps1` parameters or `MEMORY_LIMIT` / `CPU_LIMIT` env vars on `run.sh`.

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `OLLAMA_HOST` | `http://host.docker.internal:11434` | Ollama server (use `https://api.ollama.com` for cloud) |
| `OLLAMA_MODEL` | `llama3.2` | Model name passed to Ollama |
| `OLLAMA_API_KEY` | *(empty)* | Bearer token for Ollama cloud |
| `MAX_AGENT_STEPS` | `20` | Max tool-call iterations per `pentest_target` run |
| `REDTEAM_ALLOWED_TARGETS` | *(empty = all)* | Comma-separated IPs/CIDRs/domains; empty disables the allowlist |
| `REDTEAM_AUDIT_LOG` | `/app/data/audit.log` | JSONL audit log path |
| `REDTEAM_RATE_LIMIT` | `0` (disabled) | Max tool calls per 60 s window |

## Files you will most often touch

- `src/server.py` — adding a new tool means a new `@mcp.tool()` async function plus an entry in `TOOL_REGISTRY` and a parser branch in `agent/planner.py._parse_output()`.
- `src/tools/registry.py` — extend `TOOL_REGISTRY` whenever you add/change a tool; this drives the system prompt.
- `src/agent/prompts.py` — adjust the phase-ordering or branching rules; the system prompt is rebuilt on every `PentestAgent` instantiation.
- `src/parsers/` — one file per tool, each exporting a `parse_<tool>(raw_stdout, target) -> ScanResult` function.
- `Dockerfile` — pin Go tool versions, add new apt packages, or pre-fetch new release binaries; rebuild required.

## Detailed component map (from Graphify analysis)

### Core Models (`src/parsers/base.py`)
- `Port` — single open port discovered by nmap; enriched with CVEs via `enrich_with_cves()`
- `Subdomain` — discovered subdomain
- `Finding` — vulnerability finding (CVE, misconfig, etc.)
- `ScanResult` — aggregates Ports, Subdomains, Findings; has `summary` property
- `AgentResult` — final agent output (steps, findings, summary)
- `AgentStep` — single tool call in the agent chain (tool, args, result, reasoning)
- `ToolCall` — parsed tool call from LLM JSON

### The 23 MCP Tools (all in `src/server.py`, Community 1)
| Tool | Purpose | Parser |
|---|---|---|
| `nmap_scan` | Port/service scanning | `parse_nmap()` |
| `nuclei_scan` | Template-based vuln scanning | `parse_nuclei()` |
| `gobuster_dir` | Directory/file brute force | `parse_gobuster()` |
| `ffuf_fuzz` | Fast web fuzzing | `parse_ffuf()` |
| `rustscan` | Fast port scanner | `parse_rustscan()` |
| `subfinder_enum` | Subdomain enumeration | `parse_subfinder()` |
| `amass_enum` | Subdomain enumeration (Amass) | `parse_amass()` |
| `theharvester_osint` | OSINT gathering | `parse_theharvester()` |
| `dnsrecon_enum` | DNS enumeration | `parse_dnsrecon()` |
| `whatweb_scan` | Web technology fingerprinting | `parse_whatweb()` |
| `httpx_probe` | HTTP probing | `parse_httpx()` |
| `nikto_scan` | Web server scanning | `parse_nikto()` |
| `wafw00f_detect` | WAF detection | `parse_wafw00f()` |
| `wpscan_scan` | WordPress scanning | `parse_wpscan()` |
| `sqlmap_scan` | SQL injection testing | `parse_sqlmap()` |
| `commix_scan` | Command injection testing | `parse_commix()` |
| `hydra_brute` | Brute force authentication | `parse_hydra()` |
| `kerbrute` | Kerberos user enumeration | `parse_kerbrute()` |
| `msf_auxiliary` | Metasploit auxiliary modules | `parse_msf()` |
| `feroxbuster` | Directory brute force | `parse_feroxbuster()` |
| `arjun_params` | HTTP parameter discovery | `parse_arjun()` |
| `sslscan_audit` | SSL/TLS scanning | `parse_sslscan()` |
| `curl_request` | Generic HTTP request | — |

### Agent Tools (in `src/server.py`)
- `pentest_target(goal)` → `PentestAgent.run(goal)`
- `generate_report(goal)` → runs agent, returns markdown
- `export_report(goal)` → runs agent, returns HTML file path
- `sync_cve_db()` → `CveStore.sync()`
- `find_cves(query)` → `CveStore.search()`
- `cve_stats()` → CVE database stats

### CVE Enrichment (`src/parsers/cve_matcher.py`, Community 5)
- `enrich_with_cves(ports)` — cross-references nmap service versions against CVE database
- `_lookup_port()`, `_extract_vendor_product()`, `_extract_version()`, `quick_match()`
- Queries `CveStore` (NVD 2.0 feed → SQLite + FTS5) or falls back to hard-coded critical CVEs

### Memory & Persistence (`src/memory/store.py`, Community 3)
- `MemoryStore` — aiosqlite wrapper for sessions, scans, findings
- `save_session()`, `save_scan()`, `search_findings()`, `get_findings_for_target()`
- SQLite at `/app/data/redteam.db`

### CVE Store (`src/memory/cve_store.py`, Community 2)
- `CveStore` — downloads NVD 2.0 feed (200k+ CVEs), indexes to SQLite + FTS5
- `sync()` — incremental sync from NVD API
- `search(query)` — full-text search across CVE IDs, descriptions, products
- `get_cve(cve_id)` — fetch single CVE details

### Security & Audit (`src/security/audit.py`, Community 4)
- `@guarded(tool_name)` decorator — enforces allowlist, rate limit, writes JSONL audit log
- `_RateLimiter` — sliding window rate limiter
- `AuditLog` — JSONL append-only log at `/app/data/audit.log`
- `AllowlistError`, `RateLimitError` exceptions

### Tool Registry & Prompts (`src/tools/registry.py`, Community 7)
- `TOOL_REGISTRY` — list of 23 dicts with name, description, params, parser
- `build_system_prompt()` — injects tool list into phase-aware prompt
- Phase-aware prompt in `src/agent/prompts.py` (5 phases, 15 branching rules)

### Reporting (`src/reporting/`, Community 6)
- `generate_markdown_report(AgentResult)` → structured markdown
- `generate_html_report(AgentResult)` → self-contained dark-mode HTML
- `export_report()` MCP tool wraps both

### CLI Helpers
- `mcp-helper.ps1` — PowerShell wrapper routing through MCP server
- `mcp-helper-fixed.ps1` — alternate implementation
- `ollama_agent.py` — standalone agent test entry point (`_main()`)

## Legal
Allowed targets are:

Target: http://localhost:3000/
Target: 10.0.2.15 This is my own intentionally vulnerable lab machine.its kali linux. You are authorized to test it.
 `scanme.nmap.org` is the canonical legal test target.