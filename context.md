# Project Context — redteam-mcp

## What This Project Is

`redteam-mcp` is a **penetration testing MCP (Model Context Protocol) server** that wraps 20 real Kali Linux security tools and exposes them as callable functions to any MCP-compatible AI assistant (Cursor, Claude Desktop, VS Code + Kiro, etc.).

The core idea: instead of a human manually typing `nmap`, `sqlmap`, `gobuster`, etc. in a terminal, an LLM receives natural-language instructions like *"scan ports on 192.168.1.1"*, calls the right MCP tool, executes it inside a Kali Linux Docker container, and returns the results back to the conversation.

---

## Architecture

```
User (natural language)
        │
        ▼
   AI Assistant / LLM (Cursor / Claude / Kiro)
        │   MCP protocol (stdio via docker exec)
        ▼
   MCP Server  ←── src/server.py  (FastMCP, Python)
        │   subprocess / asyncio
        ▼
   Kali Linux Docker Container
        │   shell execution
        ▼
   20 Security Tools (nmap, sqlmap, gobuster, etc.)
```

- The MCP server runs **inside** the Kali container as a long-lived process (`tail -f /dev/null` keeps the container alive).
- The IDE connects to it via `docker exec -i redteam-mcp /app/.venv/bin/python /app/src/server.py`.
- Each MCP tool call spawns an `asyncio.create_subprocess_shell` process that runs the actual security tool.
- Results are returned as raw JSON strings containing `stdout`, `stderr`, and `returncode`.

---

## Current Tech Stack

| Component | Current Version / Choice |
|-----------|--------------------------|
| Python | `kalilinux/kali-rolling:latest` default (3.12) |
| MCP SDK | `mcp[cli]>=1.0.0` (no pinned upper bound) |
| FastMCP | Bundled with `mcp` SDK (v1-era FastMCP) |
| Docker base | `kalilinux/kali-rolling:latest` (floating tag) |
| Go tools | `@latest` (subfinder, httpx, nuclei, amass) |
| Transport | `stdio` only |
| LLM integration | None — the server is purely a tool provider |
| Memory / state | None — fully stateless, each tool call is isolated |
| Output format | Raw JSON string (`stdout`/`stderr`/`returncode`) |
| Error handling | Basic timeout catch, no structured error types |
| Security controls | None — no auth, no target allow-list, no rate limiting |

---

## Tools Exposed (20 total)

| # | Tool | Category |
|---|------|----------|
| 1 | `nmap_scan` | Port & service scanning |
| 2 | `gobuster_dir` | Directory brute-force |
| 3 | `sqlmap_scan` | SQL injection |
| 4 | `nikto_scan` | Web vulnerability scanner |
| 5 | `whatweb_scan` | Technology fingerprinting |
| 6 | `subfinder_enum` | Subdomain enumeration |
| 7 | `httpx_probe` | HTTP probing |
| 8 | `nuclei_scan` | Template-based vuln scanning |
| 9 | `ffuf_fuzz` | Web fuzzing |
| 10 | `wpscan_scan` | WordPress scanning |
| 11 | `amass_enum` | Attack surface mapping |
| 12 | `hydra_brute` | Password brute-force |
| 13 | `curl_request` | Raw HTTP requests |
| 14 | `dnsrecon_enum` | DNS enumeration |
| 15 | `theharvester_osint` | OSINT harvesting |
| 16 | `wafw00f_detect` | WAF detection |
| 17 | `sslscan_audit` | SSL/TLS audit |
| 18 | `commix_scan` | Command injection |
| 19 | `arjun_params` | Hidden parameter discovery |
| 20 | `msf_auxiliary` | Metasploit auxiliary modules |

---

## Helper Scripts

- **`run.ps1` / `run.sh`** — Start the container with `NET_RAW`/`NET_ADMIN` caps.
- **`build.sh`** — Build the Docker image.
- **`mcp-helper.ps1`** — Lightweight PowerShell natural-language wrapper for Nmap only (not connected to the MCP server; it calls `docker exec` directly). Works only for nmap; all other tools fall back to a help message.

---

## How the LLM Uses It

The LLM is never "in" this project — it's the client. When a user sends a prompt to their AI assistant, the assistant sees the 20 tool definitions (name + docstring + args) via MCP. It decides which tool to call, passes arguments, and receives JSON back. There is no planning layer, no memory, no feedback loop — the LLM calls one tool at a time only when the user asks.

---

## File Structure

```
redteam-mcp/
├── src/
│   ├── server.py        # All 20 MCP tool definitions
│   └── __init__.py
├── Dockerfile           # Multi-stage: Kali apt tools → Go tools → final
├── requirements.txt     # mcp[cli]>=1.0.0  (only dependency)
├── run.ps1              # Start container (Windows)
├── run.sh               # Start container (Linux/Mac)
├── build.sh             # Build image
├── mcp-helper.ps1       # Plain-English Nmap helper (standalone)
├── README.md            # Setup and usage guide
└── .kiro/settings/mcp.json  # IDE MCP connection config
```
