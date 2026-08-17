# 🔴 RedTeam MCP — Kali Linux Security Assistant & Agentic Server

An LLM-driven **Model Context Protocol (MCP)** server that connects AI assistants and IDEs (Cursor, Claude Desktop, VS Code, Kiro, Antigravity) to a suite of **42 Kali Linux & bug bounty security tools** running inside a container.

It supports both **direct tool calls** (e.g., `"Run an nmap scan on scanme.nmap.org"`) and **autonomous multi-step pentesting** powered by local Ollama models (`pentest_target`).

---

## 🛠️ Included Tools & Capabilities (42 MCP Tools)

### 1. Network Recon & Port Scanning
* **`nmap_scan`**: Detailed service and script port scanning.
* **`rustscan`**: Ultra-fast port discovery piped to Nmap.
* **`naabu_scan`**: Fast SYN-based port scanner, ideal as a first pass before nmap on large ranges.

### 2. OSINT, DNS & Subdomain Enumeration
* **`subfinder_enum`**: Passive subdomain discovery.
* **`amass_enum`**: In-depth DNS enumeration & attack surface mapping.
* **`dnsrecon_enum`**: DNS record reconnaissance.
* **`dnsx_resolve`**: Fast bulk DNS resolution & filtering of subdomain lists.
* **`alterx_permute`**: Wordlist-based subdomain permutation for finding non-obvious hosts.
* **`asnmap_lookup`**: Maps a domain/org to its ASN and owned IP ranges.
* **`uncover_search`**: Queries Shodan/Censys/Fofa-style search engines for exposed hosts.
* **`theharvester_osint`**: Public email, IP, and domain harvesting.
* **`httpx_probe`**: Live HTTP service probing, status codes, titles, tech-detect.

### 3. Web Vulnerability & Technology Analysis
* **`nikto_scan`**: Web server vulnerability auditing.
* **`nuclei_scan`**: Template-based vulnerability scanner (CVEs, exposures, misconfigs).
* **`whatweb_scan`**: Web technology & CMS fingerprinting.
* **`sslscan_audit`**: SSL/TLS cipher & certificate inspection.
* **`wpscan_scan`**: WordPress plugin, theme, and user enumeration.

### 4. Content Discovery, Crawling & URL Mining
* **`gobuster_dir`**: Directory & file brute-forcing.
* **`ffuf_fuzz`**: Endpoint, parameter, and header fuzzing.
* **`feroxbuster`**: Recursive web content discovery.
* **`arjun_params`**: Hidden HTTP parameter discovery.
* **`katana_crawl`**: Modern JS-aware crawler for discovering real, linked endpoints.
* **`gau_urls`**: Pulls known URLs for a domain from Wayback Machine, Common Crawl & OTX.
* **`waybackurls_fetch`**: Fetches archived historical URLs from the Wayback Machine.

### 5. Vulnerability Exploitation & Injection Testing
* **`sqlmap_scan`**: Automated SQL injection detection & testing.
* **`commix_scan`**: OS command injection testing.
* **`dalfox_xss`**: Automated reflected/DOM XSS scanning and parameter mining.
* **`hydra_brute`**: Multi-protocol credential brute-forcing.
* **`kerbrute`**: Active Directory Kerberos user enumeration.
* **`msf_auxiliary`**: Non-interactive Metasploit module runner.

### 6. Subdomain Takeover, Secrets & Visual Recon
* **`subzy_takeover`**: Detects hijackable/dangling subdomains pointing at unclaimed services.
* **`gitleaks_scan`**: Scans for hardcoded secrets, API keys, and credentials.
* **`gowitness_screenshot`**: Bulk screenshots live web targets for fast visual triage.

### 7. Out-of-Band Vulnerability Detection
* **`interactsh_oob`**: Blind/OOB interaction detection for SSRF, XXE, and blind RCE via a unique callback domain.

### 8. Custom Requests
* **`curl_request`**: Custom raw HTTP request execution (headers, methods, body, TLS verification toggle).

### 9. CVE Intelligence & Database
* **`cve_stats`**: View local CVE database metrics.

### 10. Agentic Autonomous Pentesting & Memory
* **`pentest_target`**: Plain-English autonomous multi-step security goal planning loop (Ollama).
* **`generate_report`**: Autonomous testing + Markdown/HTML report generation.
* **`export_report`**: Save penetration testing reports directly to `/app/reports/`.
* **`search_findings`**: Search SQLite history of past scan findings.
* **`get_attack_surface`**: Aggregated target intelligence lookup.
* **`list_sessions`**: Session history & audit trail.

---

## 💻 Connecting RedTeam MCP to Claude Desktop (Windows)

You can connect RedTeam MCP directly to **Claude Desktop on Windows** so Claude can use all Kali tools directly in conversation.

### Step-by-Step Configuration Guide:

1. **Open Claude Desktop Settings**:
   * Launch **Claude Desktop**.
   * Click on your profile/icon or open **Settings**.
   * Click on **Developer** in the left menu.
   * Click **Edit Config** (this opens `claude_desktop_config.json` in your default text editor).

   *(Alternatively, open `%APPDATA%\Claude\claude_desktop_config.json` in Notepad or File Explorer).*

2. **Paste the MCP Server Configuration**:
   Add the `redteam-kali` server entry to your JSON file:

   ```json
   {
     "mcpServers": {
       "redteam-kali": {
         "command": "docker",
         "args": [
           "exec",
           "-i",
           "redteam-mcp",
           "/app/.venv/bin/python",
           "/app/src/server.py"
         ],
         "disabled": false,
         "autoApprove": []
       }
     }
   }
   ```

3. **Save & Restart**:
   * Save `claude_desktop_config.json`.
   * Completely close and restart **Claude Desktop**.
   * You will see a hammer/tool icon indicating `redteam-kali` tools are connected!

---

## ⚙️ Connecting to Other IDEs

| IDE | Config File Location |
| :--- | :--- |
| **Cursor** | `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global) |
| **VS Code / Kiro** | `.kiro/settings/mcp.json` or `.vscode/mcp.json` |
| **Roo Code / Antigravity** | `.roo/mcp.json` or `mcp_config.json` |

Configuration JSON block for all IDEs:
```json
{
  "mcpServers": {
    "redteam-kali": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "redteam-mcp",
        "/app/.venv/bin/python",
        "/app/src/server.py"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

---

## 🚀 Quick Start Guide

### 1. Build the Docker Image
```bash
docker build -t redteam-mcp:latest .
```

### 2. Start the Container
**Windows (PowerShell):**
```powershell
.\run.ps1
```

**Linux / macOS:**
```bash
bash run.sh
```

### 3. Verify Container Status
```bash
docker ps
```
The container `redteam-mcp` will show status `Up`.

### 4. Test Server Execution (PowerShell Helper)
```powershell
.\mcp-helper-fixed.ps1 "nmap scan scanme.nmap.org"
```

---

## 🏗️ Architecture & Modules

```text
redteam-mcp/
├── Dockerfile                  # Kali Linux Docker runtime image
├── requirements.txt            # FastMCP, Ollama SDK, Pydantic, HTTPX, AIOSQLite, Jinja2
├── run.ps1 / run.sh            # Container launch scripts
├── mcp_config.json             # Root IDE MCP configuration template
└── src/
    ├── server.py               # Main MCP Server entry point (42 tools registered)
    ├── agent/                  # PentestAgent Ollama loop & reasoning prompts
    ├── tools/                  # Shell executor, output formatter, tool registry
    ├── parsers/                # Typed Pydantic parsers (Nmap, Nuclei, Nikto, WhatWeb, etc.)
    ├── memory/                 # SQLite store & NVD CVE cross-reference engine
    ├── reporting/              # Markdown & HTML report generators
    └── security/               # Target allowlist, sliding-window rate limiter, JSONL audit logger
```

---

## 🛡️ Security & Target Controls

The server includes built-in safety controls configured via environment variables:

* `REDTEAM_ALLOWED_TARGETS`: Comma-separated list of IP addresses, CIDR ranges, or domain names permitted for scanning. (Leave empty for open lab testing).
* `REDTEAM_RATE_LIMIT`: Sliding-window tool call rate limiter per minute (Default: `0` / unlimited).
* `REDTEAM_AUDIT_LOG`: Path to append-only audit log (`/app/data/audit.log`).

---

## 📋 Changelog note (v2 doc sync)

Compared against the live registered tool list as of this update:

* **Added to docs** (were live but undocumented): `naabu_scan`, `dnsx_resolve`, `alterx_permute`, `asnmap_lookup`, `uncover_search`, `katana_crawl`, `gau_urls`, `waybackurls_fetch`, `dalfox_xss`, `subzy_takeover`, `gitleaks_scan`, `gowitness_screenshot`, `interactsh_oob`
* **Documented but not currently live** — confirm if intentional: `wafw00f_detect`, `find_cves`, `sync_cve_db`

---

## ⚠️ Legal Notice

Always ensure you have **explicit written authorization** before performing security assessments on any host, application, or network. Scanning targets without permission is illegal.