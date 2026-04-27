# 🔴 Red Team MCP Server

A powerful penetration testing MCP server that runs **20 real hacking tools** inside a **Kali Linux Docker container** and connects them directly to AI assistants like Cursor, Claude, or any MCP-compatible IDE.

Instead of typing commands manually, you just ask in plain English:
> *"Scan ports on 192.168.1.1"*
> *"Find subdomains of example.com"*
> *"Check if this site has SQL injection"*

The AI calls the right tool, runs it in Kali Linux, and gives you the results.

---

## 🛠️ Tools Included (20 total)

| Tool | Purpose |
|------|---------|
| nmap | Port & service scanning |
| gobuster | Directory brute-forcing |
| ffuf | Web fuzzing |
| sqlmap | SQL injection |
| nikto | Web vulnerability scanning |
| nuclei | Template-based vuln scanning |
| whatweb | Technology fingerprinting |
| subfinder | Subdomain enumeration |
| httpx | HTTP probing |
| wpscan | WordPress scanning |
| amass | Attack surface mapping |
| hydra | Password brute-forcing |
| curl | Raw HTTP requests |
| dnsrecon | DNS enumeration |
| theHarvester | OSINT harvesting |
| wafw00f | WAF detection |
| sslscan | SSL/TLS auditing |
| commix | Command injection |
| arjun | Hidden parameter discovery |
| metasploit | Auxiliary module runner |

---

## ✅ Requirements

Before you start, make sure you have these installed:

- **Git** — https://git-scm.com/downloads
- **Docker Desktop** — https://www.docker.com/products/docker-desktop (enable Linux containers)
- **Python 3.11** — https://www.python.org/downloads/release/python-3110 *(only needed locally if you want to edit the server; the container handles everything else)*
- Any MCP-compatible IDE: **Cursor**, **VS Code + Kiro**, **Claude Desktop**, etc.

> Python version note: The project is written for Python 3.11+. The Docker container uses Kali's built-in Python 3 (3.12). Both work fine.

---

## 🚀 Installation — Step by Step

### Step 1 — Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/redteam-mcp.git
cd redteam-mcp
```

---

### Step 2 — Build the Docker image

This downloads Kali Linux and installs all 20 tools. Takes **10–20 minutes** the first time.

```bash
docker build -t redteam-mcp:latest .
```

You only ever need to run this once (or when you update the project).

---

### Step 3 — Start the container

**Windows (PowerShell):**
```powershell
.\run.ps1
```

**Mac / Linux:**
```bash
bash run.sh
```

Verify it's running:
```bash
docker ps
```
You should see `redteam-mcp` with status `Up`.

---

### Step 4 — Connect your IDE

Open your MCP config file in your IDE and paste this:

```json
{
  "mcpServers": {
    "redteam-kali": {
      "command": "docker",
      "args": [
        "exec", "-i", "redteam-mcp",
        "/app/.venv/bin/python", "/app/src/server.py"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

**Where to paste it:**

| IDE | Config file location |
|-----|---------------------|
| Cursor | `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project) |
| VS Code + Kiro | Already at `.kiro/settings/mcp.json` in this project |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows) |

After pasting, **reload your IDE window** (`Ctrl+Shift+P` → `Reload Window`).

---

### Step 5 — Start asking questions

You're ready. Just type in natural language:

```
Scan ports on scanme.nmap.org
Find subdomains of tesla.com
Check if http://testphp.vulnweb.com has SQL injection
Detect the WAF on cloudflare.com
Run a nikto scan on http://testphp.vulnweb.com
```

---

## 📋 Daily Usage Guide

### Start the project
```powershell
.\run.ps1
```
Then reload your IDE window.

### Stop when done
```bash
docker stop redteam-mcp
```

### Restart the container
```bash
docker restart redteam-mcp
```

### Full reset (if something breaks)
```bash
docker rm -f redteam-mcp
.\run.ps1
```

### Rebuild the image (only after editing Dockerfile or server.py)
```bash
docker rm -f redteam-mcp
docker build -t redteam-mcp:latest .
.\run.ps1
```

### Check container logs
```bash
docker logs redteam-mcp
```

### Open a shell inside the container
```bash
docker exec -it redteam-mcp /bin/bash
```

---

## ⚠️ Legal Notice

Only use these tools against systems you **own** or have **explicit written permission** to test. Unauthorized scanning is illegal. The legal test target used in examples is `scanme.nmap.org` (provided by the nmap project for this purpose).

---

## 📁 Project Structure

```
redteam-mcp/
├── src/
│   └── server.py        # MCP server with all 20 tools
├── Dockerfile           # Kali Linux multi-stage build
├── requirements.txt     # Python deps (mcp only)
├── run.ps1              # Start container (Windows)
├── run.sh               # Start container (Mac/Linux)
└── .kiro/
    └── settings/
        └── mcp.json     # IDE MCP config
```
