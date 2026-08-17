<#
.SYNOPSIS
    Natural-language interface to the RedTeam MCP server.

.DESCRIPTION
    Routes plain-English commands through the MCP server running inside the
    redteam-mcp container.  Every command goes through server.py so audit
    logging, rate limiting, and target allowlist are all enforced.

    This replaces the old approach of calling 'docker exec nmap' directly.

.EXAMPLES
    .\mcp-helper.ps1 "scan ports on 192.168.1.1"
    .\mcp-helper.ps1 "find subdomains of example.com"
    .\mcp-helper.ps1 "run a full web vuln scan on http://testphp.vulnweb.com"
    .\mcp-helper.ps1 "generate a report for http://testphp.vulnweb.com"
    .\mcp-helper.ps1 "search findings for apache"
    .\mcp-helper.ps1 "what CVEs affect apache 2.4.49"
    .\mcp-helper.ps1 -Interactive

.NOTES
    Requires the redteam-mcp container to be running (.\run.ps1).
    All tool calls are logged to /app/data/audit.log inside the container.
#>

param(
    [Parameter(Position = 0, Mandatory = $false)]
    [string]$Text,
    [switch]$Interactive,
    [switch]$RawJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CONTAINER = "redteam-mcp"
$PYTHON    = "/app/.venv/bin/python"
$SERVER    = "/app/src/server.py"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Ok($s)   { Write-Host $s -ForegroundColor Green  }
function Write-Err($s)  { Write-Host "[!] $s" -ForegroundColor Red }
function Write-Info($s) { Write-Host "    $s" -ForegroundColor DarkGray }

function Ensure-ContainerRunning {
    $running = docker ps --filter "name=^${CONTAINER}$" --format "{{.Names}}" 2>$null
    if (-not $running) {
        Write-Err "Container '$CONTAINER' is not running."
        if (Test-Path ".\run.ps1") {
            $ans = Read-Host "  Start it now with run.ps1? [Y/N]"
            if ($ans -match "^[Yy]") {
                Write-Info "Starting container..."
                & powershell -NoProfile -ExecutionPolicy Bypass -File ".\run.ps1"
                Start-Sleep -Seconds 3
            } else {
                throw "Container not running. Aborting."
            }
        } else {
            throw "No run.ps1 found. Start the container manually and retry."
        }
    }
}

# ---------------------------------------------------------------------------
# Call a tool through the MCP server via a tiny Python one-liner
# The server.py tool functions are importable and callable directly —
# no MCP transport overhead needed for this CLI helper.
# ---------------------------------------------------------------------------

function Invoke-McpTool {
    param(
        [string]$ToolName,
        [hashtable]$Args = @{}
    )

    # Build a compact Python dict literal for the kwargs
    $kw = ($Args.GetEnumerator() | ForEach-Object {
        $v = $_.Value
        if ($v -is [bool]) { $kw_val = if ($v) { "True" } else { "False" } }
        elseif ($v -is [int]) { $kw_val = "$v" }
        else { $kw_val = "'" + ($v -replace "'","\'") + "'" }
        "$($_.Key)=$kw_val"
    }) -join ", "

    $script = @"
import sys, asyncio, json
sys.path.insert(0, '/app/src')

async def call_tool():
    # Import the specific tool function from server
    try:
        module = __import__('server')
        func = getattr(module, '${ToolName}')
        return await func(${kw})
    except Exception as e:
        return json.dumps({'error': str(e), 'type': type(e).__name__})

result = asyncio.run(call_tool())
if hasattr(result, '__str__'):
    print(result)
else:
    print(json.dumps({'error': 'Tool returned non-string result'}))
"@

    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script))
    $raw = docker exec -i $CONTAINER $PYTHON -c "import base64,sys; exec(base64.b64decode('$encoded').decode())" 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Err "Tool '$ToolName' failed (exit $LASTEXITCODE):"
        Write-Host $raw
        return $null
    }
    return $raw
}

function Format-Result {
    param([string]$Raw, [string]$ToolName)

    if (-not $Raw) { return }

    if ($RawJson) {
        Write-Host $Raw
        return
    }

    # Try to pretty-print JSON
    try {
        $obj = $Raw | ConvertFrom-Json -Depth 20
        Write-Host ""
        Write-Ok "=== $ToolName result ==="

        # Special formatting for common result shapes
        if ($obj.stdout) {
            Write-Host $obj.stdout
        } elseif ($obj.results) {
            $obj.results | Format-List | Out-String | Write-Host
        } elseif ($obj.final_summary) {
            Write-Host $obj.final_summary
        } elseif ($obj.error) {
            Write-Err $obj.error
        } else {
            $Raw | ConvertFrom-Json | ConvertTo-Json -Depth 10 | Write-Host
        }
    } catch {
        # Not JSON — print raw
        Write-Host $Raw
    }
}

# ---------------------------------------------------------------------------
# Command parser — map plain English to tool calls
# ---------------------------------------------------------------------------

function Get-Target($text) {
    # URL first
    if ($text -match "https?://([^\s/]+)") { return $matches[1] }
    # IPv4
    if ($text -match "(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)") { return $matches[1] }
    # Domain
    if ($text -match "(?:on|against|of|for|at)\s+([a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})") {
        return $matches[1]
    }
    if ($text -match "([a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})") {
        return $matches[1]
    }
    return $null
}

function Get-Url($text) {
    if ($text -match "(https?://[^\s]+)") { return $matches[1] }
    $target = Get-Target $text
    if ($target) { return "http://$target" }
    return $null
}

function Process-Text($text) {
    if (-not $text -or $text.Trim() -eq "") { return }
    $lc = $text.ToLower()

    # ── Autonomous pentest ────────────────────────────────────────────────
    if ($lc -match "\b(full pentest|autonomous|full scan|full assessment|pentest target)\b") {
        $target = Get-Target $text
        if (-not $target) { Write-Err "No target found. Example: full pentest 10.0.0.1"; return }
        Write-Ok "[*] Running autonomous pentest on '$target'..."
        $r = Invoke-McpTool "pentest_target" @{goal = "Full penetration test of $target"}
        Format-Result $r "pentest_target"
        return
    }

    # ── Generate report ───────────────────────────────────────────────────
    if ($lc -match "\b(report|generate report|pentest report)\b") {
        $url = Get-Url $text
        if (-not $url) { Write-Err "No target found. Example: generate report for http://example.com"; return }
        Write-Ok "[*] Generating report for '$url'..."
        $r = Invoke-McpTool "generate_report" @{goal = "Full web vulnerability assessment of $url"}
        Format-Result $r "generate_report"
        return
    }

    # ── CVE lookup ────────────────────────────────────────────────────────
    if ($lc -match "\b(cve|vulnerability|vulnerabilities|exploit)\b.*\b(affect|for|in|about)\b" -or
        $lc -match "\bwhat cves\b") {
        # Extract service and version
        $service = ""
        $version = ""
        if ($lc -match "\b(apache|nginx|openssh|php|wordpress|log4j|spring|iis|mysql|redis)\b") {
            $service = $matches[1]
        }
        if ($text -match "(\d+\.\d+(?:\.\d+)?)") { $version = $matches[1] }
        if (-not $service) {
            $words = $text -split "\s+"
            $keywords = @("cve","what","cves","affect","for","in","about","vulnerabilities","find")
            $service = ($words | Where-Object { $_ -notin $keywords -and $_ -match "^[a-z]" } | Select-Object -First 1)
        }
        Write-Ok "[*] Looking up CVEs for '$service $version'..."
        $r = Invoke-McpTool "find_cves" @{service = $service; version = $version}
        Format-Result $r "find_cves"
        return
    }

    # ── Nmap / port scan ──────────────────────────────────────────────────
    if ($lc -match "\b(nmap|port scan|scan ports|port discovery|open ports)\b") {
        $target = Get-Target $text
        if (-not $target) { Write-Err "No target found. Example: scan ports on 10.0.0.1"; return }
        $ports = if ($lc -match "all ports") { "1-65535" } else { "1-1000" }
        $flags = if ($lc -match "aggressive") { "-A -T4" } elseif ($lc -match "quick|fast") { "-T4 -F" } else { "-sV -sC" }
        Write-Ok "[*] Running nmap on '$target' (ports: $ports)..."
        $r = Invoke-McpTool "nmap_scan" @{target = $target; ports = $ports; flags = $flags}
        Format-Result $r "nmap_scan"
        return
    }

    # ── Rustscan (fast port scan) ─────────────────────────────────────────
    if ($lc -match "\b(rustscan|fast scan|quick port)\b") {
        $target = Get-Target $text
        if (-not $target) { Write-Err "No target. Example: rustscan 10.0.0.1"; return }
        Write-Ok "[*] Running rustscan on '$target'..."
        $r = Invoke-McpTool "rustscan" @{target = $target}
        Format-Result $r "rustscan"
        return
    }

    # ── Subdomain enumeration ─────────────────────────────────────────────
    if ($lc -match "\b(subdomain|dns enum|subfinder|amass)\b") {
        $target = Get-Target $text
        if (-not $target) { Write-Err "No domain found. Example: find subdomains of example.com"; return }
        Write-Ok "[*] Enumerating subdomains of '$target'..."
        $r = Invoke-McpTool "subfinder_enum" @{domain = $target}
        Format-Result $r "subfinder_enum"
        return
    }

    # ── Web vuln scan ─────────────────────────────────────────────────────
    if ($lc -match "\b(nikto|web vuln|web scan|vulnerability scan)\b") {
        $url = Get-Url $text
        if (-not $url) { Write-Err "No URL found. Example: nikto scan http://example.com"; return }
        Write-Ok "[*] Running nikto on '$url'..."
        $host = ([System.Uri]$url).Host
        $port = ([System.Uri]$url).Port
        if ($port -lt 0) { $port = 80 }
        $r = Invoke-McpTool "nikto_scan" @{host = $host; port = $port}
        Format-Result $r "nikto_scan"
        return
    }

    # ── Directory brute-force ─────────────────────────────────────────────
    if ($lc -match "\b(gobuster|feroxbuster|dirb|directory|fuzz|dirs)\b") {
        $url = Get-Url $text
        if (-not $url) { Write-Err "No URL found. Example: gobuster http://example.com"; return }
        $tool = if ($lc -match "ferox") { "feroxbuster" } else { "gobuster_dir" }
        Write-Ok "[*] Running $tool on '$url'..."
        $r = Invoke-McpTool $tool @{url = $url}
        Format-Result $r $tool
        return
    }

    # ── Nuclei scan ───────────────────────────────────────────────────────
    if ($lc -match "\b(nuclei|template|cve scan)\b") {
        $url = Get-Url $text
        if (-not $url) { Write-Err "No URL found. Example: nuclei scan http://example.com"; return }
        Write-Ok "[*] Running nuclei on '$url'..."
        $r = Invoke-McpTool "nuclei_scan" @{target = $url}
        Format-Result $r "nuclei_scan"
        return
    }

    # ── Technology fingerprint ────────────────────────────────────────────
    if ($lc -match "\b(whatweb|fingerprint|tech|cms|technologies)\b") {
        $url = Get-Url $text
        if (-not $url) { Write-Err "No URL found. Example: whatweb http://example.com"; return }
        Write-Ok "[*] Running whatweb on '$url'..."
        $r = Invoke-McpTool "whatweb_scan" @{url = $url}
        Format-Result $r "whatweb_scan"
        return
    }

    # ── SSL audit ─────────────────────────────────────────────────────────
    if ($lc -match "\b(ssl|tls|certificate|cipher)\b") {
        $target = Get-Target $text
        if (-not $target) { Write-Err "No target. Example: ssl audit example.com"; return }
        Write-Ok "[*] Running sslscan on '$target'..."
        $r = Invoke-McpTool "sslscan_audit" @{host = $target}
        Format-Result $r "sslscan_audit"
        return
    }

    # ── Search findings ───────────────────────────────────────────────────
    if ($lc -match "\b(search|find|lookup|history|past)\b.*\b(finding|result|scan|vuln)\b") {
        $words = ($lc -split "\s+")
        $skip  = @("search","find","lookup","history","past","for","my","finding","result","scan","vuln","findings","results")
        $query = ($words | Where-Object { $_ -notin $skip }) -join " "
        if (-not $query) { $query = $text }
        Write-Ok "[*] Searching findings for '$query'..."
        $r = Invoke-McpTool "search_findings" @{query = $query}
        Format-Result $r "search_findings"
        return
    }

    # ── Attack surface ────────────────────────────────────────────────────
    if ($lc -match "\b(attack surface|what do we know|known info|database)\b") {
        $target = Get-Target $text
        if (-not $target) { Write-Err "No target. Example: attack surface 10.0.0.1"; return }
        Write-Ok "[*] Retrieving attack surface for '$target'..."
        $r = Invoke-McpTool "get_attack_surface" @{target = $target}
        Format-Result $r "get_attack_surface"
        return
    }

    # ── CVE DB sync ───────────────────────────────────────────────────────
    if ($lc -match "\b(sync cve|update cve|download cve|cve database)\b") {
        Write-Ok "[*] Syncing CVE database from NVD (this takes a while on first run)..."
        $r = Invoke-McpTool "sync_cve_db" @{}
        Format-Result $r "sync_cve_db"
        return
    }

    # ── CVE stats ─────────────────────────────────────────────────────────
    if ($lc -match "\b(cve stats|cve status|how many cve)\b") {
        $r = Invoke-McpTool "cve_stats" @{}
        Format-Result $r "cve_stats"
        return
    }

    # ── Fallback: send as autonomous goal ─────────────────────────────────
    Write-Ok "[*] Sending as autonomous pentest goal..."
    $r = Invoke-McpTool "pentest_target" @{goal = $text}
    Format-Result $r "pentest_target"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

try {
    Ensure-ContainerRunning
} catch {
    Write-Err $_.Exception.Message
    exit 1
}

if ($Interactive) {
    Write-Ok ""
    Write-Ok "  RedTeam MCP — Interactive Mode"
    Write-Ok "  Type any plain-English command, or 'help' / 'exit'"
    Write-Ok ""
    while ($true) {
        $line = Read-Host "mcp>"
        if ($line -match "^\s*(exit|quit|q)\s*$") { break }
        if ($line -match "^\s*help\s*$") {
            Write-Host @"

Examples:
  scan ports on 10.0.0.1
  scan all ports on 192.168.1.0/24
  find subdomains of example.com
  nikto scan http://example.com
  gobuster http://example.com
  nuclei scan http://example.com
  ssl audit example.com
  whatweb http://example.com
  full pentest 10.0.0.1
  generate report for http://example.com
  what CVEs affect apache 2.4.49
  search findings for apache
  attack surface 10.0.0.1
  sync cve database
  cve stats

"@
            continue
        }
        try { Process-Text $line } catch { Write-Err $_.Exception.Message }
    }
    Write-Ok "Goodbye."
    exit 0
}

if (-not $Text) {
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\mcp-helper.ps1 `"scan ports on 10.0.0.1`""
    Write-Host "  .\mcp-helper.ps1 `"full pentest http://testphp.vulnweb.com`""
    Write-Host "  .\mcp-helper.ps1 `"what CVEs affect apache 2.4.49`""
    Write-Host "  .\mcp-helper.ps1 -Interactive"
    Write-Host ""
    exit 0
}

try {
    Process-Text $Text
} catch {
    Write-Err $_.Exception.Message
    exit 1
}
