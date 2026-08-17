<#
.SYNOPSIS
    Working natural-language interface to RedTeam MCP server.

.DESCRIPTION
    Simple PowerShell wrapper that calls tools directly using Python.
    No MCP protocol overhead - just direct Python calls.

.EXAMPLES
    .\mcp-helper-fixed.ps1 "nmap scan scanme.nmap.org"
    .\mcp-helper-fixed.ps1 "whatweb http://testphp.vulnweb.com"
    .\mcp-helper-fixed.ps1 "find subdomains example.com"
#>

param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$Command
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CONTAINER = "redteam-mcp"
$PYTHON    = "/app/.venv/bin/python"

function Write-Ok($s)   { Write-Host $s -ForegroundColor Green }
function Write-Err($s)  { Write-Host "[!] $s" -ForegroundColor Red }
function Write-Info($s) { Write-Host "    $s" -ForegroundColor DarkGray }

function Ensure-ContainerRunning {
    $running = docker ps --filter "name=^${CONTAINER}$" --format "{{.Names}}" 2>$null
    if (-not $running) {
        Write-Err "Container '$CONTAINER' is not running."
        Write-Info "Start it with: docker run -d --name redteam-mcp --memory=4g --cpus=2 redteam-mcp:latest tail -f /dev/null"
        exit 1
    }
    return $true
}

function Call-PythonTool {
    param(
        [string]$ToolName,
        [hashtable]$Arguments = @{}
    )
    
    # Build Python code
    $argString = ""
    foreach ($key in $Arguments.Keys) {
        $value = $Arguments[$key]
        if ($value -is [string]) {
            $argString += "$key='$value', "
        } elseif ($value -is [int]) {
            $argString += "$key=$value, "
        } elseif ($value -is [bool]) {
            $argString += "$key=" + $(if ($value) { "True" } else { "False" }) + ", "
        }
    }
    $argString = $argString.TrimEnd(', ')
    
    $pythonCode = @"
import sys
sys.path.insert(0, '/app/src')
import asyncio
import server

async def run_tool():
    try:
        result = await server.${ToolName}(${argString})
        print(result)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

asyncio.run(run_tool())
"@
    
    Write-Info "Calling $ToolName with: $argString"
    
    # Encode to base64 to avoid PowerShell escaping issues
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pythonCode))
    
    $output = docker exec $CONTAINER $PYTHON -c "import base64,sys; exec(base64.b64decode('$encoded').decode('utf-8'))" 2>&1
    
    return $output
}

function Parse-Command {
    param([string]$Text)
    
    $text = $Text.ToLower().Trim()
    
    # nmap scan
    if ($text -match "nmap (?:scan )?(.+)$") {
        $target = $matches[1].Trim()
        return @{
            Tool = "nmap_scan"
            Args = @{ target = $target; ports = "1-1000"; flags = "-sV -sC" }
        }
    }
    
    # whatweb
    if ($text -match "whatweb (.+)$") {
        $url = $matches[1].Trim()
        return @{
            Tool = "whatweb_scan"
            Args = @{ url = $url }
        }
    }
    
    # subfinder
    if ($text -match "(?:find |enum )?subdomains? (?:of )?(.+)$") {
        $domain = $matches[1].Trim()
        return @{
            Tool = "subfinder_enum"
            Args = @{ domain = $domain }
        }
    }
    
    # nikto
    if ($text -match "nikto (?:scan )?(.+)$") {
        $url = $matches[1].Trim()
        if (-not $url.StartsWith("http")) { $url = "http://$url" }
        $uri = [System.Uri]$url
        return @{
            Tool = "nikto_scan"
            Args = @{ host = $uri.Host; port = $(if ($uri.Port -lt 0) { 80 } else { $uri.Port }) }
        }
    }
    
    # gobuster
    if ($text -match "gobuster (.+)$") {
        $url = $matches[1].Trim()
        if (-not $url.StartsWith("http")) { $url = "http://$url" }
        return @{
            Tool = "gobuster_dir"
            Args = @{ url = $url }
        }
    }
    
    # nuclei
    if ($text -match "nuclei (?:scan )?(.+)$") {
        $target = $matches[1].Trim()
        return @{
            Tool = "nuclei_scan"
            Args = @{ target = $target }
        }
    }
    
    # pentest (autonomous)
    if ($text -match "pentest (.+)$" -or $text -match "full scan (.+)$") {
        $target = $matches[1].Trim()
        return @{
            Tool = "pentest_target"
            Args = @{ goal = "Full penetration test of $target" }
        }
    }
    
    # Default: show help
    return $null
}

# Main execution
try {
    Ensure-ContainerRunning
    
    Write-Ok "RedTeam MCP Helper"
    Write-Ok "Command: $Command"
    Write-Ok ""
    
    $parsed = Parse-Command $Command
    if (-not $parsed) {
        Write-Err "Could not parse command. Available commands:"
        Write-Info "  nmap scan [target]"
        Write-Info "  whatweb [url]"
        Write-Info "  find subdomains [domain]"
        Write-Info "  nikto scan [url]"
        Write-Info "  gobuster [url]"
        Write-Info "  nuclei scan [target]"
        Write-Info "  pentest [target]"
        exit 1
    }
    
    $result = Call-PythonTool -ToolName $parsed.Tool -Arguments $parsed.Args
    
    Write-Ok ""
    Write-Ok "=== RESULT ==="
    Write-Host $result
    
} catch {
    Write-Err $_.Exception.Message
    exit 1
}