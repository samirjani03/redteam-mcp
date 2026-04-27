<#
.SYNOPSIS
  Simple helper to run MCP Docker tools using plain-English sentences.

.DESCRIPTION
  Lightweight parser that maps simple English phrases (e.g. "Run an Nmap scan against example.com")
  to `docker exec` commands for the `redteam-mcp` container. Intended for beginners to run
  common tasks without remembering long docker commands.

USAGE
  .\mcp-helper.ps1 "Run an Nmap scan against atozcyber.co.in"
  .\mcp-helper.ps1 -Interactive

NOTES
  - Requires Docker and the `redteam-mcp` container (this repo's `run.ps1` can start it).
  - Only a small set of phrases/tools are parsed (Nmap primarily). It's safe to extend.
  - Only scan targets you have permission to test.
#>

param(
    [Parameter(Position=0, Mandatory=$false)]
    [string]$Text,
    [switch]$Interactive
)

function Write-Info($s) { Write-Host $s -ForegroundColor Green }
function Write-Err($s) { Write-Host $s -ForegroundColor Red }

function Get-TargetFromText($t) {
    if (-not $t) { return $null }
    if ($t -match "https?://([^\\s/]+)") { return $matches[1] }
    $m = [regex]::Match($t, "(\d{1,3}(?:\.\d{1,3}){3})")
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($t, "([a-zA-Z0-9][a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})")
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Get-PortsFromText($t) {
    $m = [regex]::Match($t, "ports?\s*[:=]?\s*([0-9,\-]+)")
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($t, "port\s*[:=]?\s*([0-9]+)")
    if ($m.Success) { return $m.Groups[1].Value }
    return '1-1000'
}

function Get-FlagsFromText($t) {
    $m = [regex]::Match($t, "flags?\s*[:=]?\s*([^\\n]+)")
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    if ($t -match '\baggressive\b') { return '-A -T4' }
    if ($t -match '\bquick\b' -or $t -match '\bfast\b') { return '-T4 -F' }
    return '-sV -sC'
}

function ShouldSaveOutput($t) {
    return ($t -match "\b(save|output|file|write)\b")
}

function Ensure-ContainerRunning() {
    $status = (& docker ps --filter "name=redteam-mcp" --format "{{.Names}}:{{.Status}}" 2>$null) -join "`n"
    if (-not $status -or $status -eq '') {
        Write-Err "Container 'redteam-mcp' is not running."
        if (Test-Path .\run.ps1) {
            $ans = Read-Host "Start container now using run.ps1? (Y/N)"
            if ($ans -match '^[Yy]') {
                Write-Info "Starting container..."
                & powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1
                Start-Sleep -Seconds 2
            } else {
                throw "Container not running. Aborting."
            }
        } else {
            throw "No run.ps1 found; start container manually and retry."
        }
    } else {
        Write-Info "Container running: $status"
    }
}

function Invoke-Nmap($target, $ports, $flags, $save) {
    $flagTokens = @()
    if ($flags) { $flagTokens = ($flags -split '\s+') | Where-Object { $_ -ne '' } }
    $args = @('exec','-i','redteam-mcp','nmap')
    if ($flagTokens.Count -gt 0) { $args += $flagTokens }
    $args += @('-p',$ports,$target)
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    if ($save) {
        $tmpFile = "/tmp/mcp_nmap_$timestamp.txt"
        $args += @('-oN',$tmpFile)
    }
    Write-Info "Executing: docker $($args -join ' ')"
    $output = & docker @args 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Error: exited with code $LASTEXITCODE"
        Write-Host $output
        return
    }
    if ($save) {
        $hostFile = Join-Path (Get-Location) "mcp_nmap_$timestamp.txt"
        Write-Info "Copying output to $hostFile"
        & docker cp "redteam-mcp:$tmpFile" $hostFile | Out-Null
        Write-Info "Saved: $hostFile"
    } else {
        Write-Host $output
    }
}

function Process-Text($text) {
    if (-not $text -or $text.Trim() -eq '') { return }
    $lc = $text.ToLower()
    if ($lc -match "\bnmap\b" -or $lc -match "\bport scan\b" -or $lc -match "\bscan\b") {
        $target = Get-TargetFromText($text)
        if (-not $target) {
            Write-Err "No target found in input. Example: Run an Nmap scan against atozcyber.co.in"
            return
        }
        $ports = Get-PortsFromText($text)
        $flags = Get-FlagsFromText($text)
        $save = ShouldSaveOutput($text)
        Ensure-ContainerRunning
        Invoke-Nmap $target $ports $flags $save
        return
    }

    if ($lc -match "\bgobuster\b") {
        Write-Info "For Gobuster use: docker exec -i redteam-mcp gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,js -t 30"
        return
    }

    Write-Err "Sorry - I do not recognize that command. Try: Run an Nmap scan against example.com or use -Interactive."
}

if ($Interactive) {
    Write-Info "Entering interactive mode. Type exit to quit."
    while ($true) {
        $line = Read-Host -Prompt "mcp>"
        if ($line -match "^\s*(exit|quit|q)\s*$") { break }
        try { Process-Text $line } catch { Write-Err $_.Exception.Message }
    }
    Write-Info "Exiting."
    exit 0
}

if (-not $Text) {
    Write-Host ""
    Write-Host "Usage examples:"
    Write-Host "  .\mcp-helper.ps1 \"Run an Nmap scan against atozcyber.co.in\""
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
