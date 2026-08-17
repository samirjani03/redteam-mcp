# =============================================================================
# RedTeam MCP — Container Start Script (Windows PowerShell)
# =============================================================================
# Usage:
#   .\run.ps1                              # default: free Ollama cloud, minimax-m3:cloud
#   .\run.ps1 -Model qwen2.5-coder         # different cloud model
#   .\run.ps1 -Local -Model llama3.2       # host-side Ollama
#   .\run.ps1 -AllowedTargets "192.168.1.0/24,10.0.0.0/8"
# =============================================================================
param(
    [string]$Model           = "",
    [switch]$Local           = $false,
    [switch]$Cloud           = $false,   # deprecated alias kept for back-compat
    [string]$AllowedTargets  = "",
    [int]   $MaxSteps        = 20,
    [int]   $MemoryGB        = 4,
    [int]   $CPUs            = 2
)

$CONTAINER = "redteam-mcp"
$IMAGE     = "redteam-mcp:latest"

# ── Resolve Ollama settings ───────────────────────────────────────────────────
# Default is now the free Ollama cloud model `minimax-m3:cloud` (512K context,
# reasoning, tool-aware). Pass -Local to fall back to a host-side Ollama.
[switch]$Local = $false
if ($Cloud -and $Local)  { Write-Error "Use either -Cloud or -Local, not both."; exit 1 }
if ($Local) {
    $OllamaHost  = if ($env:OLLAMA_HOST)    { $env:OLLAMA_HOST }    else { "http://host.docker.internal:11434" }
    $OllamaKey   = ""
    $OllamaModel = if ($Model) { $Model } else { if ($env:OLLAMA_MODEL) { $env:OLLAMA_MODEL } else { "llama3.2" } }
} else {
    # Cloud by default — free tier model minimax-m3:cloud
    $OllamaHost  = if ($env:OLLAMA_HOST)    { $env:OLLAMA_HOST }    else { "https://api.ollama.com" }
    $OllamaKey   = if ($env:OLLAMA_API_KEY) { $env:OLLAMA_API_KEY } else { "" }
    $OllamaModel = if ($Model) { $Model } else { if ($env:OLLAMA_MODEL) { $env:OLLAMA_MODEL } else { "minimax-m3:cloud" } }
}

# ── Remove old container ──────────────────────────────────────────────────────
docker rm -f $CONTAINER 2>$null | Out-Null

Write-Host ""
Write-Host "  RedTeam MCP — Starting container" -ForegroundColor Cyan
Write-Host "  Image        : $IMAGE"
Write-Host "  Ollama host  : $OllamaHost"
Write-Host "  Ollama model : $OllamaModel"
Write-Host "  Max steps    : $MaxSteps"
Write-Host "  Memory limit : ${MemoryGB}g"
Write-Host "  CPU limit    : $CPUs"
if ($AllowedTargets) {
    Write-Host "  Allowed targets: $AllowedTargets" -ForegroundColor Yellow
} else {
    Write-Host "  Allowed targets: ALL (open lab mode)" -ForegroundColor DarkYellow
}
Write-Host ""

# ── Start container ───────────────────────────────────────────────────────────
docker run -d `
  --name $CONTAINER `
  --cap-add=NET_RAW `
  --cap-add=NET_ADMIN `
  --add-host host.docker.internal:host-gateway `
  --memory="${MemoryGB}g" `
  --cpus="$CPUs" `
  -e OLLAMA_HOST="$OllamaHost" `
  -e OLLAMA_MODEL="$OllamaModel" `
  -e OLLAMA_API_KEY="$OllamaKey" `
  -e MAX_AGENT_STEPS="$MaxSteps" `
  -e REDTEAM_ALLOWED_TARGETS="$AllowedTargets" `
  -e REDTEAM_AUDIT_LOG="/app/data/audit.log" `
  -v "${PWD}/src:/app/src:ro" `
  -v "redteam-data:/app/data" `
  -v "redteam-reports:/app/reports" `
  $IMAGE `
  tail -f /dev/null

if ($LASTEXITCODE -eq 0) {
    Write-Host "  Container '$CONTAINER' is running." -ForegroundColor Green
    Write-Host ""
    Write-Host "  IDE connects via:" -ForegroundColor DarkGray
    Write-Host "    docker exec -i $CONTAINER /app/.venv/bin/python /app/src/server.py"
    Write-Host ""
    Write-Host "  Quick test (requires Ollama running):" -ForegroundColor DarkGray
    Write-Host "    docker exec $CONTAINER /app/.venv/bin/python /app/src/ollama_agent.py `"scan scanme.nmap.org`""
    Write-Host ""
    Write-Host "  View audit log:" -ForegroundColor DarkGray
    Write-Host "    docker exec $CONTAINER cat /app/data/audit.log"
    Write-Host ""
    Write-Host "  Open a shell inside:" -ForegroundColor DarkGray
    Write-Host "    docker exec -it $CONTAINER /bin/bash"
} else {
    Write-Host "  [ERROR] Failed to start container." -ForegroundColor Red
    Write-Host "  Is Docker running? Try: docker info"
}
