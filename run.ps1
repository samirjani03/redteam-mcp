# PowerShell equivalent of run.sh — use this on Windows
$CONTAINER = "redteam-mcp"

# Remove old container if it exists
docker rm -f $CONTAINER 2>$null

Write-Host "[*] Starting $CONTAINER container..."
docker run -d `
  --name $CONTAINER `
  --cap-add=NET_RAW `
  --cap-add=NET_ADMIN `
  -v "${PWD}/src:/app/src:ro" `
  redteam-mcp:latest `
  tail -f /dev/null

Write-Host "[+] Container '$CONTAINER' is running."
Write-Host "[*] VS Code will connect via: docker exec -i $CONTAINER /app/.venv/bin/python /app/src/server.py"
