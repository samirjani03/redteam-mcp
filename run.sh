#!/usr/bin/env bash
# Start the Kali red-team container in the background (keeps it alive for VS Code)
set -e

CONTAINER="redteam-mcp"

# Remove old container if it exists
docker rm -f "$CONTAINER" 2>/dev/null || true

echo "[*] Starting $CONTAINER container..."
docker run -d \
  --name "$CONTAINER" \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v "$(pwd)/src:/app/src:ro" \
  redteam-mcp:latest \
  tail -f /dev/null          # keep container alive; MCP server is invoked per-call

echo "[+] Container '$CONTAINER' is running."
echo "[*] VS Code will connect via: docker exec -i $CONTAINER python3.11 src/server.py"
