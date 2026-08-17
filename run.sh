#!/usr/bin/env bash
# =============================================================================
# RedTeam MCP — Container Start Script (Linux / macOS)
# =============================================================================
# Usage:
#   ./run.sh                                      # local Ollama, llama3.2
#   OLLAMA_MODEL=qwen2.5-coder ./run.sh           # different model
#   OLLAMA_HOST=https://api.ollama.com \
#     OLLAMA_API_KEY=sk-... ./run.sh              # cloud Ollama
#   REDTEAM_ALLOWED_TARGETS="10.0.0.0/8" ./run.sh # restrict targets
# =============================================================================
set -euo pipefail

CONTAINER="redteam-mcp"
IMAGE="redteam-mcp:latest"
MEMORY="${MEMORY_LIMIT:-4g}"
CPUS="${CPU_LIMIT:-2}"

OLLAMA_HOST="${OLLAMA_HOST:-https://api.ollama.com}"
OLLAMA_MODEL="${OLLAMA_MODEL:-minimax-m3:cloud}"
OLLAMA_API_KEY="${OLLAMA_API_KEY:-}"
MAX_AGENT_STEPS="${MAX_AGENT_STEPS:-20}"
ALLOWED_TARGETS="${REDTEAM_ALLOWED_TARGETS:-}"

echo ""
echo "  RedTeam MCP — Starting container"
echo "  Image        : $IMAGE"
echo "  Ollama host  : $OLLAMA_HOST"
echo "  Ollama model : $OLLAMA_MODEL"
echo "  Max steps    : $MAX_AGENT_STEPS"
echo "  Memory limit : $MEMORY"
echo ""

# Remove old container
docker rm -f "$CONTAINER" 2>/dev/null || true

# Start with resource limits + host networking for Ollama
docker run -d \
  --name "$CONTAINER" \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --add-host host.docker.internal:host-gateway \
  --memory="$MEMORY" \
  --cpus="$CPUS" \
  -e OLLAMA_HOST="$OLLAMA_HOST" \
  -e OLLAMA_MODEL="$OLLAMA_MODEL" \
  -e OLLAMA_API_KEY="$OLLAMA_API_KEY" \
  -e MAX_AGENT_STEPS="$MAX_AGENT_STEPS" \
  -e REDTEAM_ALLOWED_TARGETS="$ALLOWED_TARGETS" \
  -e REDTEAM_AUDIT_LOG="/app/data/audit.log" \
  -v "$(pwd)/src:/app/src:ro" \
  -v "redteam-data:/app/data" \
  -v "redteam-reports:/app/reports" \
  "$IMAGE" \
  tail -f /dev/null

echo ""
echo "  Container '$CONTAINER' is running."
echo ""
echo "  IDE connects via:"
echo "    docker exec -i $CONTAINER /app/.venv/bin/python /app/src/server.py"
echo ""
echo "  Quick agent test:"
echo "    docker exec $CONTAINER /app/.venv/bin/python /app/src/ollama_agent.py 'scan scanme.nmap.org'"
echo ""
echo "  View audit log:"
echo "    docker exec $CONTAINER cat /app/data/audit.log"
