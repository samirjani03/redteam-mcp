#!/usr/bin/env bash
# Build the Kali red-team Docker image
set -e
echo "[*] Building redteam-mcp image..."
docker build -t redteam-mcp:latest .
echo "[+] Build complete."
