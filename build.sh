#!/usr/bin/env bash
# =============================================================================
# RedTeam MCP — Docker image build script
# =============================================================================
# The Dockerfile is a single-stage build on top of `kalilinux/kali-rolling:latest`
# (Kali's rolling image is rebuilt weekly and only the `latest` tag is
# persistently published on Docker Hub).
#
# Usage:
#   ./build.sh              # standard build
#   ./build.sh --no-cache   # force full rebuild
#   TAG=v1.2.0 ./build.sh   # tag with version
# =============================================================================
set -euo pipefail

IMAGE="redteam-mcp"
TAG="${TAG:-latest}"
FULL_TAG="${IMAGE}:${TAG}"

NO_CACHE=""
if [[ "${1:-}" == "--no-cache" ]]; then
    NO_CACHE="--no-cache"
fi

echo ""
echo "  Building $FULL_TAG ..."
echo "  Dockerfile: ./Dockerfile"
echo ""

# BuildKit parallel stages — dramatically speeds up the Go+Rust+binary stages
export DOCKER_BUILDKIT=1

docker build \
    $NO_CACHE \
    --progress=plain \
    -t "$FULL_TAG" \
    -f Dockerfile \
    .

echo ""
echo "  Build complete: $FULL_TAG"
echo ""
echo "  Image size:"
docker images "$IMAGE" --format "  {{.Repository}}:{{.Tag}}  {{.Size}}"
echo ""
echo "  Next steps:"
echo "    .\\run.ps1              (Windows)"
echo "    ./run.sh               (Linux/macOS)"
