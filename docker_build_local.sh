#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="${IMAGE_NAME:-dataspace-ica:local}"
NO_CACHE_FLAG="${NO_CACHE_FLAG:-false}"

if [[ "${1:-}" == "--no-cache" || "${1:-}" == "-n" ]]; then
  NO_CACHE_FLAG="true"
fi

echo "Checking Docker daemon..."
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running."
  exit 1
fi

echo "Running typecheck..."
(cd "$SCRIPT_DIR" && npm run typecheck)

echo "Building image: $IMAGE_NAME"
if [[ "$NO_CACHE_FLAG" == "true" ]]; then
  docker build --no-cache -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"
else
  docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"
fi

echo "Image built: $IMAGE_NAME"
