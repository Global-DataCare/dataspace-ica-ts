#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DEFAULT_IMAGE_TAG="$(
  cd "$SCRIPT_DIR"
  node --input-type=module - <<'EOF'
import { readFileSync } from 'node:fs';
const raw = readFileSync(new URL('./package.json', import.meta.url), 'utf8');
const parsed = JSON.parse(raw);
process.stdout.write(String(parsed.version || 'latest').trim() || 'latest');
EOF
)"
IMAGE_NAME="${IMAGE_NAME:-dataspace-ica:${DEFAULT_IMAGE_TAG}}"
CONTAINER_NAME="${CONTAINER_NAME:-dataspace-ica-api}"

resolve_env_file() {
  local selector="$1"
  case "$selector" in
    st-v2|stv2|staging-v2)
      selector="st-v2"
      ;;
  esac

  if [[ -z "$selector" || "$selector" == "local" ]]; then
    echo "$SCRIPT_DIR/.env.local"
    return 0
  fi

  if [[ "$selector" =~ ^(demo|dev|staging|st-v2|prod)$ ]]; then
    echo "$SCRIPT_DIR/.env.deploy.$selector"
    return 0
  fi

  if [[ -f "$selector" ]]; then
    echo "$selector"
    return 0
  fi

  if [[ -f "$SCRIPT_DIR/$selector" ]]; then
    echo "$SCRIPT_DIR/$selector"
    return 0
  fi

  return 1
}

extract_env_value() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '
    /^[[:space:]]*#/ { next }
    $1 == k {
      value=$2
      sub(/\r$/, "", value)
      print value
      exit
    }
  ' "$file"
}

ENV_SELECTOR="${1:-local}"
if ! ENV_FILE="$(resolve_env_file "$ENV_SELECTOR")"; then
  echo "ERROR: Unable to resolve env file for '$ENV_SELECTOR'."
  echo "Usage: ./docker_run.sh [local|demo|dev|staging|st-v2|prod|/path/to/env]"
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Env file not found: $ENV_FILE"
  exit 1
fi

echo "Checking Docker daemon..."
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running."
  exit 1
fi

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "ERROR: Image '$IMAGE_NAME' not found."
  echo "Run ./docker_build_local.sh first."
  exit 1
fi

APP_PORT="$(extract_env_value "$ENV_FILE" "ICA_API_PORT")"
APP_PORT="${APP_PORT:-3310}"
if [[ -z "${HOST_PORT:-}" ]]; then
  if [[ "$ENV_SELECTOR" == "local" ]]; then
    HOST_PORT="8010"
  else
    HOST_PORT="$APP_PORT"
  fi
else
  HOST_PORT="${HOST_PORT}"
fi

echo "Running container"
echo "  Image:      $IMAGE_NAME"
echo "  Container:  $CONTAINER_NAME"
echo "  Env file:   $ENV_FILE"
echo "  Host port:  $HOST_PORT"
echo "  App port:   $APP_PORT"

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

docker run -d \
  --name "$CONTAINER_NAME" \
  --env-file "$ENV_FILE" \
  -p "$HOST_PORT:$APP_PORT" \
  "$IMAGE_NAME"

echo "Container started: $CONTAINER_NAME"
echo "Health check URL: http://localhost:$HOST_PORT/"
