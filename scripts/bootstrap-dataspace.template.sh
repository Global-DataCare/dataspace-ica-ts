#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Copy this file to scripts/bootstrap-<dataspace>.private.sh and customize values.
# Private/customer-specific scripts must stay out of public git.

PROJECT_ID="<project-id>"
PROJECT_NAME="<project-name>"
REGION="europe-southwest1"
ZONE="europe-southwest1-a"
CLUSTER_NAME="<cluster-name>"

NAMESPACE="dataspace-ica"
KSA_NAME="dataspace-ica-runtime"
GSA_NAME="dataspace-ica-runtime"
GSA_EMAIL="${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

STATIC_IP_NAME="<static-ip-name>"
PRE_SHARED_CERT_NAME="<pre-shared-cert-name>"
BUCKET_NAME="<bucket-name>"
PUBSUB_TOPIC="<topic-name>"
PUBSUB_SUBSCRIPTION="<subscription-name>"

ENV_NAME="<env-name>"
ENV_FILE="$ROOT_DIR/.env.deploy.${ENV_NAME}"

BILLING_ACCOUNT_ID=""
SKIP_DEPLOY="false"

usage() {
  cat <<EOF
Generic dataspace bootstrap template.

Usage:
  ./scripts/bootstrap-<dataspace>.private.sh [--billing-account <id>] [--skip-deploy]

Notes:
  - Keep private scripts out of public git (use *.private.sh naming).
  - Prefer Workload Identity on GKE instead of key files inside pods.
EOF
}

ensure_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "ERROR: Required command not found: $cmd"
    exit 1
  }
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --billing-account)
      BILLING_ACCOUNT_ID="${2:-}"
      shift 2
      ;;
    --skip-deploy)
      SKIP_DEPLOY="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

ensure_cmd gcloud
ensure_cmd kubectl
ensure_cmd python3
if [[ "$SKIP_DEPLOY" != "true" ]]; then
  ensure_cmd docker
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Env file not found: $ENV_FILE"
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

if [[ -n "${DEPLOY_REGION:-}" ]]; then
  REGION="$DEPLOY_REGION"
fi

if [[ -z "$BILLING_ACCOUNT_ID" ]]; then
  echo "ERROR: Missing --billing-account <id>"
  exit 1
fi

echo "Bootstrap template loaded."
echo "  Project: $PROJECT_ID"
echo "  Cluster: $CLUSTER_NAME"
echo "  Region:  $REGION"
echo "  Env:     $ENV_NAME"

echo "Next step: paste/port provisioning steps from your private script implementation."
