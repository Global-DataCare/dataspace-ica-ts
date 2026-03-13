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

resolve_credentials_path() {
  local raw_path="$1"
  if [[ -z "$raw_path" ]]; then
    return 1
  fi
  if [[ "$raw_path" = /* ]]; then
    printf '%s\n' "$raw_path"
    return 0
  fi
  printf '%s\n' "$SCRIPT_DIR/${raw_path#./}"
}

read_service_account_project_id() {
  local json_file="$1"
  node --input-type=module - "$json_file" <<'EOF'
import { readFileSync } from 'node:fs';
const filePath = process.argv[2];
const parsed = JSON.parse(readFileSync(filePath, 'utf8'));
process.stdout.write(String(parsed.project_id || '').trim());
EOF
}

if [[ -z "${1:-}" ]]; then
  echo "ERROR: Missing environment name."
  echo "Usage: ./cloud_deploy.sh <demo|dev|staging|prod> [--yes]"
  exit 1
fi

ENV_NAME="$1"
CONFIRM="true"
if [[ "${2:-}" == "--yes" || "${2:-}" == "-y" ]]; then
  CONFIRM="false"
fi

ENV_FILE="$SCRIPT_DIR/.env.deploy.$ENV_NAME"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Env file not found: $ENV_FILE"
  exit 1
fi

declare -a DUPLICATE_ENV_KEYS=()
while IFS= read -r duplicate_key; do
  [[ -z "$duplicate_key" ]] && continue
  DUPLICATE_ENV_KEYS+=("$duplicate_key")
done < <(
  awk -F= '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    {
      key=$1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
      if (key == "") next
      count[key]++
      lines[key] = lines[key] ? lines[key] "," NR : NR
    }
    END {
      for (k in count) {
        if (count[k] > 1) {
          print k ": " lines[k]
        }
      }
    }
  ' "$ENV_FILE" | sort
)

if (( ${#DUPLICATE_ENV_KEYS[@]} > 0 )); then
  echo "ERROR: Duplicate env keys detected in $ENV_FILE:"
  for entry in "${DUPLICATE_ENV_KEYS[@]}"; do
    echo "  - $entry"
  done
  echo "Fix duplicates before running deploy."
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

required_vars=(
  FIRESTORE_PROJECT_ID
  DEPLOY_REGION
  DEPLOY_SERVICE_NAME
  ARTIFACT_REGISTRY_NAME
)

for var in "${required_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: Required variable '$var' is missing in $ENV_FILE"
    exit 1
  fi
done

LOCAL_IMAGE="${LOCAL_IMAGE:-dataspace-ica:${DEFAULT_IMAGE_TAG}}"
IMAGE_TAG="${IMAGE_TAG:-$DEFAULT_IMAGE_TAG}"
NAMESPACE="${K8S_NAMESPACE:-dataspace-ica}"
K8S_CONTEXT="${K8S_CONTEXT:-}"
K8S_SERVICE_ACCOUNT_NAME="dataspace-ica-runtime"
GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT="${GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT:-}"
STATIC_LB_IP="${K8S_LOADBALANCER_IP:-}"
IMAGE_URI="${DEPLOY_REGION}-docker.pkg.dev/${FIRESTORE_PROJECT_ID}/${ARTIFACT_REGISTRY_NAME}/${DEPLOY_SERVICE_NAME}:${IMAGE_TAG}"
LOCAL_CREDENTIALS_PATH=""
if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
  LOCAL_CREDENTIALS_PATH="$(resolve_credentials_path "$GOOGLE_APPLICATION_CREDENTIALS")"
elif [[ -f "$SCRIPT_DIR/gcp-service-account.json" ]]; then
  LOCAL_CREDENTIALS_PATH="$SCRIPT_DIR/gcp-service-account.json"
fi

echo "Deploy summary"
echo "  Env file:       $ENV_FILE"
echo "  Project:        $FIRESTORE_PROJECT_ID"
echo "  Region:         $DEPLOY_REGION"
echo "  Service/Image:  $DEPLOY_SERVICE_NAME"
echo "  Image URI:      $IMAGE_URI"
echo "  Namespace:      $NAMESPACE"
echo "  Local image:    $LOCAL_IMAGE"
echo "  K8S SA:         $K8S_SERVICE_ACCOUNT_NAME"
if [[ -n "$GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT" ]]; then
  echo "  GCP SA:         $GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT"
fi
if [[ -n "$STATIC_LB_IP" ]]; then
  echo "  Static LB IP:   $STATIC_LB_IP"
fi
if [[ -n "$LOCAL_CREDENTIALS_PATH" ]]; then
  echo "  Local SA JSON:  $LOCAL_CREDENTIALS_PATH"
fi

if [[ "$CONFIRM" == "true" ]]; then
  read -r -p "Proceed with deploy? (y/n): " reply
  if [[ ! "$reply" =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 1
  fi
fi

echo "Checking local image..."
if ! docker image inspect "$LOCAL_IMAGE" >/dev/null 2>&1; then
  echo "ERROR: Local image '$LOCAL_IMAGE' not found."
  echo "Run ./docker_build_local.sh first."
  exit 1
fi

if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" && ! -f "$LOCAL_CREDENTIALS_PATH" ]]; then
  echo "ERROR: GOOGLE_APPLICATION_CREDENTIALS points to a missing file: $LOCAL_CREDENTIALS_PATH"
  echo "Create a key JSON for the target runtime project before deploying."
  exit 1
fi

if [[ -n "$LOCAL_CREDENTIALS_PATH" ]]; then
  SERVICE_ACCOUNT_PROJECT_ID="$(read_service_account_project_id "$LOCAL_CREDENTIALS_PATH")"
  if [[ -z "$SERVICE_ACCOUNT_PROJECT_ID" ]]; then
    echo "ERROR: Could not read project_id from $LOCAL_CREDENTIALS_PATH"
    exit 1
  fi
  if [[ "$SERVICE_ACCOUNT_PROJECT_ID" != "$FIRESTORE_PROJECT_ID" ]]; then
    echo "ERROR: Service account JSON project_id ($SERVICE_ACCOUNT_PROJECT_ID) does not match FIRESTORE_PROJECT_ID ($FIRESTORE_PROJECT_ID)."
    echo "Use a key from the runtime data project or remove the local JSON from this repo before deploying."
    exit 1
  fi
fi

echo "Configuring gcloud..."
gcloud config set project "$FIRESTORE_PROJECT_ID" >/dev/null
gcloud services enable artifactregistry.googleapis.com >/dev/null
echo "Tip: if you see ADC quota warnings, run once:"
echo "  gcloud auth application-default set-quota-project \"$FIRESTORE_PROJECT_ID\""

if ! gcloud artifacts repositories describe "$ARTIFACT_REGISTRY_NAME" --location="$DEPLOY_REGION" >/dev/null 2>&1; then
  gcloud artifacts repositories create "$ARTIFACT_REGISTRY_NAME" \
    --repository-format=docker \
    --location="$DEPLOY_REGION" \
    --description="Docker repository for ${DEPLOY_SERVICE_NAME}" >/dev/null
fi

gcloud auth configure-docker "${DEPLOY_REGION}-docker.pkg.dev" --quiet >/dev/null

echo "Tagging and pushing image..."
docker tag "$LOCAL_IMAGE" "$IMAGE_URI"
docker push "$IMAGE_URI"

if [[ -n "$K8S_CONTEXT" ]]; then
  kubectl config use-context "$K8S_CONTEXT"
fi

CURRENT_CONTEXT="$(kubectl config current-context 2>/dev/null || true)"
if [[ "$CURRENT_CONTEXT" =~ ^gke_([^_]+)_ ]]; then
  CLUSTER_PROJECT_FROM_CONTEXT="${BASH_REMATCH[1]}"
  if [[ -n "$CLUSTER_PROJECT_FROM_CONTEXT" && "$CLUSTER_PROJECT_FROM_CONTEXT" != "$FIRESTORE_PROJECT_ID" ]]; then
    echo "WARNING: kubectl context project ($CLUSTER_PROJECT_FROM_CONTEXT) differs from FIRESTORE_PROJECT_ID ($FIRESTORE_PROJECT_ID)."
    echo "         This is valid for cross-project setups, but static LB IPs must belong to the cluster project/region."
  fi
fi

echo "Applying Kubernetes manifests..."
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -n "$NAMESPACE" -f "$SCRIPT_DIR/deploy/k8s/serviceaccount.yaml"
if [[ -n "$GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT" ]]; then
  kubectl annotate -n "$NAMESPACE" serviceaccount/"$K8S_SERVICE_ACCOUNT_NAME" \
    iam.gke.io/gcp-service-account="$GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT" \
    --overwrite
fi
kubectl apply -n "$NAMESPACE" -f "$SCRIPT_DIR/deploy/k8s/configmap.yaml"
kubectl apply -n "$NAMESPACE" -f "$SCRIPT_DIR/deploy/k8s/service.yaml"
if [[ -n "$STATIC_LB_IP" ]]; then
  echo "Pinning LoadBalancer static IP: $STATIC_LB_IP"
  kubectl patch -n "$NAMESPACE" service/dataspace-ica-api \
    --type=merge \
    -p "{\"spec\":{\"type\":\"LoadBalancer\",\"loadBalancerIP\":\"$STATIC_LB_IP\"}}"
fi
kubectl apply -n "$NAMESPACE" -f "$SCRIPT_DIR/deploy/k8s/deployment.yaml"

echo "Applying runtime env secret from $ENV_FILE"
kubectl create secret generic dataspace-ica-secrets \
  --from-env-file="$ENV_FILE" \
  --dry-run=client -o yaml | kubectl apply -n "$NAMESPACE" -f -

kubectl set image -n "$NAMESPACE" deployment/dataspace-ica-api api="$IMAGE_URI"
echo "Restarting deployment to apply secret/env changes..."
kubectl rollout restart -n "$NAMESPACE" deployment/dataspace-ica-api
kubectl rollout status -n "$NAMESPACE" deployment/dataspace-ica-api --timeout=240s

echo "Deployment completed."
kubectl get pods -n "$NAMESPACE" -o wide
kubectl get svc -n "$NAMESPACE" dataspace-ica-api -o wide

CURRENT_IMAGE="$(kubectl get -n "$NAMESPACE" deployment/dataspace-ica-api -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true)"
if [[ -n "$CURRENT_IMAGE" ]]; then
  echo "Deployed image: $CURRENT_IMAGE"
fi

EXTERNAL_IP="$(kubectl get -n "$NAMESPACE" svc/dataspace-ica-api -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
if [[ -n "$EXTERNAL_IP" ]]; then
  echo "Public endpoints:"
  echo "  http://$EXTERNAL_IP/"
  echo "  http://$EXTERNAL_IP/api-docs"
  echo "  http://$EXTERNAL_IP/openapi.json"
  echo "  http://$EXTERNAL_IP/.well-known/did.json"
else
  echo "Public EXTERNAL-IP is pending."
  echo "Watch with:"
  echo "  kubectl -n $NAMESPACE get svc dataspace-ica-api -w"
fi
