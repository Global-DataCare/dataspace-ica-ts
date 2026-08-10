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

render_manifest() {
  local manifest_path="$1"
  sed \
    -e "s|\${K8S_APP_NAME}|$K8S_APP_NAME|g" \
    -e "s|\${K8S_SERVICE_NAME}|$K8S_SERVICE_NAME|g" \
    -e "s|\${K8S_CONFIGMAP_NAME}|$K8S_CONFIGMAP_NAME|g" \
    -e "s|\${K8S_SECRET_NAME}|$K8S_SECRET_NAME|g" \
    -e "s|\${K8S_SERVICE_ACCOUNT_NAME}|$K8S_SERVICE_ACCOUNT_NAME|g" \
    -e "s|\${K8S_SERVICE_TYPE}|$K8S_SERVICE_TYPE|g" \
    -e "s|\${K8S_MANAGED_CERT_NAME}|$K8S_MANAGED_CERT_NAME|g" \
    -e "s|\${K8S_INGRESS_HOST}|$K8S_INGRESS_HOST|g" \
    "$manifest_path"
}

render_ingress_manifest() {
  cat <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ${K8S_APP_NAME}
  namespace: ${NAMESPACE}
  annotations:
    kubernetes.io/ingress.class: "gce"
EOF

  if [[ -n "$K8S_INGRESS_STATIC_IP_NAME" ]]; then
    echo "    kubernetes.io/ingress.global-static-ip-name: \"${K8S_INGRESS_STATIC_IP_NAME}\""
  fi

  if [[ -n "$K8S_MANAGED_CERT_NAME" ]]; then
    echo "    networking.gke.io/managed-certificates: \"${K8S_MANAGED_CERT_NAME}\""
  fi

  if [[ -n "$K8S_PRE_SHARED_CERT_NAME" ]]; then
    echo "    ingress.gcp.kubernetes.io/pre-shared-cert: \"${K8S_PRE_SHARED_CERT_NAME}\""
  fi

  if [[ "$K8S_DISABLE_HTTP" == "true" ]]; then
    echo "    kubernetes.io/ingress.allow-http: \"false\""
  fi

  cat <<EOF
spec:
EOF

  if [[ -n "$K8S_TLS_SECRET_NAME" ]]; then
    cat <<EOF
  tls:
    - secretName: ${K8S_TLS_SECRET_NAME}
EOF
  fi

  cat <<EOF
  rules:
    -
EOF

  if [[ -n "$K8S_INGRESS_HOST" ]]; then
    echo "      host: ${K8S_INGRESS_HOST}"
  fi

  cat <<EOF
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ${K8S_SERVICE_NAME}
                port:
                  number: 80
EOF
}

if [[ -z "${1:-}" ]]; then
  echo "ERROR: Missing environment name."
  echo "Usage: ./cloud_deploy.sh <environment> [--yes] [--allow-staging]"
  exit 1
fi

RAW_ENV_NAME="$1"
if [[ ! "$RAW_ENV_NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: Invalid environment name: $RAW_ENV_NAME"
  exit 1
fi
ENV_NAME="$RAW_ENV_NAME"
CONFIRM="true"
ALLOW_STAGING="false"
shift
for arg in "$@"; do
  case "$arg" in
    --yes|-y)
      CONFIRM="false"
      ;;
    --allow-staging)
      ALLOW_STAGING="true"
      ;;
    *)
      echo "ERROR: Unknown argument: $arg"
      echo "Usage: ./cloud_deploy.sh <environment> [--yes] [--allow-staging]"
      exit 1
      ;;
  esac
done

ENV_FILE="$SCRIPT_DIR/.env.deploy.$ENV_NAME"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Env file not found: $ENV_FILE"
  exit 1
fi

if [[ "$ENV_NAME" == "staging" && "$ALLOW_STAGING" != "true" ]]; then
  echo "ERROR: staging deploy is protected."
  echo "Use another configured environment, or re-run with --allow-staging if you really want staging."
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
K8S_APP_NAME="${K8S_APP_NAME:-dataspace-ica-api}"
K8S_SERVICE_NAME="${K8S_SERVICE_NAME:-$K8S_APP_NAME}"
K8S_CONFIGMAP_NAME="${K8S_CONFIGMAP_NAME:-${K8S_APP_NAME}-config}"
K8S_SECRET_NAME="${K8S_SECRET_NAME:-${K8S_APP_NAME}-secrets}"
K8S_SERVICE_ACCOUNT_NAME="${K8S_SERVICE_ACCOUNT_NAME:-dataspace-ica-runtime}"
GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT="${GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT:-}"
STATIC_LB_IP="${K8S_LOADBALANCER_IP:-}"
K8S_INGRESS_ENABLED="${K8S_INGRESS_ENABLED:-false}"
K8S_INGRESS_HOST="${K8S_INGRESS_HOST:-}"
K8S_INGRESS_STATIC_IP_NAME="${K8S_INGRESS_STATIC_IP_NAME:-}"
K8S_MANAGED_CERT_NAME="${K8S_MANAGED_CERT_NAME:-}"
K8S_PRE_SHARED_CERT_NAME="${K8S_PRE_SHARED_CERT_NAME:-}"
K8S_TLS_SECRET_NAME="${K8S_TLS_SECRET_NAME:-}"
K8S_DISABLE_HTTP="${K8S_DISABLE_HTTP:-false}"
K8S_SERVICE_TYPE="${K8S_SERVICE_TYPE:-}"
if [[ -z "$K8S_SERVICE_TYPE" ]]; then
  if [[ "$K8S_INGRESS_ENABLED" == "true" ]]; then
    K8S_SERVICE_TYPE="NodePort"
  else
    K8S_SERVICE_TYPE="LoadBalancer"
  fi
fi
IMAGE_URI="${DEPLOY_REGION}-docker.pkg.dev/${FIRESTORE_PROJECT_ID}/${ARTIFACT_REGISTRY_NAME}/${DEPLOY_SERVICE_NAME}:${IMAGE_TAG}"
LOCAL_CREDENTIALS_PATH=""
if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
  LOCAL_CREDENTIALS_PATH="$(resolve_credentials_path "$GOOGLE_APPLICATION_CREDENTIALS")"
fi

echo "Deploy summary"
echo "  Env file:       $ENV_FILE"
echo "  Project:        $FIRESTORE_PROJECT_ID"
echo "  Region:         $DEPLOY_REGION"
echo "  Service/Image:  $DEPLOY_SERVICE_NAME"
echo "  Image URI:      $IMAGE_URI"
echo "  Namespace:      $NAMESPACE"
echo "  K8S App:        $K8S_APP_NAME"
echo "  K8S Service:    $K8S_SERVICE_NAME"
echo "  K8S ConfigMap:  $K8S_CONFIGMAP_NAME"
echo "  K8S Secret:     $K8S_SECRET_NAME"
echo "  Local image:    $LOCAL_IMAGE"
echo "  K8S SA:         $K8S_SERVICE_ACCOUNT_NAME"
if [[ -n "$GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT" ]]; then
  echo "  GCP SA:         $GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT"
fi
if [[ -n "$STATIC_LB_IP" ]]; then
  echo "  Static LB IP:   $STATIC_LB_IP"
fi
echo "  Ingress:        $K8S_INGRESS_ENABLED"
if [[ "$K8S_INGRESS_ENABLED" == "true" ]]; then
  echo "  Ingress Host:   ${K8S_INGRESS_HOST:-<none>}"
  if [[ -n "$K8S_INGRESS_STATIC_IP_NAME" ]]; then
    echo "  Ingress IP:     $K8S_INGRESS_STATIC_IP_NAME"
  fi
  if [[ -n "$K8S_MANAGED_CERT_NAME" ]]; then
    echo "  Managed Cert:   $K8S_MANAGED_CERT_NAME"
  fi
  if [[ -n "$K8S_PRE_SHARED_CERT_NAME" ]]; then
    echo "  Pre-shared SSL: $K8S_PRE_SHARED_CERT_NAME"
  fi
  if [[ -n "$K8S_TLS_SECRET_NAME" ]]; then
    echo "  TLS Secret:     $K8S_TLS_SECRET_NAME"
  fi
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

tls_mode_count=0
[[ -n "$K8S_MANAGED_CERT_NAME" ]] && tls_mode_count=$((tls_mode_count + 1))
[[ -n "$K8S_PRE_SHARED_CERT_NAME" ]] && tls_mode_count=$((tls_mode_count + 1))
[[ -n "$K8S_TLS_SECRET_NAME" ]] && tls_mode_count=$((tls_mode_count + 1))

if [[ "$tls_mode_count" -gt 1 ]]; then
  echo "ERROR: choose only one TLS mode: K8S_MANAGED_CERT_NAME, K8S_PRE_SHARED_CERT_NAME or K8S_TLS_SECRET_NAME."
  exit 1
fi

if [[ "$K8S_DISABLE_HTTP" == "true" && "$tls_mode_count" -eq 0 ]]; then
  echo "ERROR: K8S_DISABLE_HTTP=true requires a TLS mode."
  exit 1
fi

if [[ -n "$K8S_MANAGED_CERT_NAME" && -z "$K8S_INGRESS_HOST" ]]; then
  echo "ERROR: K8S_MANAGED_CERT_NAME requires K8S_INGRESS_HOST."
  exit 1
fi

if [[ "$K8S_INGRESS_ENABLED" == "true" && "$K8S_SERVICE_TYPE" == "LoadBalancer" ]]; then
  echo "WARNING: Ingress is enabled while service type is LoadBalancer."
  echo "         This works, but usually NodePort is cleaner behind GCE Ingress."
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
render_manifest "$SCRIPT_DIR/deploy/k8s/serviceaccount.yaml" | kubectl apply -n "$NAMESPACE" -f -
if [[ -n "$GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT" ]]; then
  kubectl annotate -n "$NAMESPACE" serviceaccount/"$K8S_SERVICE_ACCOUNT_NAME" \
    iam.gke.io/gcp-service-account="$GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT" \
    --overwrite
fi
render_manifest "$SCRIPT_DIR/deploy/k8s/configmap.yaml" | kubectl apply -n "$NAMESPACE" -f -
render_manifest "$SCRIPT_DIR/deploy/k8s/service.yaml" | kubectl apply -n "$NAMESPACE" -f -
if [[ -n "$STATIC_LB_IP" ]]; then
  echo "Pinning LoadBalancer static IP: $STATIC_LB_IP"
  kubectl patch -n "$NAMESPACE" service/"$K8S_SERVICE_NAME" \
    --type=merge \
    -p "{\"spec\":{\"type\":\"LoadBalancer\",\"loadBalancerIP\":\"$STATIC_LB_IP\"}}"
fi
render_manifest "$SCRIPT_DIR/deploy/k8s/deployment.yaml" | kubectl apply -n "$NAMESPACE" -f -

if [[ "$K8S_INGRESS_ENABLED" == "true" ]]; then
  if [[ -n "$K8S_MANAGED_CERT_NAME" ]]; then
    render_manifest "$SCRIPT_DIR/deploy/k8s/managed-certificate.yaml" | kubectl apply -n "$NAMESPACE" -f -
  fi
  render_ingress_manifest | kubectl apply -n "$NAMESPACE" -f -
fi

echo "Applying runtime env secret from $ENV_FILE"
kubectl create secret generic "$K8S_SECRET_NAME" \
  --from-env-file="$ENV_FILE" \
  --dry-run=client -o yaml | kubectl apply -n "$NAMESPACE" -f -

kubectl set image -n "$NAMESPACE" deployment/"$K8S_APP_NAME" api="$IMAGE_URI"
echo "Restarting deployment to apply secret/env changes..."
kubectl rollout restart -n "$NAMESPACE" deployment/"$K8S_APP_NAME"
kubectl rollout status -n "$NAMESPACE" deployment/"$K8S_APP_NAME" --timeout=240s

echo "Deployment completed."
kubectl get pods -n "$NAMESPACE" -o wide
kubectl get svc -n "$NAMESPACE" "$K8S_SERVICE_NAME" -o wide
if [[ "$K8S_INGRESS_ENABLED" == "true" ]]; then
  kubectl get ingress -n "$NAMESPACE" "$K8S_APP_NAME" -o wide || true
fi

CURRENT_IMAGE="$(kubectl get -n "$NAMESPACE" deployment/"$K8S_APP_NAME" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true)"
if [[ -n "$CURRENT_IMAGE" ]]; then
  echo "Deployed image: $CURRENT_IMAGE"
fi

EXTERNAL_IP="$(kubectl get -n "$NAMESPACE" svc/"$K8S_SERVICE_NAME" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
INGRESS_IP=""
if [[ "$K8S_INGRESS_ENABLED" == "true" ]]; then
  INGRESS_IP="$(kubectl get -n "$NAMESPACE" ingress/"$K8S_APP_NAME" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
fi
if [[ -n "$EXTERNAL_IP" ]]; then
  echo "Public endpoints:"
  echo "  http://$EXTERNAL_IP/"
  echo "  http://$EXTERNAL_IP/api-docs"
  echo "  http://$EXTERNAL_IP/openapi.json"
  echo "  http://$EXTERNAL_IP/.well-known/did.json"
else
  echo "Public EXTERNAL-IP is pending."
  echo "Watch with:"
  echo "  kubectl -n $NAMESPACE get svc $K8S_SERVICE_NAME -w"
fi

if [[ "$K8S_INGRESS_ENABLED" == "true" ]]; then
  if [[ -n "$INGRESS_IP" ]]; then
    echo "Ingress endpoints:"
    if [[ "$K8S_DISABLE_HTTP" != "true" ]]; then
      echo "  http://$INGRESS_IP/"
    fi
    if [[ "$tls_mode_count" -gt 0 ]]; then
      echo "  https://$INGRESS_IP/"
    fi
    if [[ -n "$K8S_INGRESS_HOST" ]]; then
      if [[ "$K8S_DISABLE_HTTP" != "true" ]]; then
        echo "  http://$K8S_INGRESS_HOST/"
      fi
      if [[ "$tls_mode_count" -gt 0 ]]; then
        echo "  https://$K8S_INGRESS_HOST/"
      fi
    fi
  else
    echo "Ingress EXTERNAL-IP is pending."
    echo "Watch with:"
    echo "  kubectl -n $NAMESPACE get ingress $K8S_APP_NAME -w"
  fi
fi
