#!/usr/bin/env bash
# Journey: 1) start isolated Firestore/PostgreSQL/Kubo; 2) seed synthetic ICA
# records and audit bytes; 3) migrate to PostgreSQL/IPFS; 4) reread every
# record and CID; 5) verify reconciliation hashes; 6) destroy runtime state.
# Authorization invariant: the runner accepts only the demo Firestore project
# and explicit private-encrypted IPFS custody confirmation.
# Persistence invariant: PostgreSQL and CID bytes must survive independent
# rereads before evidence is marked PASS; no real participant data is used.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT}/deploy/local-migration/docker-compose.yml"
COMPOSE_PROJECT="ica-migration-$$"
WORK_DIR="$(mktemp -d)"
AUDIT_SOURCE_DIR="${WORK_DIR}/source-gcs"
OUTPUT_DIR="${ICA_MIGRATION_EVIDENCE_DIR:-${ROOT}/artifacts/postgres-ipfs-migration-$(date -u +%Y%m%dT%H%M%SZ)}"
FIREBASE_LOG="${WORK_DIR}/firestore-emulator.log"
FIREBASE_PID=''

cleanup() {
  if [[ -n "${FIREBASE_PID}" ]]; then kill "${FIREBASE_PID}" >/dev/null 2>&1 || true; fi
  docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" down --volumes >/dev/null 2>&1 || true
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

for command in docker firebase node curl jq shasum; do
  command -v "${command}" >/dev/null || { echo "Missing ${command}" >&2; exit 1; }
done
[[ ! -e "${OUTPUT_DIR}" ]] || { echo "Evidence directory already exists: ${OUTPUT_DIR}" >&2; exit 1; }

if [[ -n "${ICA_MIGRATION_JAVA_HOME:-}" ]]; then
  export JAVA_HOME="${ICA_MIGRATION_JAVA_HOME}"
elif [[ -x /usr/local/opt/openjdk@21/bin/java ]]; then
  export JAVA_HOME='/usr/local/opt/openjdk@21'
fi
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="${JAVA_HOME}/bin:${PATH}"; fi
java_major="$(java -version 2>&1 | sed -nE '1s/.*version "([0-9]+).*/\1/p')"
[[ "${java_major:-0}" -ge 21 ]] || {
  echo 'Firebase Emulator requires Java 21+. Set ICA_MIGRATION_JAVA_HOME.' >&2
  exit 1
}

export ICA_MIGRATION_POSTGRES_PORT="${ICA_MIGRATION_POSTGRES_PORT:-55434}"
export ICA_MIGRATION_IPFS_API_PORT="${ICA_MIGRATION_IPFS_API_PORT:-55003}"
docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" up -d

firebase emulators:start --only firestore \
  --config "${ROOT}/deploy/local-migration/firebase.json" \
  --project demo-ica-migration >"${FIREBASE_LOG}" 2>&1 &
FIREBASE_PID="$!"

for attempt in $(seq 1 60); do
  if docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" exec -T postgres \
      pg_isready -U ica -d ica >/dev/null 2>&1 \
    && curl -fsS -X POST "http://127.0.0.1:${ICA_MIGRATION_IPFS_API_PORT}/api/v0/version" >/dev/null \
    && curl -sS "http://127.0.0.1:58080" >/dev/null; then
    break
  fi
  [[ "${attempt}" -lt 60 ]] || { cat "${FIREBASE_LOG}" >&2; exit 1; }
  sleep 1
done

export FIRESTORE_EMULATOR_HOST='127.0.0.1:58080'
export FIRESTORE_PROJECT_ID='demo-ica-migration'
export ICA_MIGRATION_CONFIRM_SOURCE_PROJECT="${FIRESTORE_PROJECT_ID}"
export ICA_MIGRATION_SOURCE_COLLECTIONS_PREFIX='migration_source'
export ICA_MIGRATION_TARGET_COLLECTIONS_PREFIX='migration_target'
export ICA_MIGRATION_AUDIT_SOURCE_DIR="${AUDIT_SOURCE_DIR}"
export ICA_MIGRATION_OUTPUT_DIR="${OUTPUT_DIR}"
export POSTGRES_URL="postgresql://ica:ica-local-migration@127.0.0.1:${ICA_MIGRATION_POSTGRES_PORT}/ica"
export IPFS_API_URL="http://127.0.0.1:${ICA_MIGRATION_IPFS_API_PORT}"
export ICA_MIGRATION_IPFS_CUSTODY='private-encrypted'
export ICA_MIGRATION_DATA_PROTECTION_CONFIRMED='true'

node "${ROOT}/scripts/migration/seed-synthetic-firestore-source.ts"
node "${ROOT}/src/api/scripts/migrate-firestore-gcs-to-postgres-ipfs.ts" --apply

POSTGRES_MIGRATION_TEST_URL="${POSTGRES_URL}" \
IPFS_MIGRATION_TEST_API_URL="${IPFS_API_URL}" \
  node --test "${ROOT}/test/integration/postgres-ipfs-migration.integration.test.ts"

jq -e '.sourceDigestSha256 == .targetDigestSha256 and (.unresolvedGcsReferences | length == 0)' \
  "${OUTPUT_DIR}/postgres-migration-report.json" >/dev/null
jq -e '.objectCount == 1 and (.objects | length == 1)' \
  "${OUTPUT_DIR}/audit-ipfs-manifest.json" >/dev/null
(
  cd "${OUTPUT_DIR}"
  shasum -a 256 audit-ipfs-manifest.json postgres-migration-report.json > SHA256SUMS
  shasum -a 256 -c SHA256SUMS
)
printf 'PASS\n' > "${OUTPUT_DIR}/PASS"
echo 'Local PostgreSQL/IPFS migration evidence: PASS'
