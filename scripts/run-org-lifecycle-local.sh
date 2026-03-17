#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

API_BASE_URL="${API_BASE_URL:-http://127.0.0.1:3310}"
CURL_INSECURE="${CURL_INSECURE:-false}"
TENANT_ID="${TENANT_ID:-ica}"
JURISDICTION="${JURISDICTION:-ES}"
SECTOR="${SECTOR:-animal-care}"
RESOURCE_TYPE="${RESOURCE_TYPE:-contract}"
PDF_PATH="${PDF_PATH:-${REPO_DIR}/../TEST-A4-multisign-fnmt.pdf}"
ORG_URL="${ORG_URL:-member.example.org}"
POLL_SLEEP_SECONDS="${POLL_SLEEP_SECONDS:-1}"
POLL_MAX_ATTEMPTS="${POLL_MAX_ATTEMPTS:-20}"
ARTIFACTS_ROOT="${ARTIFACTS_ROOT:-${REPO_DIR}/artifacts/smoke/org-lifecycle}"
RUN_ID="${RUN_ID:-$(date '+%Y%m%d-%H%M%S')}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-${ARTIFACTS_ROOT}/${RUN_ID}}"

CURL_ARGS=(-sS)
if [[ "${CURL_INSECURE}" == "true" ]]; then
  CURL_ARGS+=(-k)
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required." >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required." >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  echo "node is required." >&2
  exit 1
fi
if [[ ! -f "${PDF_PATH}" ]]; then
  echo "PDF not found: ${PDF_PATH}" >&2
  exit 1
fi

mkdir -p "${ARTIFACTS_DIR}"
TMP_DIR="${ARTIFACTS_DIR}"

VERIFY_URL="${API_BASE_URL}/${TENANT_ID}/cds-${JURISDICTION}/v1/${SECTOR}/terms/pdf/${RESOURCE_TYPE}/_verify"
CREATE_URL="${API_BASE_URL}/${TENANT_ID}/cds-${JURISDICTION}/v1/${SECTOR}/entity/did/document/_create"
REMOVE_URL="${API_BASE_URL}/${TENANT_ID}/cds-${JURISDICTION}/v1/${SECTOR}/terms/pdf/${RESOURCE_TYPE}/_remove"

log() {
  printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

log_kv() {
  printf '  - %s: %s\n' "$1" "$2"
}

fail_with_response() {
  local message="$1"
  local file="$2"
  echo "${message}" >&2
  if [[ -f "${file}" ]]; then
    echo "--- response body (${file}) ---" >&2
    cat "${file}" >&2
    echo >&2
    echo "--- end response body ---" >&2
  fi
  exit 1
}

require_json_field() {
  local file="$1"
  local jq_expr="$2"
  local label="$3"
  local value
  value="$(jq -cer "${jq_expr}" "${file}")" || {
    echo "Missing ${label} in ${file}" >&2
    exit 1
  }
  printf '%s' "${value}"
}

post_didcomm() {
  local url="$1"
  local payload_file="$2"
  local headers_file="$3"
  local body_file="$4"

  curl "${CURL_ARGS[@]}" \
    -X POST \
    -H 'Content-Type: application/didcomm-plain+json' \
    -D "${headers_file}" \
    -o "${body_file}" \
    --data-binary "@${payload_file}" \
    "${url}"
}

poll_location() {
  local location="$1"
  local out_file="$2"
  local attempt=1

  while (( attempt <= POLL_MAX_ATTEMPTS )); do
    local headers_file="${TMP_DIR}/poll-${attempt}.headers"
    local body_file="${TMP_DIR}/poll-${attempt}.json"
    local status
    status="$(curl "${CURL_ARGS[@]}" \
      -X POST \
      -H 'Content-Type: application/didcomm-plain+json' \
      -D "${headers_file}" \
      -o "${body_file}" \
      --data '{}' \
      -w '%{http_code}' \
      "${location}")"

    if [[ "${status}" == "202" ]]; then
      sleep "${POLL_SLEEP_SECONDS}"
      attempt=$((attempt + 1))
      continue
    fi

    if [[ "${status}" != "200" ]]; then
      echo "Polling failed for ${location} with HTTP ${status}" >&2
      cat "${body_file}" >&2 || true
      exit 1
    fi

    cp "${body_file}" "${out_file}"
    return 0
  done

  echo "Polling timed out for ${location}" >&2
  exit 1
}

extract_location() {
  local headers_file="$1"
  local location
  location="$(
    grep -i '^location:' "${headers_file}" \
      | tail -n 1 \
      | sed -E 's/^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[[:space:]]*//; s/\r$//'
  )"
  if [[ -z "${location}" ]]; then
    echo "Missing Location header in ${headers_file}" >&2
    cat "${headers_file}" >&2 || true
    exit 1
  fi
  if [[ "${location}" == http* ]]; then
    printf '%s' "${location}"
    return 0
  fi
  printf '%s%s' "${API_BASE_URL}" "${location}"
}

generate_controller_keypair() {
  node --input-type=module -e "
    import { generateKeyPairSync } from 'node:crypto';
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    const publicKeyJwk = publicKey.export({ format: 'jwk' });
    publicKeyJwk.alg = 'ES384';
    publicKeyJwk.use = 'sig';
    publicKeyJwk.kid = 'controller-msg-es384-local';
    const privateKeyJwk = privateKey.export({ format: 'jwk' });
    privateKeyJwk.alg = 'ES384';
    privateKeyJwk.use = 'sig';
    privateKeyJwk.kid = publicKeyJwk.kid;
    console.log(JSON.stringify({ publicKeyJwk, privateKeyJwk }, null, 2));
  "
}

build_verify_payload() {
  local thid="$1"
  local jti="$2"
  local controller_jwk_file="$3"
  local attachment_block="$4"
  local payload_file="$5"

  local pdf_b64
  pdf_b64="$(base64 < "${PDF_PATH}" | tr -d '\n')"

  jq -n \
    --arg thid "${thid}" \
    --arg jti "${jti}" \
    --arg pdfB64 "${pdf_b64}" \
    --slurpfile controller "${controller_jwk_file}" \
    --argjson attachmentBlock "${attachment_block}" \
    '{
      jti: $jti,
      thid: $thid,
      type: "https://globaldatacare.es/didcomm/ica/terms/verify-request/v1",
      meta: {
        jws: {
          protected: {
            alg: "ES384",
            kid: $controller[0].kid,
            jwk: $controller[0]
          }
        }
      },
      body: {},
      attachments: (
        [
          {
            id: "signed-terms",
            media_type: "application/pdf",
            data: { base64: $pdfB64 }
          }
        ] + $attachmentBlock
      )
    }' > "${payload_file}"
}

build_create_payload() {
  local thid="$1"
  local org_identifier="$2"
  local org_tax_id="$3"
  local org_public_jwk_file="$4"
  local controller_same_as="$5"
  local controller_public_jwk_file="$6"
  local payload_file="$7"

  jq -n \
    --arg thid "${thid}" \
    --arg identifier "${org_identifier}" \
    --arg taxID "${org_tax_id}" \
    --arg sameAs "${controller_same_as}" \
    --slurpfile orgJwk "${org_public_jwk_file}" \
    --slurpfile controllerJwk "${controller_public_jwk_file}" \
    '{
      thid: $thid,
      type: "https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1",
      body: {
        data: [
          {
            resource: {
              organization: {
                identifier: $identifier,
                taxID: $taxID,
                publicKeyJwk: $orgJwk[0]
              },
              controller: (
                {
                  publicKeyJwk: $controllerJwk[0]
                }
                + (if $sameAs != "" then { sameAs: $sameAs } else {} end)
              )
            }
          }
        ]
      }
    }' > "${payload_file}"
}

build_remove_payload() {
  local thid="$1"
  local org_identifier="$2"
  local org_tax_id="$3"
  local controller_same_as="$4"
  local controller_public_jwk_file="$5"
  local payload_file="$6"

  jq -n \
    --arg thid "${thid}" \
    --arg identifier "${org_identifier}" \
    --arg taxID "${org_tax_id}" \
    --arg sameAs "${controller_same_as}" \
    --slurpfile controller "${controller_public_jwk_file}" \
    '{
      thid: $thid,
      type: "https://globaldatacare.es/didcomm/ica/terms/remove-request/v1",
      meta: {
        jws: {
          protected: {
            alg: "ES384",
            kid: $controller[0].kid,
            jwk: $controller[0]
          }
        }
      },
      body: {
        data: [
          {
            resource: {
              organization: {
                taxID: $taxID,
                identifier: $identifier
              },
              controller: (
                if $sameAs != "" then { sameAs: $sameAs } else {} end
              ),
              reason: "organization-requested-removal"
            }
          }
        ]
      }
    }' > "${payload_file}"
}

extract_verify_outputs() {
  local verify_response_file="$1"
  local out_prefix="$2"

  local organization_count
  local person_count
  organization_count="$(jq -r '[.body.data[]? | select(.type=="Organization-verification-v1.0")] | length' "${verify_response_file}")"
  person_count="$(jq -r '[.body.data[]? | select(.type=="LegalRepresentative-verification-v1.0")] | length' "${verify_response_file}")"

  if [[ "${organization_count}" == "0" ]]; then
    fail_with_response "Verify response does not contain Organization-verification-v1.0." "${verify_response_file}"
  fi
  if [[ "${person_count}" == "0" ]]; then
    fail_with_response "Verify response does not contain LegalRepresentative-verification-v1.0." "${verify_response_file}"
  fi

  jq -ce '.body.data[] | select(.type=="Organization-verification-v1.0") | .publicKeyJwk' "${verify_response_file}" > "${out_prefix}-org-public.json"
  jq -ce '.body.data[] | select(.type=="Organization-verification-v1.0") | .privateKeyJwk' "${verify_response_file}" > "${out_prefix}-org-private.json"
  jq -ce '.body.data[] | select(.type=="Organization-verification-v1.0") | .resource.credentialSubject.id' "${verify_response_file}" > "${out_prefix}-org-id.json"
  jq -ce '.body.data[] | select(.type=="Organization-verification-v1.0") | .resource.credentialSubject.taxID' "${verify_response_file}" > "${out_prefix}-org-taxid.json"
  jq -ce '.body.data[] | select(.type=="LegalRepresentative-verification-v1.0") | (.resource.credentialSubject.sameAs // "")' "${verify_response_file}" > "${out_prefix}-controller-sameas.json"
}

run_verify_cycle() {
  local cycle_name="$1"
  local attachment_block_json="$2"
  local verify_payload="${TMP_DIR}/${cycle_name}-verify-request.json"
  local verify_headers="${TMP_DIR}/${cycle_name}-verify.headers"
  local verify_submit_body="${TMP_DIR}/${cycle_name}-verify-submit.json"
  local verify_response="${TMP_DIR}/${cycle_name}-verify-response.json"

  build_verify_payload "${cycle_name}-verify-thid" "${cycle_name}-verify-jti" \
    "${TMP_DIR}/controller-public.json" "${attachment_block_json}" "${verify_payload}"

  log "${cycle_name}: _verify"
  post_didcomm "${VERIFY_URL}" "${verify_payload}" "${verify_headers}" "${verify_submit_body}" >/dev/null
  local verify_location
  verify_location="$(extract_location "${verify_headers}")"
  log_kv "verify poll" "${verify_location}"
  poll_location "${verify_location}" "${verify_response}"
  log_kv "verify response" "${verify_response}"
  extract_verify_outputs "${verify_response}" "${TMP_DIR}/${cycle_name}"

  local org_identifier
  local org_tax_id
  local controller_same_as
  org_identifier="$(jq -r '.' "${TMP_DIR}/${cycle_name}-org-id.json")"
  org_tax_id="$(jq -r '.' "${TMP_DIR}/${cycle_name}-org-taxid.json")"
  controller_same_as="$(jq -r '.' "${TMP_DIR}/${cycle_name}-controller-sameas.json")"

  log "${cycle_name}: verified org taxID=${org_tax_id} did=${org_identifier}"
  log "${cycle_name}: organization private key returned once and saved to ${TMP_DIR}/${cycle_name}-org-private.json"

  local create_payload="${TMP_DIR}/${cycle_name}-create-request.json"
  local create_headers="${TMP_DIR}/${cycle_name}-create.headers"
  local create_submit_body="${TMP_DIR}/${cycle_name}-create-submit.json"
  local create_response="${TMP_DIR}/${cycle_name}-create-response.json"
  build_create_payload "${cycle_name}-create-thid" "${org_identifier}" "${org_tax_id}" \
    "${TMP_DIR}/${cycle_name}-org-public.json" "${controller_same_as}" "${TMP_DIR}/controller-public.json" "${create_payload}"

  log "${cycle_name}: _create"
  post_didcomm "${CREATE_URL}" "${create_payload}" "${create_headers}" "${create_submit_body}" >/dev/null
  local create_location
  create_location="$(extract_location "${create_headers}")"
  log_kv "create poll" "${create_location}"
  poll_location "${create_location}" "${create_response}"
  log_kv "create response" "${create_response}"

  local did_id
  did_id="$(require_json_field "${create_response}" '.body.data[0].resource.didDocument.id' 'didDocument.id')"
  log "${cycle_name}: created DID document ${did_id}"

  echo "${org_identifier}" > "${TMP_DIR}/${cycle_name}-org-identifier.txt"
  echo "${org_tax_id}" > "${TMP_DIR}/${cycle_name}-org-taxid.txt"
  echo "${controller_same_as}" > "${TMP_DIR}/${cycle_name}-controller-sameas.txt"
}

log "Generating controller ES384 keypair"
log_kv "api base" "${API_BASE_URL}"
log_kv "tenant" "${TENANT_ID}"
log_kv "jurisdiction" "${JURISDICTION}"
log_kv "sector" "${SECTOR}"
log_kv "resourceType" "${RESOURCE_TYPE}"
log_kv "pdf" "${PDF_PATH}"
log_kv "artifacts" "${ARTIFACTS_DIR}"
generate_controller_keypair > "${TMP_DIR}/controller-keypair.json"
jq -ce '.publicKeyJwk' "${TMP_DIR}/controller-keypair.json" > "${TMP_DIR}/controller-public.json"
jq -ce '.privateKeyJwk' "${TMP_DIR}/controller-keypair.json" > "${TMP_DIR}/controller-private.json"

run_verify_cycle "cycle1" '[]'

ORG_IDENTIFIER="$(cat "${TMP_DIR}/cycle1-org-identifier.txt")"
ORG_TAX_ID="$(cat "${TMP_DIR}/cycle1-org-taxid.txt")"
CONTROLLER_SAME_AS="$(cat "${TMP_DIR}/cycle1-controller-sameas.txt")"

REMOVE_PAYLOAD="${TMP_DIR}/cycle1-remove-request.json"
REMOVE_HEADERS="${TMP_DIR}/cycle1-remove.headers"
REMOVE_SUBMIT_BODY="${TMP_DIR}/cycle1-remove-submit.json"
REMOVE_RESPONSE="${TMP_DIR}/cycle1-remove-response.json"

build_remove_payload "cycle1-remove-thid" "${ORG_IDENTIFIER}" "${ORG_TAX_ID}" "${CONTROLLER_SAME_AS}" \
  "${TMP_DIR}/controller-public.json" "${REMOVE_PAYLOAD}"

log "cycle1: _remove"
post_didcomm "${REMOVE_URL}" "${REMOVE_PAYLOAD}" "${REMOVE_HEADERS}" "${REMOVE_SUBMIT_BODY}" >/dev/null
REMOVE_LOCATION="$(extract_location "${REMOVE_HEADERS}")"
log_kv "remove poll" "${REMOVE_LOCATION}"
poll_location "${REMOVE_LOCATION}" "${REMOVE_RESPONSE}"
log_kv "remove response" "${REMOVE_RESPONSE}"
REMOVED_DID="$(require_json_field "${REMOVE_RESPONSE}" '.body.data[0].resource.did' 'removed did')"
log "cycle1: removed terms for ${REMOVED_DID}"

run_verify_cycle "cycle2" '[]'

ORG_IDENTIFIER="$(cat "${TMP_DIR}/cycle2-org-identifier.txt")"
ORG_TAX_ID="$(cat "${TMP_DIR}/cycle2-org-taxid.txt")"
CONTROLLER_SAME_AS="$(cat "${TMP_DIR}/cycle2-controller-sameas.txt")"

REMOVE_PAYLOAD="${TMP_DIR}/cycle2-remove-request.json"
REMOVE_HEADERS="${TMP_DIR}/cycle2-remove.headers"
REMOVE_SUBMIT_BODY="${TMP_DIR}/cycle2-remove-submit.json"
REMOVE_RESPONSE="${TMP_DIR}/cycle2-remove-response.json"

build_remove_payload "cycle2-remove-thid" "${ORG_IDENTIFIER}" "${ORG_TAX_ID}" "${CONTROLLER_SAME_AS}" \
  "${TMP_DIR}/controller-public.json" "${REMOVE_PAYLOAD}"

log "cycle2: _remove"
post_didcomm "${REMOVE_URL}" "${REMOVE_PAYLOAD}" "${REMOVE_HEADERS}" "${REMOVE_SUBMIT_BODY}" >/dev/null
REMOVE_LOCATION="$(extract_location "${REMOVE_HEADERS}")"
log_kv "remove poll" "${REMOVE_LOCATION}"
poll_location "${REMOVE_LOCATION}" "${REMOVE_RESPONSE}"
log_kv "remove response" "${REMOVE_RESPONSE}"
REMOVED_DID="$(require_json_field "${REMOVE_RESPONSE}" '.body.data[0].resource.did' 'removed did')"
log "cycle2: removed terms for ${REMOVED_DID}"

jq -n \
  --arg apiBaseUrl "${API_BASE_URL}" \
  --arg tenantId "${TENANT_ID}" \
  --arg jurisdiction "${JURISDICTION}" \
  --arg sector "${SECTOR}" \
  --arg resourceType "${RESOURCE_TYPE}" \
  --arg pdfPath "${PDF_PATH}" \
  --arg artifactsDir "${ARTIFACTS_DIR}" \
  --arg cycle1Did "$(cat "${TMP_DIR}/cycle1-org-identifier.txt")" \
  --arg cycle1TaxId "$(cat "${TMP_DIR}/cycle1-org-taxid.txt")" \
  --arg cycle2Did "$(cat "${TMP_DIR}/cycle2-org-identifier.txt")" \
  --arg cycle2TaxId "$(cat "${TMP_DIR}/cycle2-org-taxid.txt")" \
  '{
    apiBaseUrl: $apiBaseUrl,
    tenantId: $tenantId,
    jurisdiction: $jurisdiction,
    sector: $sector,
    resourceType: $resourceType,
    pdfPath: $pdfPath,
    artifactsDir: $artifactsDir,
    result: "completed-removed",
    cycle1: {
      did: $cycle1Did,
      taxID: $cycle1TaxId,
      verifyResponse: "cycle1-verify-response.json",
      createResponse: "cycle1-create-response.json",
      removeResponse: "cycle1-remove-response.json",
      orgPublicKey: "cycle1-org-public.json",
      orgPrivateKey: "cycle1-org-private.json"
    },
    cycle2: {
      did: $cycle2Did,
      taxID: $cycle2TaxId,
      verifyResponse: "cycle2-verify-response.json",
      createResponse: "cycle2-create-response.json",
      removeResponse: "cycle2-remove-response.json",
      orgPublicKey: "cycle2-org-public.json",
      orgPrivateKey: "cycle2-org-private.json"
    }
  }' > "${TMP_DIR}/summary.json"

log "Completed two organization lifecycle cycles and finished in removed state."
log_kv "summary" "${TMP_DIR}/summary.json"
log_kv "artifacts" "${TMP_DIR}"
