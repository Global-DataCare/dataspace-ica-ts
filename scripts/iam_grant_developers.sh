#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Grant IAM roles for developers across billing, org/folder, and projects.

Usage:
  ./scripts/iam_grant_developers.sh \
    --members "dev1@example.com,devops@example.com" \
    --member-type user \
    --projects "globaldatacare-ica-dev,globaldatacare-test" \
    --billing-account "014A34-6E960C-35E085" \
    --org-id "123456789012" \
    [--dry-run]

Required:
  --members            Comma-separated list. Entries can be plain emails or full IAM members
                       (e.g. user:dev@x.com, group:team@x.com, serviceAccount:sa@p.iam.gserviceaccount.com).
  --projects           Comma-separated project ids.
  --billing-account    Billing account id.

At least one:
  --org-id             Organization id for project creation role binding.
  --folder-id          Folder id for project creation role binding.

Optional:
  --member-type        Prefix for plain emails when member string has no ":". Default: user
                       Allowed: user | group | serviceAccount | domain
  --project-roles      Comma-separated roles for each project.
                       Default:
                         roles/container.admin,
                         roles/iam.serviceAccountUser,
                         roles/serviceusage.serviceUsageAdmin,
                         roles/artifactregistry.admin
  --skip-project-creator  Do not grant roles/resourcemanager.projectCreator
  --skip-billing-user     Do not grant roles/billing.user
  --dry-run               Print commands without executing
  -h, --help              Show help
EOF
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

split_csv() {
  local input="$1"
  local -n out_ref="$2"
  out_ref=()
  IFS=',' read -r -a raw_items <<<"$input"
  for item in "${raw_items[@]}"; do
    item="$(trim "$item")"
    [[ -z "$item" ]] && continue
    out_ref+=("$item")
  done
}

run_cmd() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[dry-run] '
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

MEMBERS_RAW=""
PROJECTS_RAW=""
BILLING_ACCOUNT_ID=""
ORG_ID=""
FOLDER_ID=""
MEMBER_TYPE="user"
PROJECT_ROLES_RAW="roles/container.admin,roles/iam.serviceAccountUser,roles/serviceusage.serviceUsageAdmin,roles/artifactregistry.admin"
GRANT_PROJECT_CREATOR="true"
GRANT_BILLING_USER="true"
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --members)
      MEMBERS_RAW="${2:-}"
      shift 2
      ;;
    --projects)
      PROJECTS_RAW="${2:-}"
      shift 2
      ;;
    --billing-account)
      BILLING_ACCOUNT_ID="${2:-}"
      shift 2
      ;;
    --org-id)
      ORG_ID="${2:-}"
      shift 2
      ;;
    --folder-id)
      FOLDER_ID="${2:-}"
      shift 2
      ;;
    --member-type)
      MEMBER_TYPE="${2:-}"
      shift 2
      ;;
    --project-roles)
      PROJECT_ROLES_RAW="${2:-}"
      shift 2
      ;;
    --skip-project-creator)
      GRANT_PROJECT_CREATOR="false"
      shift
      ;;
    --skip-billing-user)
      GRANT_BILLING_USER="false"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$MEMBERS_RAW" || -z "$PROJECTS_RAW" || -z "$BILLING_ACCOUNT_ID" ]]; then
  echo "ERROR: --members, --projects and --billing-account are required."
  usage
  exit 1
fi

if [[ "$GRANT_PROJECT_CREATOR" == "true" && -z "$ORG_ID" && -z "$FOLDER_ID" ]]; then
  echo "ERROR: --org-id or --folder-id is required unless --skip-project-creator is used."
  exit 1
fi

case "$MEMBER_TYPE" in
  user|group|serviceAccount|domain) ;;
  *)
    echo "ERROR: --member-type must be one of: user, group, serviceAccount, domain"
    exit 1
    ;;
esac

declare -a MEMBERS PROJECTS PROJECT_ROLES
split_csv "$MEMBERS_RAW" MEMBERS
split_csv "$PROJECTS_RAW" PROJECTS
split_csv "$PROJECT_ROLES_RAW" PROJECT_ROLES

if [[ ${#MEMBERS[@]} -eq 0 || ${#PROJECTS[@]} -eq 0 || ${#PROJECT_ROLES[@]} -eq 0 ]]; then
  echo "ERROR: members/projects/project-roles cannot be empty."
  exit 1
fi

declare -a IAM_MEMBERS
for member in "${MEMBERS[@]}"; do
  if [[ "$member" == *:* ]]; then
    IAM_MEMBERS+=("$member")
  else
    IAM_MEMBERS+=("${MEMBER_TYPE}:$member")
  fi
done

echo "Grant plan"
echo "  Members: ${IAM_MEMBERS[*]}"
echo "  Projects: ${PROJECTS[*]}"
echo "  Billing account: $BILLING_ACCOUNT_ID"
echo "  Org id: ${ORG_ID:-<none>}"
echo "  Folder id: ${FOLDER_ID:-<none>}"
echo "  Project roles: ${PROJECT_ROLES[*]}"
echo "  Dry run: $DRY_RUN"

for member in "${IAM_MEMBERS[@]}"; do
  if [[ "$GRANT_PROJECT_CREATOR" == "true" ]]; then
    if [[ -n "$ORG_ID" ]]; then
      run_cmd gcloud organizations add-iam-policy-binding "$ORG_ID" \
        --member="$member" \
        --role="roles/resourcemanager.projectCreator"
    else
      run_cmd gcloud resource-manager folders add-iam-policy-binding "$FOLDER_ID" \
        --member="$member" \
        --role="roles/resourcemanager.projectCreator"
    fi
  fi

  if [[ "$GRANT_BILLING_USER" == "true" ]]; then
    run_cmd gcloud beta billing accounts add-iam-policy-binding "$BILLING_ACCOUNT_ID" \
      --member="$member" \
      --role="roles/billing.user"
  fi

  for project in "${PROJECTS[@]}"; do
    for role in "${PROJECT_ROLES[@]}"; do
      run_cmd gcloud projects add-iam-policy-binding "$project" \
        --member="$member" \
        --role="$role"
    done
  done
done

echo "Done."
