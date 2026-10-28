#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
selected_host=false
if [[ "${1:-}" == --agent ]]; then
  [[ "${2:-}" == host-operator && $# -ge 2 && $# -le 3 ]] || { echo 'invalid explicit agent selector' >&2; exit 1; }
  selected_host=true; shift 2
elif [[ "${1:-}" == -* || $# -gt 1 ]]; then echo 'invalid provisioning arguments' >&2; exit 1
fi
readonly selected_host
env_file="${1:-${root_dir}/.env}"

if (( EUID == 0 )) && [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != root ]]; then
  invoking_home="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
  [[ -n "${invoking_home}" ]] || {
    printf 'Unable to resolve the invoking user home for %s.\n' "${SUDO_USER}" >&2
    exit 1
  }
  export HOME="${invoking_home}"
fi

[[ -r "${env_file}" ]] || {
  printf 'Missing environment file: %s\n' "${env_file}" >&2
  exit 1
}

set -a
# shellcheck disable=SC1090
source "${env_file}"
set +a

if [[ "$selected_host" == true ]]; then
  (( EUID == 0 )) || { echo 'selected preflight requires trusted host root' >&2; exit 1; }
  : "${AGENT_RUNTIME_ROOT:?AGENT_RUNTIME_ROOT required}"
  : "${HOST_OPERATOR_GIT_IDENTITY_MANIFEST:?fourth public Git manifest required}"
  : "${AGENT_GIT_IDENTITY_MANIFEST:?legacy public Git manifest required}"
  node "$root_dir/docker/git-identity.mjs" validate-host-layout "$AGENT_RUNTIME_ROOT"
  node "$root_dir/docker/git-identity.mjs" check-host "$HOST_OPERATOR_GIT_IDENTITY_MANIFEST" "$AGENT_GIT_IDENTITY_MANIFEST" "$AGENT_RUNTIME_ROOT/host-operator/credentials"
  node "$root_dir/scripts/state-storage.mjs" --agent host-operator check "$AGENT_RUNTIME_ROOT" "${HOST_OPERATOR_STATE_BYTES:-536870912}"
  node --input-type=module - "$root_dir" "$AGENT_RUNTIME_ROOT" <<'HOST_PREFLIGHT'
import fs from 'node:fs';import {pathToFileURL}from'node:url';
const [source,root]=process.argv.slice(2);
const {validateHostBuzzKeys}=await import(pathToFileURL(source+'/docker/git-identity.mjs'));
const {validateRecoveryDirectory}=await import(pathToFileURL(source+'/docker/host-operator-entrypoint.mjs'));
const bad=()=>{throw Error('fourth metadata validation failed');};
validateHostBuzzKeys(process.env.BUZZ_AGENT_OWNER_HEX,process.env.HOST_OPERATOR_EXISTING_BUZZ_PUBKEYS,process.env.HOST_OPERATOR_BUZZ_PUBKEY);
if(!/^[A-Za-z0-9_-]{1,128}$/.test(process.env.HOST_OPERATOR_KANEO_USER_ID??'') || !process.env.KANEO_API_URL || !process.env.BUZZ_RELAY_URL)bad();
const home=root+'/state-storage/host-operator',credentials=root+'/host-operator/credentials';
const allowed=['gitconfig','buzz-private-key','buzz-auth-tag','kaneo-credentials.json','codex-auth.json','openai-api-key'];
const names=fs.readdirSync(credentials);
if(names.some(n=>!allowed.includes(n)) || ['gitconfig','buzz-private-key','buzz-auth-tag','kaneo-credentials.json'].some(n=>!names.includes(n)) || !names.some(n=>['codex-auth.json','openai-api-key'].includes(n)))bad();
for(const n of names){const st=fs.lstatSync(credentials+'/'+n);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.uid!==10001||st.gid!==10001||(st.mode&0o7777)!==0o600||!st.size)bad();}
const homeNames=['lost+found','.agent','.cache','.config','.codex','.local','.npm','.gitconfig'];
for(const n of fs.readdirSync(home)){
 if(!homeNames.includes(n))bad();const file=home+'/'+n,st=fs.lstatSync(file);
 if(n==='lost+found'){validateRecoveryDirectory(st);if(fs.readdirSync(file).length)bad();}
 else if(st.isSymbolicLink()||st.uid!==10001||st.gid!==10001||(st.mode&0o7777)!==(st.isDirectory()?0o700:0o600)||(!st.isDirectory() && (n!=='.gitconfig'||!st.isFile()||st.nlink!==1)))bad();
}
const compose=fs.readFileSync(source+'/compose.yaml','utf8').split('  host-operator:')[1];
if(!compose || !/target: \/workspace\n\s+read_only: true/.test(compose))bad();
HOST_PREFLIGHT
  echo 'Fourth-only preflight PASS; no network/actor/model acceptance implied.'
  exit 0
fi

: "${GITHUB_GATEWAY_ALLOWED_OWNERS:=${AGENT_WORKSPACE_ORGANIZATION:-}}"
: "${DISPATCHER_PROVIDER:=claude}"
: "${DEVELOPER_PROVIDER:=codex}"
: "${REVIEWER_PROVIDER:=claude}"

required_variables=(
  AGENT_GIT_IDENTITY_MANIFEST
  BUZZ_RELAY_URL
  KANEO_API_URL
  AGENT_WORKSPACE_ORGANIZATION
  GITHUB_GATEWAY_IMAGE
  GITHUB_GATEWAY_MCP_URL
  GITHUB_GATEWAY_CREDENTIALS_ROOT
  GITHUB_GATEWAY_RUNTIME_DIR
  GITHUB_CONTROL_APP_SLUG
  GITHUB_DEVELOPER_APP_SLUG
  GITHUB_REVIEWER_APP_SLUG
  BUZZ_AGENT_OWNER_HEX
  DISPATCHER_CREDENTIALS_DIR
  DISPATCHER_WORKSPACE
  DEVELOPER_CREDENTIALS_DIR
  DEVELOPER_WORKSPACE
  REVIEWER_CREDENTIALS_DIR
  REVIEWER_WORKSPACE
)

for variable_name in "${required_variables[@]}"; do
  [[ -n "${!variable_name:-}" ]] || {
    printf 'Missing required variable in %s: %s\n' "${env_file}" "${variable_name}" >&2
    exit 1
  }
done

expected_gateway_image="$(sed -n 's/^GITHUB_GATEWAY_IMAGE=//p' "${root_dir}/.env.example")"
if [[ ! "${expected_gateway_image}" =~ ^local/github-app-agent-gateway:[0-9a-f]{7}$ ]]; then
  printf 'Unable to read the compatible GITHUB_GATEWAY_IMAGE from %s/.env.example.\n' "${root_dir}" >&2
  exit 1
fi
if [[ "${GITHUB_GATEWAY_IMAGE}" != "${expected_gateway_image}" ]]; then
  printf 'GITHUB_GATEWAY_IMAGE is incompatible with this runtime: expected=%s actual=%s.\n' \
    "${expected_gateway_image}" "${GITHUB_GATEWAY_IMAGE}" >&2
  exit 1
fi

if [[ "${GITHUB_GATEWAY_ALLOWED_OWNERS}" != "${AGENT_WORKSPACE_ORGANIZATION}" ]]; then
  printf 'GITHUB_GATEWAY_ALLOWED_OWNERS must match AGENT_WORKSPACE_ORGANIZATION (%s).\n' \
    "${AGENT_WORKSPACE_ORGANIZATION}" >&2
  exit 1
fi

if [[ ! "${BUZZ_AGENT_OWNER_HEX}" =~ ^[0-9a-fA-F]{64}$ ]]; then
  printf 'BUZZ_AGENT_OWNER_HEX must be a 64-character hex public key.\n' >&2
  exit 1
fi

readonly agent_uid=10001
readonly gateway_uid=1000

if (( EUID != 0 )); then
  printf 'Run preflight as root (sudo) to inspect both agent and gateway bind mounts.\n' >&2
  exit 1
fi

stat_uid() {
  if stat -c '%u' "$1" >/dev/null 2>&1; then
    stat -c '%u' "$1"
  else
    stat -f '%u' "$1"
  fi
}

stat_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

require_owner_and_mode() {
  local path="$1"
  local expected_mode="$2"
  local description="$3"
  local expected_uid="${4:-${agent_uid}}"
  local actual_uid
  local actual_mode

  actual_uid="$(stat_uid "${path}")"
  actual_mode="$(stat_mode "${path}")"
  [[ "${actual_uid}" == "${expected_uid}" ]] || {
    printf '%s must be owned by UID %s: %s (found UID %s)\n' \
      "${description}" "${expected_uid}" "${path}" "${actual_uid}" >&2
    exit 1
  }
  [[ "${actual_mode}" == "${expected_mode}" ]] || {
    printf '%s must have mode %s: %s (found %s)\n' \
      "${description}" "${expected_mode}" "${path}" "${actual_mode}" >&2
    exit 1
  }
}

require_workspace_access() {
  local name="$1"
  local workspace="$2"
  local access="$3"
  local required_directory_mode='u+rx'
  local mismatched_path

  if [[ "${access}" == "read-write" ]]; then
    required_directory_mode='u+rwx'
  fi

  mismatched_path="$(find "${workspace}" -xdev ! -uid "${agent_uid}" -print -quit)"
  [[ -z "${mismatched_path}" ]] || {
    printf '%s workspace contains a path not owned by UID %s: %s\n' \
      "${name}" "${agent_uid}" "${mismatched_path}" >&2
    exit 1
  }

  mismatched_path="$(find "${workspace}" -xdev -type d ! -perm "-${required_directory_mode}" -print -quit)"
  [[ -z "${mismatched_path}" ]] || {
    printf '%s workspace has a directory without %s permission for UID %s: %s\n' \
      "${name}" "${required_directory_mode}" "${agent_uid}" "${mismatched_path}" >&2
    exit 1
  }

  mismatched_path="$(find "${workspace}" -xdev -type f ! -perm -u+r -print -quit)"
  [[ -z "${mismatched_path}" ]] || {
    printf '%s workspace has a file without u+r permission for UID %s: %s\n' \
      "${name}" "${agent_uid}" "${mismatched_path}" >&2
    exit 1
  }

  if [[ "${access}" == "read-write" ]]; then
    # Git intentionally stores immutable object files without owner-write
    # permission. The agent writes new objects into their writable parent
    # directories instead of modifying existing objects.
    mismatched_path="$(find "${workspace}" -xdev -type f \
      ! -path '*/.git/objects/*' ! -perm -u+w -print -quit)"
    [[ -z "${mismatched_path}" ]] || {
      printf '%s workspace has a worktree or Git metadata file without u+w permission for UID %s: %s\n' \
        "${name}" "${agent_uid}" "${mismatched_path}" >&2
      exit 1
    }
  fi
}

check_agent() {
  local name="$1"
  local provider="$2"
  local credentials_dir="$3"
  local workspace="$4"
  local workspace_access="$5"
  local github_gateway="$6"

  [[ -d "${credentials_dir}" ]] || {
    printf '%s credential directory is missing: %s\n' "${name}" "${credentials_dir}" >&2
    exit 1
  }
  [[ -f "${credentials_dir}/buzz-private-key" ]] || {
    printf '%s is missing buzz-private-key.\n' "${name}" >&2
    exit 1
  }
  [[ -f "${credentials_dir}/buzz-auth-tag" ]] || {
    printf '%s is missing buzz-auth-tag; run provision-buzz-agent-identity.sh.\n' \
      "${name}" >&2
    exit 1
  }
  [[ -f "${credentials_dir}/kaneo-credentials.json" ]] || {
    printf '%s is missing kaneo-credentials.json.\n' "${name}" >&2
    exit 1
  }
  if [[ "${github_gateway}" == "true" && ! -f "${credentials_dir}/github-gateway-agent-token" ]]; then
    printf '%s is missing github-gateway-agent-token.\n' "${name}" >&2
    exit 1
  fi
  [[ -d "${workspace}" ]] || {
    printf '%s organization workspace root is missing: %s\n' \
      "${name}" "${workspace}" >&2
    exit 1
  }

  require_owner_and_mode "${credentials_dir}" 700 "${name} credential directory"
  local credential_path
  while IFS= read -r -d '' credential_path; do
    require_owner_and_mode "${credential_path}" 600 "${name} credential file"
  done < <(find "${credentials_dir}" -xdev -type f -print0)
  require_workspace_access "${name}" "${workspace}" "${workspace_access}"

  case "${provider}" in
    claude)
      [[ -f "${credentials_dir}/claude-oauth-token" \
        || -f "${credentials_dir}/anthropic-api-key" ]] || {
        printf '%s needs claude-oauth-token or anthropic-api-key.\n' "${name}" >&2
        exit 1
      }
      ;;
    codex)
      [[ -f "${credentials_dir}/codex-auth.json" \
        || -f "${credentials_dir}/openai-api-key" ]] || {
        printf '%s needs codex-auth.json or openai-api-key.\n' "${name}" >&2
        exit 1
      }
      ;;
    *)
      printf '%s has unsupported provider: %s\n' "${name}" "${provider}" >&2
      exit 1
      ;;
  esac
}

check_gateway() {
  command -v jq >/dev/null 2>&1 || {
    printf 'jq is required to validate gateway role mappings.\n' >&2
    exit 1
  }
  command -v node >/dev/null 2>&1 || {
    printf 'node is required to validate gateway agent expiry.\n' >&2
    exit 1
  }
  [[ -d "${GITHUB_GATEWAY_CREDENTIALS_ROOT}" ]] || {
    printf 'Gateway credential root is missing: %s\n' "${GITHUB_GATEWAY_CREDENTIALS_ROOT}" >&2
    exit 1
  }
  [[ -d "${GITHUB_GATEWAY_RUNTIME_DIR}" ]] || {
    printf 'Gateway runtime directory is missing: %s\n' "${GITHUB_GATEWAY_RUNTIME_DIR}" >&2
    exit 1
  }
  require_owner_and_mode "${GITHUB_GATEWAY_CREDENTIALS_ROOT}" 700 \
    "Gateway credential root" "${gateway_uid}"
  require_owner_and_mode "${GITHUB_GATEWAY_RUNTIME_DIR}" 700 \
    "Gateway runtime directory" "${gateway_uid}"

  local runtime_file
  for runtime_file in apps.json agents.json jobs.json; do
    [[ -f "${GITHUB_GATEWAY_RUNTIME_DIR}/${runtime_file}" ]] || {
      printf 'Gateway runtime file is missing: %s/%s\n' \
        "${GITHUB_GATEWAY_RUNTIME_DIR}" "${runtime_file}" >&2
      exit 1
    }
    require_owner_and_mode "${GITHUB_GATEWAY_RUNTIME_DIR}/${runtime_file}" 600 \
      "Gateway runtime file" "${gateway_uid}"
  done

  local agent_id
  local agent_role
  for agent_id in dispatcher-planner developer-a reviewer-a; do
    case "${agent_id}" in
      dispatcher-planner) agent_role=control ;;
      developer-a) agent_role=developer ;;
      reviewer-a) agent_role=reviewer ;;
    esac
    node --input-type=module -e '
      import { readFile } from "node:fs/promises";

      const [agentsFile, agentId, role] = process.argv.slice(1);
      const config = JSON.parse(await readFile(agentsFile, "utf8"));
      const records = config.agents.filter((agent) => agent.id === agentId);
      if (records.length !== 1) process.exit(2);
      const [record] = records;
      const expiresAt = Date.parse(record.expiresAt);
      if (
        record.role !== role ||
        record.disabled !== false ||
        !Number.isFinite(expiresAt) ||
        expiresAt <= Date.now()
      ) process.exit(3);
    ' "${GITHUB_GATEWAY_RUNTIME_DIR}/agents.json" "${agent_id}" "${agent_role}" || {
      printf 'Gateway agent record for %s is missing, duplicated, disabled, expired, or invalid.\n' \
        "${agent_id}" >&2
      exit 1
    }
  done

  local role
  local slug
  local expected_slug
  for role in control developer reviewer; do
    case "${role}" in
      control) expected_slug="${GITHUB_CONTROL_APP_SLUG}" ;;
      developer) expected_slug="${GITHUB_DEVELOPER_APP_SLUG}" ;;
      reviewer) expected_slug="${GITHUB_REVIEWER_APP_SLUG}" ;;
    esac
    slug="$(jq -er --arg role "${role}" '.roles[$role].appSlug' \
      "${GITHUB_GATEWAY_RUNTIME_DIR}/apps.json")" || {
      printf 'Gateway apps.json has no valid %s role mapping.\n' "${role}" >&2
      exit 1
    }
    [[ "${slug}" == "${expected_slug}" ]] || {
      printf 'Gateway apps.json %s mapping must be %s (found %s).\n' \
        "${role}" "${expected_slug}" "${slug}" >&2
      exit 1
    }
    [[ -d "${GITHUB_GATEWAY_CREDENTIALS_ROOT}/${slug}" ]] || {
      printf 'Gateway App credential directory is missing: %s/%s\n' \
        "${GITHUB_GATEWAY_CREDENTIALS_ROOT}" "${slug}" >&2
      exit 1
    }
    require_owner_and_mode "${GITHUB_GATEWAY_CREDENTIALS_ROOT}/${slug}" 700 \
      "Gateway App credential directory" "${gateway_uid}"
    require_owner_and_mode "${GITHUB_GATEWAY_CREDENTIALS_ROOT}/${slug}/app.json" 600 \
      "Gateway App metadata" "${gateway_uid}"
    require_owner_and_mode "${GITHUB_GATEWAY_CREDENTIALS_ROOT}/${slug}/private-key.pem" 600 \
      "Gateway App private key" "${gateway_uid}"
  done
}

# Compare the complete approved mapping and verify UID, GID, modes and paths.
node "${root_dir}/docker/git-identity.mjs" check "${AGENT_GIT_IDENTITY_MANIFEST}" \
  "${DISPATCHER_CREDENTIALS_DIR}" "${DEVELOPER_CREDENTIALS_DIR}" "${REVIEWER_CREDENTIALS_DIR}"

check_agent dispatcher-planner "${DISPATCHER_PROVIDER}" \
  "${DISPATCHER_CREDENTIALS_DIR}" "${DISPATCHER_WORKSPACE}" read-only true
check_agent developer-a "${DEVELOPER_PROVIDER}" \
  "${DEVELOPER_CREDENTIALS_DIR}" "${DEVELOPER_WORKSPACE}" read-write true
check_agent reviewer-a "${REVIEWER_PROVIDER}" \
  "${REVIEWER_CREDENTIALS_DIR}" "${REVIEWER_WORKSPACE}" read-only true
check_gateway

printf 'Preflight passed. No credential values were read or printed.\n'
