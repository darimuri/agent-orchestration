#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="${1:-${root_dir}/.env}"
repository_root="$(cd "${root_dir}/.." && pwd)"
host_home="${HOME}"

die() {
  printf 'provision-runtime: %s\n' "$*" >&2
  exit 1
}

if (( EUID == 0 )) && [[ "${PROVISION_RUNTIME_TEST_MODE:-0}" != 1 ]]; then
  die "run as the host user, not root; the script invokes sudo when needed"
fi
[[ -r "${env_file}" ]] || die "environment file is missing or unreadable: ${env_file}"

set -a
# shellcheck disable=SC1090
source "${env_file}"
set +a

: "${GATEWAY_AGENT_TOKEN_TTL_DAYS:=30}"
: "${DISPATCHER_PROVIDER:=claude}"
: "${DEVELOPER_PROVIDER:=codex}"
: "${REVIEWER_PROVIDER:=claude}"
: "${AGENT_RUNTIME_ROOT:=${host_home}/buzz-agents}"
: "${GITHUB_GATEWAY_CREDENTIALS_BASE_DIR:=${host_home}/.config/darimuri-agent-orchestration}"

required_variables=(
  AGENT_GIT_IDENTITY_MANIFEST
  AGENT_WORKSPACE_ORGANIZATION
  AGENT_WORKSPACE_GIT_URL_TEMPLATE
  GITHUB_GATEWAY_IMAGE
  GITHUB_GATEWAY_ALLOWED_OWNERS
  DISPATCHER_CREDENTIALS_DIR
  DISPATCHER_WORKSPACE
  DEVELOPER_CREDENTIALS_DIR
  DEVELOPER_WORKSPACE
  REVIEWER_CREDENTIALS_DIR
  REVIEWER_WORKSPACE
  GITHUB_GATEWAY_CREDENTIALS_ROOT
  GITHUB_GATEWAY_RUNTIME_DIR
  GITHUB_CONTROL_APP_SLUG
  GITHUB_DEVELOPER_APP_SLUG
  GITHUB_REVIEWER_APP_SLUG
)

for variable_name in "${required_variables[@]}"; do
  [[ -n "${!variable_name:-}" ]] \
    || die "missing required variable in ${env_file}: ${variable_name}"
done

expected_gateway_image="$(sed -n 's/^GITHUB_GATEWAY_IMAGE=//p' "${root_dir}/.env.example")"
[[ "${expected_gateway_image}" =~ ^local/github-app-agent-gateway:[0-9a-f]{7}$ ]] \
  || die "unable to read the compatible GITHUB_GATEWAY_IMAGE from ${root_dir}/.env.example"
[[ "${GITHUB_GATEWAY_IMAGE}" == "${expected_gateway_image}" ]] \
  || die "GITHUB_GATEWAY_IMAGE is incompatible with this provisioner: expected=${expected_gateway_image} actual=${GITHUB_GATEWAY_IMAGE}; update ${env_file} and build the expected image before provisioning"

[[ "${AGENT_WORKSPACE_ORGANIZATION}" =~ ^[A-Za-z0-9_.-]+$ ]] \
  || die "AGENT_WORKSPACE_ORGANIZATION must be a GitHub organization login"
[[ "${AGENT_WORKSPACE_GIT_URL_TEMPLATE}" == *'{owner}'* \
  && "${AGENT_WORKSPACE_GIT_URL_TEMPLATE}" == *'{repository}'* ]] \
  || die "AGENT_WORKSPACE_GIT_URL_TEMPLATE must contain {owner} and {repository}"
[[ "${GITHUB_GATEWAY_ALLOWED_OWNERS}" == "${AGENT_WORKSPACE_ORGANIZATION}" ]] \
  || die "GITHUB_GATEWAY_ALLOWED_OWNERS must match AGENT_WORKSPACE_ORGANIZATION"
[[ "${GITHUB_CONTROL_APP_SLUG}" =~ ^[a-z0-9][a-z0-9-]*$ ]] \
  || die "GITHUB_CONTROL_APP_SLUG must be a GitHub App slug"
[[ "${GITHUB_DEVELOPER_APP_SLUG}" =~ ^[a-z0-9][a-z0-9-]*$ ]] \
  || die "GITHUB_DEVELOPER_APP_SLUG must be a GitHub App slug"
[[ "${GITHUB_REVIEWER_APP_SLUG}" =~ ^[a-z0-9][a-z0-9-]*$ ]] \
  || die "GITHUB_REVIEWER_APP_SLUG must be a GitHub App slug"
[[ "${GATEWAY_AGENT_TOKEN_TTL_DAYS}" =~ ^[1-9][0-9]*$ ]] \
  || die "GATEWAY_AGENT_TOKEN_TTL_DAYS must be an integer from 1 to 365"
(( GATEWAY_AGENT_TOKEN_TTL_DAYS <= 365 )) \
  || die "GATEWAY_AGENT_TOKEN_TTL_DAYS must be an integer from 1 to 365"

for command_name in jq node flock realpath sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 \
    || die "required command is missing: ${command_name}"
done

canonicalize_managed_path() {
  local variable_name="$1"
  local label="$2"
  local path="${!variable_name}"
  local canonical

  [[ "${path}" == /* ]] || die "${label} must be an absolute path: ${path}"
  canonical="$(realpath -m -- "${path}")"
  [[ "${path}" == "${canonical}" ]] \
    || die "${label} must be canonical and contain no symlink or '..' component: ${path}"

  case "${canonical}" in
    /|/home|/root|/srv|/etc|/usr|/var|/opt|/tmp|"${host_home}"|"${repository_root}")
      die "${label} uses a protected path: ${canonical}"
      ;;
  esac
  if [[ "${repository_root}" == "${canonical}/"* || "${canonical}" == "${repository_root}/"* ]]; then
    die "${label} must not contain or be inside the repository checkout: ${canonical}"
  fi

  printf -v "${variable_name}" '%s' "${canonical}"
}

require_strict_descendant() {
  local child_label="$1"
  local child="$2"
  local parent_label="$3"
  local parent="$4"
  [[ "${child}" == "${parent}/"* ]] \
    || die "${child_label} must be below ${parent_label}: ${child}"
}

require_disjoint_paths() {
  local left_label="$1"
  local left="$2"
  local right_label="$3"
  local right="$4"
  if [[ "${left}" == "${right}" || "${left}" == "${right}/"* || "${right}" == "${left}/"* ]]; then
    die "${left_label} and ${right_label} must not be equal or nested: ${left} ; ${right}"
  fi
}

canonicalize_managed_path AGENT_RUNTIME_ROOT AGENT_RUNTIME_ROOT
canonicalize_managed_path GITHUB_GATEWAY_CREDENTIALS_BASE_DIR GITHUB_GATEWAY_CREDENTIALS_BASE_DIR
for variable_name in \
  DISPATCHER_CREDENTIALS_DIR DISPATCHER_WORKSPACE \
  DEVELOPER_CREDENTIALS_DIR DEVELOPER_WORKSPACE \
  REVIEWER_CREDENTIALS_DIR REVIEWER_WORKSPACE \
  GITHUB_GATEWAY_RUNTIME_DIR GITHUB_GATEWAY_CREDENTIALS_ROOT; do
  canonicalize_managed_path "${variable_name}" "${variable_name}"
done

for variable_name in \
  DISPATCHER_CREDENTIALS_DIR DISPATCHER_WORKSPACE \
  DEVELOPER_CREDENTIALS_DIR DEVELOPER_WORKSPACE \
  REVIEWER_CREDENTIALS_DIR REVIEWER_WORKSPACE \
  GITHUB_GATEWAY_RUNTIME_DIR; do
  require_strict_descendant \
    "${variable_name}" "${!variable_name}" AGENT_RUNTIME_ROOT "${AGENT_RUNTIME_ROOT}"
done
require_strict_descendant \
  GITHUB_GATEWAY_CREDENTIALS_ROOT "${GITHUB_GATEWAY_CREDENTIALS_ROOT}" \
  GITHUB_GATEWAY_CREDENTIALS_BASE_DIR "${GITHUB_GATEWAY_CREDENTIALS_BASE_DIR}"

managed_path_names=(
  DISPATCHER_CREDENTIALS_DIR DISPATCHER_WORKSPACE
  DEVELOPER_CREDENTIALS_DIR DEVELOPER_WORKSPACE
  REVIEWER_CREDENTIALS_DIR REVIEWER_WORKSPACE
  GITHUB_GATEWAY_RUNTIME_DIR GITHUB_GATEWAY_CREDENTIALS_ROOT
)
for ((left_index = 0; left_index < ${#managed_path_names[@]}; left_index++)); do
  for ((right_index = left_index + 1; right_index < ${#managed_path_names[@]}; right_index++)); do
    left_name="${managed_path_names[${left_index}]}"
    right_name="${managed_path_names[${right_index}]}"
    require_disjoint_paths \
      "${left_name}" "${!left_name}" "${right_name}" "${!right_name}"
  done
done

# Validate all identities before any provisioning mutation or token creation.
node "${root_dir}/docker/git-identity.mjs" validate "${AGENT_GIT_IDENTITY_MANIFEST}"

provision_lock_dir="${XDG_RUNTIME_DIR:-${HOME}/.cache/darimuri-agent-orchestration}"
install -d -m 0700 "${provision_lock_dir}"
exec {provision_lock_fd}>"${provision_lock_dir}/provision.lock"
flock -n "${provision_lock_fd}" \
  || die "another agent provisioning process is already running"

as_root() {
  if (( EUID == 0 )); then
    "$@"
  else
    sudo "$@"
  fi
}

if (( EUID != 0 )); then
  command -v sudo >/dev/null 2>&1 || die "required command is missing: sudo"
  sudo -v
fi

readonly agent_uid=10001
readonly gateway_uid=1000
readonly node_path="$(command -v node)"
temporary_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${temporary_dir}"
}
trap cleanup EXIT
umask 077

ensure_workspace_root() {
  local name="$1"
  local workspace="$2"
  as_root install -d -m 0755 -o "${agent_uid}" -g "${agent_uid}" "${workspace}"
  as_root chown -R "${agent_uid}:${agent_uid}" "${workspace}"
  printf 'Prepared %s organization workspace root: %s\n' "${name}" "${workspace}"
}

prepare_agent_credentials() {
  local credentials_dir="$1"
  as_root install -d -m 0700 -o "${agent_uid}" -g "${agent_uid}" "${credentials_dir}"
  as_root chown -R "${agent_uid}:${agent_uid}" "${credentials_dir}"
  as_root find "${credentials_dir}" -xdev -type d -exec chmod 0700 {} +
  as_root find "${credentials_dir}" -xdev -type f -exec chmod 0600 {} +
}

install_runtime_json() {
  local source_file="$1"
  local destination="$2"

  if as_root test -e "${destination}"; then
    as_root test -f "${destination}" \
      || die "gateway runtime path exists but is not a file: ${destination}"
    printf 'Preserving existing gateway runtime file: %s\n' "${destination}"
  else
    as_root install -m 0600 -o "${gateway_uid}" -g "${gateway_uid}" \
      "${source_file}" "${destination}"
  fi
  as_root chown "${gateway_uid}:${gateway_uid}" "${destination}"
  as_root chmod 0600 "${destination}"
}

prepare_gateway_runtime() {
  local apps_template="${temporary_dir}/apps.json"
  local agents_template="${temporary_dir}/agents.json"
  local jobs_template="${temporary_dir}/jobs.json"

  jq -n \
    --arg control "${GITHUB_CONTROL_APP_SLUG}" \
    --arg developer "${GITHUB_DEVELOPER_APP_SLUG}" \
    --arg reviewer "${GITHUB_REVIEWER_APP_SLUG}" \
    '{roles:{control:{appSlug:$control},developer:{appSlug:$developer},reviewer:{appSlug:$reviewer}}}' \
    >"${apps_template}"
  printf '%s\n' '{"agents":[]}' >"${agents_template}"
  printf '%s\n' '{"jobs":[]}' >"${jobs_template}"

  as_root install -d -m 0700 -o "${gateway_uid}" -g "${gateway_uid}" \
    "${GITHUB_GATEWAY_RUNTIME_DIR}"
  install_runtime_json "${apps_template}" "${GITHUB_GATEWAY_RUNTIME_DIR}/apps.json"
  install_runtime_json "${agents_template}" "${GITHUB_GATEWAY_RUNTIME_DIR}/agents.json"
  install_runtime_json "${jobs_template}" "${GITHUB_GATEWAY_RUNTIME_DIR}/jobs.json"

  ensure_gateway_app_mapping control "${GITHUB_CONTROL_APP_SLUG}"
  ensure_gateway_app_mapping developer "${GITHUB_DEVELOPER_APP_SLUG}"
  ensure_gateway_app_mapping reviewer "${GITHUB_REVIEWER_APP_SLUG}"
  as_root jq -e '.agents | type == "array"' \
    "${GITHUB_GATEWAY_RUNTIME_DIR}/agents.json" >/dev/null \
    || die "gateway agents.json must contain an agents array"
  as_root jq -e '.jobs | type == "array"' \
    "${GITHUB_GATEWAY_RUNTIME_DIR}/jobs.json" >/dev/null \
    || die "gateway jobs.json must contain a jobs array"
}

ensure_gateway_app_mapping() {
  local role="$1"
  local app_slug="$2"
  local apps_file="${GITHUB_GATEWAY_RUNTIME_DIR}/apps.json"
  local current_slug
  local updated_file="${temporary_dir}/apps-${role}.json"

  current_slug="$(as_root jq -r --arg role "${role}" '.roles[$role].appSlug // empty' "${apps_file}")"
  if [[ -z "${current_slug}" ]]; then
    as_root jq --arg role "${role}" --arg slug "${app_slug}" \
      '.roles[$role] = {appSlug:$slug}' "${apps_file}" >"${updated_file}"
    as_root install -m 0600 -o "${gateway_uid}" -g "${gateway_uid}" \
      "${updated_file}" "${apps_file}"
    printf 'Added gateway %s App mapping: %s\n' "${role}" "${app_slug}"
    return
  fi
  [[ "${current_slug}" == "${app_slug}" ]] \
    || die "gateway apps.json ${role} mapping does not match ${app_slug}"
}

prepare_gateway_credentials_root() {
  as_root install -d -m 0700 -o "${gateway_uid}" -g "${gateway_uid}" \
    "${GITHUB_GATEWAY_CREDENTIALS_ROOT}"
  as_root chown -R "${gateway_uid}:${gateway_uid}" "${GITHUB_GATEWAY_CREDENTIALS_ROOT}"
  as_root find "${GITHUB_GATEWAY_CREDENTIALS_ROOT}" -xdev -type d -exec chmod 0700 {} +
  as_root find "${GITHUB_GATEWAY_CREDENTIALS_ROOT}" -xdev -type f -exec chmod 0600 {} +
}

ensure_gateway_agent_token() {
  local agent_id="$1"
  local role="$2"
  local credentials_dir="$3"
  local token_file="${credentials_dir}/github-gateway-agent-token"
  local token_hash

  if as_root test -f "${token_file}"; then
    token_hash="$(as_root sha256sum "${token_file}")"
    token_hash="${token_hash%% *}"
    as_root "${node_path}" --input-type=module -e '
      import { readFile } from "node:fs/promises";

      const [agentsFile, agentId, role, tokenHash] = process.argv.slice(1);
      const config = JSON.parse(await readFile(agentsFile, "utf8"));
      const records = config.agents.filter((agent) => agent.id === agentId);
      if (records.length !== 1) process.exit(2);
      const [record] = records;
      const expiresAt = Date.parse(record.expiresAt);
      if (
        record.role !== role ||
        record.tokenSha256 !== tokenHash ||
        record.disabled !== false ||
        !Number.isFinite(expiresAt) ||
        expiresAt <= Date.now()
      ) process.exit(3);
    ' "${GITHUB_GATEWAY_RUNTIME_DIR}/agents.json" \
      "${agent_id}" "${role}" "${token_hash}" \
      || die "existing gateway token for ${agent_id} is expired, duplicated, disabled, or inconsistent; remove its stale agents.json record and token file, then rerun provisioning"
    printf 'Preserving existing gateway token for %s.\n' "${agent_id}"
    return
  fi

  as_root env "GATEWAY_AGENT_TOKEN_TTL_DAYS=${GATEWAY_AGENT_TOKEN_TTL_DAYS}" \
    "${node_path}" "${root_dir}/scripts/provision-gateway-agent.mjs" \
    "${agent_id}" "${role}" "${credentials_dir}" "${GITHUB_GATEWAY_RUNTIME_DIR}"
}

missing_files=()
record_missing_file() {
  local path="$1"
  if ! as_root test -f "${path}"; then
    missing_files+=("${path}")
  fi
}

record_missing_alternative() {
  local first="$1"
  local second="$2"
  local description="$3"
  if ! as_root test -f "${first}" && ! as_root test -f "${second}"; then
    missing_files+=("${description}: ${first} or ${second}")
  fi
}

# Under the existing provisioning lock, reject all conflicts before changing layout.
as_root "${node_path}" "${root_dir}/docker/git-identity.mjs" check-install \
  "${AGENT_GIT_IDENTITY_MANIFEST}" \
  "${DISPATCHER_CREDENTIALS_DIR}" "${DEVELOPER_CREDENTIALS_DIR}" "${REVIEWER_CREDENTIALS_DIR}"

ensure_workspace_root dispatcher-planner "${DISPATCHER_WORKSPACE}"
ensure_workspace_root developer-a "${DEVELOPER_WORKSPACE}"
ensure_workspace_root reviewer-a "${REVIEWER_WORKSPACE}"

prepare_agent_credentials "${DISPATCHER_CREDENTIALS_DIR}"
prepare_agent_credentials "${DEVELOPER_CREDENTIALS_DIR}"
prepare_agent_credentials "${REVIEWER_CREDENTIALS_DIR}"
as_root "${node_path}" "${root_dir}/docker/git-identity.mjs" install \
  "${AGENT_GIT_IDENTITY_MANIFEST}" \
  "${DISPATCHER_CREDENTIALS_DIR}" "${DEVELOPER_CREDENTIALS_DIR}" "${REVIEWER_CREDENTIALS_DIR}"
prepare_gateway_runtime
prepare_gateway_credentials_root

ensure_gateway_agent_token dispatcher-planner control "${DISPATCHER_CREDENTIALS_DIR}"
ensure_gateway_agent_token developer-a developer "${DEVELOPER_CREDENTIALS_DIR}"
ensure_gateway_agent_token reviewer-a reviewer "${REVIEWER_CREDENTIALS_DIR}"

for credentials_dir in \
  "${DISPATCHER_CREDENTIALS_DIR}" \
  "${DEVELOPER_CREDENTIALS_DIR}" \
  "${REVIEWER_CREDENTIALS_DIR}"; do
  record_missing_file "${credentials_dir}/buzz-private-key"
  record_missing_file "${credentials_dir}/buzz-auth-tag"
  record_missing_file "${credentials_dir}/kaneo-credentials.json"
done
record_provider_credential() {
  local name="$1"
  local provider="$2"
  local credentials_dir="$3"

  case "${provider}" in
    claude)
      record_missing_alternative \
        "${credentials_dir}/claude-oauth-token" \
        "${credentials_dir}/anthropic-api-key" \
        "${name} Claude credential"
      ;;
    codex)
      record_missing_alternative \
        "${credentials_dir}/codex-auth.json" \
        "${credentials_dir}/openai-api-key" \
        "${name} Codex credential"
      ;;
    *)
      die "unsupported provider for ${name}: ${provider}"
      ;;
  esac
}

record_provider_credential dispatcher-planner \
  "${DISPATCHER_PROVIDER}" "${DISPATCHER_CREDENTIALS_DIR}"
record_provider_credential developer-a \
  "${DEVELOPER_PROVIDER}" "${DEVELOPER_CREDENTIALS_DIR}"
record_provider_credential reviewer-a \
  "${REVIEWER_PROVIDER}" "${REVIEWER_CREDENTIALS_DIR}"

for app_slug in \
  "${GITHUB_CONTROL_APP_SLUG}" \
  "${GITHUB_DEVELOPER_APP_SLUG}" \
  "${GITHUB_REVIEWER_APP_SLUG}"; do
  record_missing_file "${GITHUB_GATEWAY_CREDENTIALS_ROOT}/${app_slug}/app.json"
  record_missing_file "${GITHUB_GATEWAY_CREDENTIALS_ROOT}/${app_slug}/private-key.pem"
done

printf '\nRuntime layout is ready.\n'
if ((${#missing_files[@]} > 0)); then
  printf 'Install these credentials before running preflight:\n'
  printf '  - %s\n' "${missing_files[@]}"
else
  printf 'All required credential files are present.\n'
fi

if as_root jq -e '.jobs | length == 0' "${GITHUB_GATEWAY_RUNTIME_DIR}/jobs.json" >/dev/null; then
  printf 'Add trusted job assignments to %s before using GitHub tools.\n' \
    "${GITHUB_GATEWAY_RUNTIME_DIR}/jobs.json"
fi
if [[ ! "${BUZZ_AGENT_OWNER_HEX:-}" =~ ^[0-9a-fA-F]{64}$ ]]; then
  printf 'Replace BUZZ_AGENT_OWNER_HEX in %s with the owner public key.\n' "${env_file}"
fi
printf 'Provision or verify owner-attested Buzz identities with: %s/scripts/provision-buzz-agent-identity.sh\n' \
  "${root_dir}"
printf 'Add a job repository with: %s/scripts/provision-agent-repository.sh %s/<repository>\n' \
  "${root_dir}" "${AGENT_WORKSPACE_ORGANIZATION}"
printf 'Then run: sudo %s/scripts/preflight.sh %s\n' "${root_dir}" "${env_file}"
