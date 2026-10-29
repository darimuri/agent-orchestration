#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repository_root="$(cd "${root_dir}/.." && pwd)"
# Shared independent-clone flow; the manual fallback retains its host-only scope.
source "${root_dir}/scripts/repository-clone.sh"
host_home="${HOME}"
selected_host=false
if [[ "${1:-}" == --agent ]]; then
  [[ "${2:-}" == host-operator && $# -ge 3 && $# -le 5 ]] || { echo 'invalid explicit agent selector' >&2; exit 1; }
  selected_host=true; shift 2
elif [[ "${1:-}" == -* || $# -gt 3 ]]; then echo 'invalid repository arguments' >&2; exit 1
fi
readonly selected_host
repository="${1:-}"
requested_ref="${2:-}"
env_file="${3:-${root_dir}/.env}"

die() {
  printf 'provision-agent-repository: %s\n' "$*" >&2
  exit 1
}

if (( EUID == 0 )) && [[ "${PROVISION_RUNTIME_TEST_MODE:-0}" != 1 ]]; then
  die "run as the host user, not root; the script invokes sudo when needed"
fi
[[ -n "${repository}" ]] \
  || die "usage: provision-agent-repository.sh <owner/repository> [ref] [env-file]"
[[ -r "${env_file}" ]] || die "environment file is missing or unreadable: ${env_file}"

set -a
# shellcheck disable=SC1090
source "${env_file}"
set +a

: "${AGENT_WORKSPACE_DEFAULT_REF:=main}"
: "${AGENT_RUNTIME_ROOT:=${host_home}/buzz-agents}"
requested_ref="${requested_ref:-${AGENT_WORKSPACE_DEFAULT_REF}}"

required_variables=(
  AGENT_WORKSPACE_ORGANIZATION
  AGENT_WORKSPACE_GIT_URL_TEMPLATE
  DISPATCHER_WORKSPACE
  DEVELOPER_WORKSPACE
  REVIEWER_WORKSPACE
)
if [[ "$selected_host" == true ]]; then
  required_variables=(AGENT_WORKSPACE_ORGANIZATION AGENT_WORKSPACE_GIT_URL_TEMPLATE AGENT_RUNTIME_ROOT)
  node "$root_dir/docker/git-identity.mjs" validate-host-repository-layout "$AGENT_RUNTIME_ROOT"
  HOST_OPERATOR_WORKSPACE="$AGENT_RUNTIME_ROOT/host-operator/workspace"
  [[ -d "$HOST_OPERATOR_WORKSPACE" ]] || die 'prepare selected runtime before repository provisioning'
fi
for variable_name in "${required_variables[@]}"; do
  [[ -n "${!variable_name:-}" ]] \
    || die "missing required variable in ${env_file}: ${variable_name}"
done

[[ "${repository}" =~ ^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$ ]] \
  || die "repository must use owner/name format"
owner="${BASH_REMATCH[1]}"
repository_name="${BASH_REMATCH[2]}"
[[ "${owner}" == "${AGENT_WORKSPACE_ORGANIZATION}" ]] \
  || die "repository owner ${owner} is outside AGENT_WORKSPACE_ORGANIZATION=${AGENT_WORKSPACE_ORGANIZATION}"
[[ "${requested_ref}" != -* ]] || die "repository ref must not begin with '-'"
[[ "${AGENT_WORKSPACE_GIT_URL_TEMPLATE}" == *'{owner}'* \
  && "${AGENT_WORKSPACE_GIT_URL_TEMPLATE}" == *'{repository}'* ]] \
  || die "AGENT_WORKSPACE_GIT_URL_TEMPLATE must contain {owner} and {repository}"

for command_name in flock git mktemp realpath; do
  command -v "${command_name}" >/dev/null 2>&1 \
    || die "required command is missing: ${command_name}"
done

canonicalize_workspace_path() {
  local variable_name="$1"
  local path="${!variable_name}"
  local canonical

  [[ "${path}" == /* ]] || die "${variable_name} must be an absolute path: ${path}"
  canonical="$(realpath -m -- "${path}")"
  [[ "${path}" == "${canonical}" ]] \
    || die "${variable_name} must be canonical and contain no symlink or '..' component: ${path}"
  case "${canonical}" in
    /|/home|/root|/srv|/etc|/usr|/var|/opt|/tmp|"${host_home}"|"${repository_root}")
      die "${variable_name} uses a protected path: ${canonical}"
      ;;
  esac
  if [[ "${repository_root}" == "${canonical}/"* || "${canonical}" == "${repository_root}/"* ]]; then
    die "${variable_name} must not contain or be inside the repository checkout: ${canonical}"
  fi
  printf -v "${variable_name}" '%s' "${canonical}"
}

canonicalize_workspace_path AGENT_RUNTIME_ROOT
selected_workspace_names=(DISPATCHER_WORKSPACE DEVELOPER_WORKSPACE REVIEWER_WORKSPACE)
if [[ "$selected_host" == true ]]; then selected_workspace_names=(HOST_OPERATOR_WORKSPACE); fi
for variable_name in "${selected_workspace_names[@]}"; do
  canonicalize_workspace_path "${variable_name}"
  [[ "${!variable_name}" == "${AGENT_RUNTIME_ROOT}/"* ]] \
    || die "${variable_name} must be below AGENT_RUNTIME_ROOT: ${!variable_name}"
done

workspace_names=("${selected_workspace_names[@]}")
for ((left_index = 0; left_index < ${#workspace_names[@]}; left_index++)); do
  for ((right_index = left_index + 1; right_index < ${#workspace_names[@]}; right_index++)); do
    left_name="${workspace_names[${left_index}]}"
    right_name="${workspace_names[${right_index}]}"
    left_path="${!left_name}"
    right_path="${!right_name}"
    if [[ "${left_path}" == "${right_path}" \
      || "${left_path}" == "${right_path}/"* \
      || "${right_path}" == "${left_path}/"* ]]; then
      die "${left_name} and ${right_name} must not be equal or nested"
    fi
  done
done

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
repository_url="${AGENT_WORKSPACE_GIT_URL_TEMPLATE//\{owner\}/${owner}}"
repository_url="${repository_url//\{repository\}/${repository_name}}"
temporary_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${temporary_dir}"
}
trap cleanup EXIT

provision_clone() {
  local agent_name="$1"
  local workspace_root="$2"
  local destination="${workspace_root}/${owner}/${repository_name}"
  local staging="${temporary_dir}/${agent_name}"
  local origin

  if [[ "$selected_host" == true ]]; then
    as_root "$(command -v node)" --input-type=module - "$root_dir" "$workspace_root" "$owner" "$repository_name" <<'CHECK_DEST'
import fs from'node:fs';import{pathToFileURL}from'node:url';const[source,root,owner,repo]=process.argv.slice(2);const{safePath}=await import(pathToFileURL(source+'/docker/git-identity.mjs'));for(const file of [root,root+'/'+owner,root+'/'+owner+'/'+repo]){safePath(file);try{const st=fs.lstatSync(file);if(!st.isDirectory()||st.uid!==10001||st.gid!==10001||(st.mode&0o022))throw Error('unsafe selected clone');}catch(e){if(e.code!=='ENOENT')throw e;}}
CHECK_DEST
  fi
  as_root install -d -m 0755 -o "${agent_uid}" -g "${agent_uid}" "${workspace_root}/${owner}"

  if as_root test -e "${destination}"; then
    as_root test -d "${destination}/.git" \
      || die "${agent_name} repository path exists but is not a full clone: ${destination}"
    origin="$(as_root git -c safe.directory="${destination}" -C "${destination}" remote get-url origin)"
    [[ "${origin}" == "${repository_url}" ]] \
      || die "${agent_name} repository origin is ${origin}, expected ${repository_url}"
    if [[ "$selected_host" == true ]]; then
      as_root test ! -e "$destination/.git/objects/info/alternates" || die 'selected clone has alternates'
      as_root test ! -L "$destination/.git" || die 'selected clone is linked'
      [[ -z "$(as_root find "$destination/.git" -type l -print -quit)" ]] || die 'selected Git metadata contains links'
      [[ -z "$(as_root find "$destination/.git" -type f -links +1 -print -quit)" ]] || die 'selected clone shares objects'
    fi
    printf 'Preserving %s clone: %s\n' "${agent_name}" "${destination}"
    return
  fi

  # Keep local source objects independent before changing clone ownership.
  clone_independent_repository "${repository_url}" "${requested_ref}" "${staging}"
  as_root mv "${staging}" "${destination}"
  as_root chown -R "${agent_uid}:${agent_uid}" "${destination}"
  printf 'Provisioned %s clone: %s\n' "${agent_name}" "${destination}"
}

if [[ "$selected_host" == true ]]; then
  provision_clone host-operator "$HOST_OPERATOR_WORKSPACE"
  echo 'Fourth independent clone prepared; container workspace stays read-only.'
  exit 0
fi
provision_clone dispatcher-planner "${DISPATCHER_WORKSPACE}"
provision_clone developer-a "${DEVELOPER_WORKSPACE}"
provision_clone reviewer-a "${REVIEWER_WORKSPACE}"

printf 'Repository %s is available to each agent at /workspace/%s/%s.\n' \
  "${repository}" "${owner}" "${repository_name}"
