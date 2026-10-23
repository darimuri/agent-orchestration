#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repository_root="$(cd "${root_dir}/.." && pwd)"
# Shared independent-clone flow; the manual fallback retains its host-only scope.
source "${root_dir}/scripts/repository-clone.sh"
host_home="${HOME}"
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
for variable_name in DISPATCHER_WORKSPACE DEVELOPER_WORKSPACE REVIEWER_WORKSPACE; do
  canonicalize_workspace_path "${variable_name}"
  [[ "${!variable_name}" == "${AGENT_RUNTIME_ROOT}/"* ]] \
    || die "${variable_name} must be below AGENT_RUNTIME_ROOT: ${!variable_name}"
done

workspace_names=(DISPATCHER_WORKSPACE DEVELOPER_WORKSPACE REVIEWER_WORKSPACE)
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

  as_root install -d -m 0755 -o "${agent_uid}" -g "${agent_uid}" \
    "${workspace_root}/${owner}"

  if as_root test -e "${destination}"; then
    as_root test -d "${destination}/.git" \
      || die "${agent_name} repository path exists but is not a full clone: ${destination}"
    origin="$(as_root git -c safe.directory="${destination}" -C "${destination}" remote get-url origin)"
    [[ "${origin}" == "${repository_url}" ]] \
      || die "${agent_name} repository origin is ${origin}, expected ${repository_url}"
    printf 'Preserving %s clone: %s\n' "${agent_name}" "${destination}"
    return
  fi

  # Keep local source objects independent before changing clone ownership.
  clone_independent_repository "${repository_url}" "${requested_ref}" "${staging}"
  as_root mv "${staging}" "${destination}"
  as_root chown -R "${agent_uid}:${agent_uid}" "${destination}"
  printf 'Provisioned %s clone: %s\n' "${agent_name}" "${destination}"
}

provision_clone dispatcher-planner "${DISPATCHER_WORKSPACE}"
provision_clone developer-a "${DEVELOPER_WORKSPACE}"
provision_clone reviewer-a "${REVIEWER_WORKSPACE}"

printf 'Repository %s is available to each agent at /workspace/%s/%s.\n' \
  "${repository}" "${owner}" "${repository_name}"
