#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="${AGENT_ENV_FILE:-${root_dir}/.env}"

die() {
  printf 'provision-buzz-agent-identity: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: provision-buzz-agent-identity.sh [--verify-only] [agent ...]

Agents: dispatcher-planner developer-a reviewer-a
With no agent arguments, provisions all three identities.
EOF
}

verify_only=false
requested_agents=()
while (($# > 0)); do
  case "$1" in
    --verify-only)
      verify_only=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      requested_agents+=("$@")
      break
      ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      requested_agents+=("$1")
      ;;
  esac
  shift
done

if ((EUID == 0)); then
  die "run as the host user, not root"
fi
[[ -r "${env_file}" ]] || die "environment file is missing or unreadable: ${env_file}"

set -a
# shellcheck disable=SC1090
source "${env_file}"
set +a

: "${BUZZ_OWNER_PRIVATE_KEY_FILE:=/home2/dormael/buzz/owner-private-key.hex}"
: "${BUZZ_NAK_BIN:=/home2/dormael/buzz/.tools/nak}"
: "${BUZZ_NIP_OA_IMAGE:=local/buzz-nip-oa:c8f7321}"
: "${BUZZ_NIP_OA_SOURCE_COMMIT:=c8f73213089cbd5a0f1e675d3193558280d46e10}"
: "${AGENT_RUNTIME_UID:=10001}"
: "${AGENT_RUNTIME_GID:=10001}"
: "${AGENT_BUZZ_SPRIG_IMAGE:=ghcr.io/block/buzz-sprig:sha-6530b58@sha256:17facfc7608d8ddb33bc056c9aaba1098f4ef6abe5655702fbfd7584d1f74d76}"

required_variables=(
  BUZZ_RELAY_URL
  BUZZ_AGENT_OWNER_HEX
  DISPATCHER_CREDENTIALS_DIR
  DEVELOPER_CREDENTIALS_DIR
  REVIEWER_CREDENTIALS_DIR
)
for variable_name in "${required_variables[@]}"; do
  [[ -n "${!variable_name:-}" ]] \
    || die "missing required variable in ${env_file}: ${variable_name}"
done

for command_name in docker jq flock; do
  command -v "${command_name}" >/dev/null 2>&1 \
    || die "required command is missing: ${command_name}"
done
[[ -x "${BUZZ_NAK_BIN}" ]] || die "nak is missing or not executable: ${BUZZ_NAK_BIN}"
[[ -f "${BUZZ_OWNER_PRIVATE_KEY_FILE}" ]] \
  || die "owner private key is missing: ${BUZZ_OWNER_PRIVATE_KEY_FILE}"
[[ "${BUZZ_AGENT_OWNER_HEX}" =~ ^[0-9a-f]{64}$ ]] \
  || die "BUZZ_AGENT_OWNER_HEX must be 64 lowercase hex characters"
[[ "${AGENT_RUNTIME_UID}" =~ ^[0-9]+$ && "${AGENT_RUNTIME_GID}" =~ ^[0-9]+$ ]] \
  || die "AGENT_RUNTIME_UID and AGENT_RUNTIME_GID must be numeric"

declare -A credentials_dirs=(
  [dispatcher-planner]="${DISPATCHER_CREDENTIALS_DIR}"
  [developer-a]="${DEVELOPER_CREDENTIALS_DIR}"
  [reviewer-a]="${REVIEWER_CREDENTIALS_DIR}"
)
declare -A profile_names=(
  [dispatcher-planner]='Dispatcher Planner'
  [developer-a]='Developer A'
  [reviewer-a]='Reviewer A'
)
declare -A profile_about=(
  [dispatcher-planner]='Darimuri development workflow dispatcher and planning agent'
  [developer-a]='Darimuri development workflow implementation agent'
  [reviewer-a]='Darimuri development workflow review agent'
)

if ((${#requested_agents[@]} == 0)); then
  requested_agents=(dispatcher-planner developer-a reviewer-a)
fi
for agent in "${requested_agents[@]}"; do
  [[ -v "credentials_dirs[${agent}]" ]] || die "unknown agent: ${agent}"
done

lock_dir="${XDG_RUNTIME_DIR:-${HOME}/.cache/darimuri-agent-orchestration}"
install -d -m 0700 "${lock_dir}"
exec {lock_fd}>"${lock_dir}/buzz-identity-provision.lock"
flock -n "${lock_fd}" || die "another Buzz identity provisioning process is running"

temporary_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${temporary_dir}"
}
trap cleanup EXIT
umask 077

owner_pubkey="$("${BUZZ_NAK_BIN}" key public <"${BUZZ_OWNER_PRIVATE_KEY_FILE}")"
owner_pubkey="${owner_pubkey//$'\r'/}"
owner_pubkey="${owner_pubkey//$'\n'/}"
[[ "${owner_pubkey}" == "${BUZZ_AGENT_OWNER_HEX}" ]] \
  || die "owner private key does not match BUZZ_AGENT_OWNER_HEX"

provisioner_revision="$(
  docker image inspect \
    --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
    "${BUZZ_NIP_OA_IMAGE}" 2>/dev/null || true
)"
if [[ "${verify_only}" == false && "${provisioner_revision}" != "${BUZZ_NIP_OA_SOURCE_COMMIT}" ]]; then
  printf 'Building pinned Buzz NIP-OA provisioner image: %s\n' "${BUZZ_NIP_OA_IMAGE}"
  docker build \
    --file "${root_dir}/docker/Dockerfile.buzz-nip-oa" \
    --build-arg "BUZZ_SOURCE_COMMIT=${BUZZ_NIP_OA_SOURCE_COMMIT}" \
    --tag "${BUZZ_NIP_OA_IMAGE}" \
    "${root_dir}"
fi
if ! docker image inspect "${BUZZ_NIP_OA_IMAGE}" >/dev/null 2>&1; then
  die "provisioner image is unavailable: ${BUZZ_NIP_OA_IMAGE}"
fi

derive_agent_pubkey() {
  local key_file="$1"
  local pubkey
  pubkey="$(
    docker run --rm \
      --user 0:0 \
      --mount "type=bind,src=${key_file},dst=/run/secrets/buzz-private-key,readonly" \
      --entrypoint cat \
      "${AGENT_BUZZ_SPRIG_IMAGE}" \
      /run/secrets/buzz-private-key \
      | "${BUZZ_NAK_BIN}" key public
  )"
  pubkey="${pubkey//$'\r'/}"
  pubkey="${pubkey//$'\n'/}"
  [[ "${pubkey}" =~ ^[0-9a-f]{64}$ ]] || die "nak returned an invalid agent public key"
  printf '%s' "${pubkey}"
}

credential_file_exists() {
  local credentials_dir="$1"
  local filename="$2"
  docker run --rm \
    --user 0:0 \
    --mount "type=bind,src=${credentials_dir},dst=/run/agent/credentials,readonly" \
    --env "CREDENTIAL_FILENAME=${filename}" \
    --entrypoint sh \
    "${AGENT_BUZZ_SPRIG_IMAGE}" \
    -ec 'test -f "/run/agent/credentials/${CREDENTIAL_FILENAME}"'
}

query_events() {
  local output_file="$1"
  shift
  NOSTR_SECRET_KEY="$(<"${BUZZ_OWNER_PRIVATE_KEY_FILE}")" \
    "${BUZZ_NAK_BIN}" req --auth "$@" "${BUZZ_RELAY_URL}" >"${output_file}"
}

verify_identity() {
  local agent="$1"
  local pubkey="$2"
  local name="${profile_names[${agent}]}"
  local installed_auth_tag="${temporary_dir}/${agent}-installed-auth-tag"
  local profile_events="${temporary_dir}/${agent}-profiles.jsonl"
  local policy_events="${temporary_dir}/${agent}-policies.jsonl"

  credential_file_exists "${credentials_dirs[${agent}]}" buzz-auth-tag \
    || die "${agent} is missing ${credentials_dirs[${agent}]}/buzz-auth-tag"
  docker run --rm \
    --user 0:0 \
    --mount "type=bind,src=${credentials_dirs[${agent}]}/buzz-auth-tag,dst=/run/secrets/buzz-auth-tag,readonly" \
    --entrypoint cat \
    "${AGENT_BUZZ_SPRIG_IMAGE}" \
    /run/secrets/buzz-auth-tag >"${installed_auth_tag}"
  jq -e . "${installed_auth_tag}" >/dev/null \
    || die "${agent} installed buzz-auth-tag is not valid JSON"

  query_events "${profile_events}" --author "${pubkey}" --kind 0 --limit 10
  jq -s -e \
    --arg pubkey "${pubkey}" \
    --arg owner "${owner_pubkey}" \
    --arg name "${name}" \
    --slurpfile installed_auth_tag "${installed_auth_tag}" '
      map(select(.kind == 0 and .pubkey == $pubkey))
      | sort_by(.created_at, .id) | last
      | (.content | fromjson | (.display_name // .name)) == $name
        and ([.tags[] | select(. == $installed_auth_tag[0])] | length == 1)
        and ($installed_auth_tag[0][1] == $owner)
    ' "${profile_events}" >/dev/null \
    || die "${agent} latest profile is missing its expected name or owner auth tag"

  query_events "${policy_events}" --author "${owner_pubkey}" --kind 30177 \
    --tag "d=${pubkey}" --limit 10
  jq -s -e \
    --arg owner "${owner_pubkey}" \
    --arg pubkey "${pubkey}" \
    --arg name "${name}" '
      map(select(
        .kind == 30177
        and .pubkey == $owner
        and any(.tags[]; .[0] == "d" and .[1] == $pubkey)
      ))
      | sort_by(.created_at, .id) | last
      | (.content | fromjson) as $content
      | $content.name == $name
        and $content.parallelism == 1
        and $content.respond_to == "owner-only"
    ' "${policy_events}" >/dev/null \
    || die "${agent} latest owner policy is missing or invalid"

  printf 'Verified %s Buzz identity: %s\n' "${agent}" "${pubkey}"
}

provision_identity() {
  local agent="$1"
  local credentials_dir="${credentials_dirs[${agent}]}"
  local key_file="${credentials_dir}/buzz-private-key"
  local temporary_auth_tag="${temporary_dir}/${agent}-buzz-auth-tag"
  local pubkey
  local policy_content

  credential_file_exists "${credentials_dir}" buzz-private-key \
    || die "${agent} is missing ${key_file}"
  pubkey="$(derive_agent_pubkey "${key_file}")"

  if [[ "${verify_only}" == false ]]; then
    docker run --rm \
      --user "$(id -u):$(id -g)" \
      --mount "type=bind,src=${BUZZ_OWNER_PRIVATE_KEY_FILE},dst=/run/secrets/owner-private-key,readonly" \
      "${BUZZ_NIP_OA_IMAGE}" \
      /run/secrets/owner-private-key "${pubkey}" >"${temporary_auth_tag}"

    jq -e \
      --arg owner "${owner_pubkey}" '
        type == "array"
        and length == 4
        and .[0] == "auth"
        and .[1] == $owner
        and .[2] == ""
        and (.[3] | test("^[0-9a-f]{128}$"))
      ' "${temporary_auth_tag}" >/dev/null \
      || die "computed ${agent} auth tag has an invalid shape"

    docker run --rm --user 0:0 \
      --mount "type=bind,src=${temporary_auth_tag},dst=/run/source/buzz-auth-tag,readonly" \
      --mount "type=bind,src=${credentials_dir},dst=/run/destination" \
      --env "AGENT_RUNTIME_UID=${AGENT_RUNTIME_UID}" \
      --env "AGENT_RUNTIME_GID=${AGENT_RUNTIME_GID}" \
      --entrypoint sh \
      "${AGENT_BUZZ_SPRIG_IMAGE}" \
      -ec '
        umask 077
        cat /run/source/buzz-auth-tag > /run/destination/buzz-auth-tag
        chown "${AGENT_RUNTIME_UID}:${AGENT_RUNTIME_GID}" /run/destination/buzz-auth-tag
        chmod 0600 /run/destination/buzz-auth-tag
      '

    docker run --rm \
      --user "${AGENT_RUNTIME_UID}:${AGENT_RUNTIME_GID}" \
      --mount "type=bind,src=${credentials_dir},dst=/run/agent/credentials,readonly" \
      --env "BUZZ_RELAY_URL=${BUZZ_RELAY_URL}" \
      --env "PROFILE_NAME=${profile_names[${agent}]}" \
      --env "PROFILE_ABOUT=${profile_about[${agent}]}" \
      --entrypoint sh \
      "${AGENT_BUZZ_SPRIG_IMAGE}" \
      -ec '
        export BUZZ_PRIVATE_KEY="$(cat /run/agent/credentials/buzz-private-key)"
        export BUZZ_AUTH_TAG="$(cat /run/agent/credentials/buzz-auth-tag)"
        exec buzz users set-profile --name "${PROFILE_NAME}" --about "${PROFILE_ABOUT}"
      ' >/dev/null

    policy_content="$(jq -cn \
      --arg name "${profile_names[${agent}]}" \
      '{name:$name,parallelism:1,respond_to:"owner-only"}')"
    NOSTR_SECRET_KEY="$(<"${BUZZ_OWNER_PRIVATE_KEY_FILE}")" \
      "${BUZZ_NAK_BIN}" event --auth \
      --kind 30177 \
      --tag "d=${pubkey}" \
      --content "${policy_content}" \
      "${BUZZ_RELAY_URL}" >/dev/null
  fi

  verify_identity "${agent}" "${pubkey}"
}

for agent in "${requested_agents[@]}"; do
  provision_identity "${agent}"
done

if [[ "${verify_only}" == false ]]; then
  printf 'Provisioned %s owner-attested Buzz agent identity/identities.\n' \
    "${#requested_agents[@]}"
else
  printf 'Verified %s owner-attested Buzz agent identity/identities.\n' \
    "${#requested_agents[@]}"
fi
