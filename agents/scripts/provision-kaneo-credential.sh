#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
replace=false
if [[ "${1:-}" == --replace ]]; then
  replace=true
  shift
fi
role="${1:-}"
env_file="${2:-${root_dir}/.env}"

die() {
  printf 'provision-kaneo-credential: %s\n' "$*" >&2
  exit 1
}

if [[ "${role}" == --help || "${role}" == -h ]]; then
  printf 'Usage: %s [--replace] <dispatcher-planner|developer-a|reviewer-a> [env-file]\n' "$0"
  exit 0
fi

(( EUID != 0 )) || die "run as the host user, not root; the script invokes sudo"
[[ -r "${env_file}" ]] || die "environment file is missing or unreadable: ${env_file}"
[[ -t 0 && -t 1 ]] || die "run from an interactive terminal for device authorization"

set -a
# shellcheck disable=SC1090
source "${env_file}"
set +a

case "${role}" in
  dispatcher-planner)
    credentials_dir="${DISPATCHER_CREDENTIALS_DIR:-}"
    ;;
  developer-a)
    credentials_dir="${DEVELOPER_CREDENTIALS_DIR:-}"
    ;;
  reviewer-a)
    credentials_dir="${REVIEWER_CREDENTIALS_DIR:-}"
    ;;
  *)
    die "role must be dispatcher-planner, developer-a, or reviewer-a"
    ;;
esac

[[ -n "${credentials_dir}" ]] || die "credential directory is not configured for ${role}"
[[ -n "${KANEO_API_URL:-}" ]] || die "KANEO_API_URL is missing from ${env_file}"
[[ -d "${credentials_dir}" ]] || die "credential directory does not exist: ${credentials_dir}"

for command_name in docker flock jq mktemp node sudo; do
  command -v "${command_name}" >/dev/null 2>&1 \
    || die "required command is missing: ${command_name}"
done
node_path="$(command -v node)"

image="local/buzz-agent-codex:${AGENT_CODEX_VERSION:-0.154.0}"
docker image inspect "${image}" >/dev/null 2>&1 \
  || die "required image is missing: ${image}"

provision_lock_dir="${XDG_RUNTIME_DIR:-${HOME}/.cache/darimuri-agent-orchestration}"
install -d -m 0700 "${provision_lock_dir}"
exec {provision_lock_fd}>"${provision_lock_dir}/provision.lock"
flock -n "${provision_lock_fd}" \
  || die "another agent provisioning process is already running"

destination="${credentials_dir}/kaneo-credentials.json"
if sudo test -e "${destination}"; then
  [[ "${replace}" == true ]] \
    || die "credential already exists; use --replace to revoke and reauthorize: ${destination}"

  printf 'Revoking the existing %s Kaneo device session.\n' "${role}"
  sudo "${node_path}" --input-type=module -e '
    import { readFile } from "node:fs/promises";

    const [credentialPath, expectedBaseUrl] = process.argv.slice(1);
    const credential = JSON.parse(await readFile(credentialPath, "utf8"));
    if (
      credential?.version !== 1 ||
      credential?.baseUrl !== expectedBaseUrl ||
      typeof credential?.accessToken !== "string" ||
      credential.accessToken.length === 0
    ) {
      throw new Error("existing Kaneo credential is invalid");
    }

    const response = await fetch(`${expectedBaseUrl}/api/auth/sign-out`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential.accessToken}`,
        "Content-Type": "application/json",
      },
      body: "{}",
    });
    if (!response.ok && response.status !== 401) {
      throw new Error(`Kaneo session revocation failed with HTTP ${response.status}`);
    }
  ' "${destination}" "${KANEO_API_URL}"
  sudo rm -f "${destination}"
fi

temporary_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${temporary_dir}"
}
trap cleanup EXIT
chmod 0700 "${temporary_dir}"

printf 'Authorize the %s Kaneo identity using the URL printed below.\n' "${role}"
docker run --rm --interactive --tty \
  --user "$(id -u):$(id -g)" \
  --env "KANEO_API_URL=${KANEO_API_URL}" \
  --env XDG_CONFIG_HOME=/auth \
  --volume "${temporary_dir}:/auth" \
  --entrypoint node \
  "${image}" \
  --input-type=module \
  -e '
    import { AuthService } from
      "file:///usr/local/lib/node_modules/@kaneo/mcp/dist/auth/auth-service.js";

    const auth = new AuthService({
      baseUrl: process.env.KANEO_API_URL,
      clientId: "kaneo-mcp",
    });
    await auth.getAccessToken();
    console.error("Kaneo device authorization completed.");
  '

source_file="${temporary_dir}/kaneo-mcp/credentials.json"
[[ -s "${source_file}" ]] || die "Kaneo did not create a credential file"
jq -e \
  --arg base_url "${KANEO_API_URL}" \
  '.version == 1 and
   .baseUrl == $base_url and
   .clientId == "kaneo-mcp" and
   (.accessToken | type == "string" and length > 0)' \
  "${source_file}" >/dev/null \
  || die "Kaneo created an invalid credential file"

sudo install -m 0600 -o 10001 -g 10001 "${source_file}" "${destination}"
printf 'Installed %s Kaneo credential: %s\n' "${role}" "${destination}"
