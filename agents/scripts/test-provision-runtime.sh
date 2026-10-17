#!/usr/bin/env bash
set -euo pipefail
umask 077

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
host_uid="$(id -u)"
host_gid="$(id -g)"
scratch_dir="$(mktemp -d)"

cleanup() {
  if (( EUID == 0 )); then
    chown -R "${host_uid}:${host_gid}" "${scratch_dir}" >/dev/null 2>&1 || true
  else
    sudo chown -R "${host_uid}:${host_gid}" "${scratch_dir}" >/dev/null 2>&1 || true
  fi
  rm -rf "${scratch_dir}"
}
trap cleanup EXIT

as_root() {
  if (( EUID == 0 )); then
    "$@"
  else
    sudo "$@"
  fi
}

source_repository="${scratch_dir}/sources/test-org/test-repo.git"
mkdir -p "${source_repository}"
git -C "${source_repository}" init --initial-branch=main >/dev/null
printf '%s\n' '# provisioning fixture' >"${source_repository}/README.md"
git -C "${source_repository}" add README.md
git -C "${source_repository}" \
  -c user.name=fixture -c user.email=fixture@example.test \
  commit -m fixture >/dev/null

source_object="$(git -C "${source_repository}" rev-parse HEAD)"
source_object_path="${source_repository}/.git/objects/${source_object:0:2}/${source_object:2}"
source_object_owner="$(stat -c '%u:%g' "${source_object_path}")"
source_object_inode="$(stat -c '%d:%i' "${source_object_path}")"

expected_gateway_image="$(sed -n 's/^GITHUB_GATEWAY_IMAGE=//p' "${root_dir}/.env.example")"
env_file="${scratch_dir}/runtime.env"
cat >"${env_file}" <<EOF
BUZZ_RELAY_URL=wss://buzz.example.test
KANEO_API_URL=https://kaneo.example.test
BUZZ_AGENT_OWNER_HEX=0000000000000000000000000000000000000000000000000000000000000000
AGENT_WORKSPACE_ORGANIZATION=test-org
AGENT_WORKSPACE_GIT_URL_TEMPLATE=${scratch_dir}/sources/{owner}/{repository}.git
AGENT_WORKSPACE_DEFAULT_REF=main
AGENT_RUNTIME_ROOT=${scratch_dir}/agent-runtime
AGENT_GIT_IDENTITY_MANIFEST=${scratch_dir}/git-identities.json
XDG_RUNTIME_DIR=${scratch_dir}/run
GITHUB_GATEWAY_ALLOWED_OWNERS=test-org
GITHUB_GATEWAY_IMAGE=${expected_gateway_image}
GITHUB_GATEWAY_MCP_URL=http://github-gateway:8787/mcp
GITHUB_CONTROL_APP_SLUG=control-app
GITHUB_DEVELOPER_APP_SLUG=developer-app
GITHUB_REVIEWER_APP_SLUG=reviewer-app
GITHUB_GATEWAY_CREDENTIALS_BASE_DIR=${scratch_dir}/gateway-credential-base
GITHUB_GATEWAY_CREDENTIALS_ROOT=${scratch_dir}/gateway-credential-base/github-apps
GITHUB_GATEWAY_RUNTIME_DIR=${scratch_dir}/agent-runtime/github-gateway
DISPATCHER_CREDENTIALS_DIR=${scratch_dir}/agent-runtime/dispatcher/credentials
DISPATCHER_WORKSPACE=${scratch_dir}/agent-runtime/dispatcher/workspace
DEVELOPER_CREDENTIALS_DIR=${scratch_dir}/agent-runtime/developer/credentials
DEVELOPER_WORKSPACE=${scratch_dir}/agent-runtime/developer/workspace
REVIEWER_CREDENTIALS_DIR=${scratch_dir}/agent-runtime/reviewer/credentials
REVIEWER_WORKSPACE=${scratch_dir}/agent-runtime/reviewer/workspace
DISPATCHER_PROVIDER=codex
DEVELOPER_PROVIDER=codex
REVIEWER_PROVIDER=codex
EOF

cp "${root_dir}/git-identities.example.json" "${scratch_dir}/git-identities.json"

expect_runtime_failure() {
  local label="$1"
  local candidate_env="$2"
  if PROVISION_RUNTIME_TEST_MODE="${PROVISION_RUNTIME_TEST_MODE:-0}" \
    "${root_dir}/scripts/provision-runtime.sh" "${candidate_env}" >/dev/null 2>&1; then
    printf 'Unsafe runtime configuration was accepted: %s\n' "${label}" >&2
    exit 1
  fi
}

expect_preflight_failure() {
  local label="$1"
  local candidate_env="${2:-${env_file}}"
  if as_root "${root_dir}/scripts/preflight.sh" "${candidate_env}" >/dev/null 2>&1; then
    printf 'Unsafe gateway agent state passed preflight: %s\n' "${label}" >&2
    exit 1
  fi
}

stale_gateway_env="${scratch_dir}/stale-gateway.env"
cp "${env_file}" "${stale_gateway_env}"
printf '%s\n' 'GITHUB_GATEWAY_IMAGE=local/github-app-agent-gateway:e99cc43' >>"${stale_gateway_env}"
expect_runtime_failure 'stale gateway image pin' "${stale_gateway_env}"
test ! -e "${scratch_dir}/agent-runtime/github-gateway"

dangerous_env="${scratch_dir}/dangerous.env"
cp "${env_file}" "${dangerous_env}"
printf '%s\n' 'DEVELOPER_WORKSPACE=/' >>"${dangerous_env}"
expect_runtime_failure 'protected root path' "${dangerous_env}"

overlap_workspace_env="${scratch_dir}/overlap-workspace.env"
cp "${env_file}" "${overlap_workspace_env}"
printf 'REVIEWER_WORKSPACE=%s\n' \
  "${scratch_dir}/agent-runtime/developer/workspace" >>"${overlap_workspace_env}"
expect_runtime_failure 'overlapping agent workspaces' "${overlap_workspace_env}"

overlap_credentials_env="${scratch_dir}/overlap-credentials.env"
cp "${env_file}" "${overlap_credentials_env}"
printf 'REVIEWER_CREDENTIALS_DIR=%s\n' \
  "${scratch_dir}/agent-runtime/developer/credentials/child" >>"${overlap_credentials_env}"
expect_runtime_failure 'nested agent credentials' "${overlap_credentials_env}"

mkdir -p "${scratch_dir}/agent-runtime" "${scratch_dir}/symlink-target"
ln -s "${scratch_dir}/symlink-target" "${scratch_dir}/agent-runtime/reviewer-link"
symlink_env="${scratch_dir}/symlink.env"
cp "${env_file}" "${symlink_env}"
printf 'REVIEWER_WORKSPACE=%s\n' \
  "${scratch_dir}/agent-runtime/reviewer-link" >>"${symlink_env}"
expect_runtime_failure 'symlinked managed path' "${symlink_env}"

PROVISION_RUNTIME_TEST_MODE="${PROVISION_RUNTIME_TEST_MODE:-0}" \
  "${root_dir}/scripts/provision-runtime.sh" "${env_file}" >/dev/null
PROVISION_RUNTIME_TEST_MODE="${PROVISION_RUNTIME_TEST_MODE:-0}" \
  "${root_dir}/scripts/provision-agent-repository.sh" \
  test-org/test-repo main "${env_file}" >/dev/null

test "$(stat -c '%u:%g' "${source_object_path}")" = "${source_object_owner}"
git -C "${source_repository}" cat-file -e "${source_object}^{commit}"

for workspace in dispatcher developer reviewer; do
  clone_object_path="${scratch_dir}/agent-runtime/${workspace}/workspace/test-org/test-repo/.git/objects/${source_object:0:2}/${source_object:2}"
  test "$(as_root stat -c '%d:%i' "${clone_object_path}")" != "${source_object_inode}"
  as_root test ! -e "${scratch_dir}/agent-runtime/${workspace}/workspace/.git"
  as_root test -d "${scratch_dir}/agent-runtime/${workspace}/workspace/test-org/test-repo/.git"
  test "$(as_root stat -c '%u' "${scratch_dir}/agent-runtime/${workspace}/workspace")" = 10001
  test "$(as_root stat -c '%u' "${scratch_dir}/agent-runtime/${workspace}/workspace/test-org/test-repo")" = 10001
  test "$(as_root stat -c '%u' "${scratch_dir}/agent-runtime/${workspace}/credentials")" = 10001
  test "$(as_root stat -c '%a' "${scratch_dir}/agent-runtime/${workspace}/credentials")" = 700
done
if PROVISION_RUNTIME_TEST_MODE="${PROVISION_RUNTIME_TEST_MODE:-0}" \
  "${root_dir}/scripts/provision-agent-repository.sh" \
  other-org/test-repo main "${env_file}" >/dev/null 2>&1; then
  printf 'Repository outside the configured organization was accepted.\n' >&2
  exit 1
fi
(
  flock -n 9
  if PROVISION_RUNTIME_TEST_MODE="${PROVISION_RUNTIME_TEST_MODE:-0}" \
    "${root_dir}/scripts/provision-agent-repository.sh" \
    test-org/test-repo main "${env_file}" >/dev/null 2>&1; then
    printf 'Concurrent repository provisioning was accepted.\n' >&2
    exit 1
  fi
) 9>"${scratch_dir}/run/provision.lock"
test "$(stat -c '%u' "${scratch_dir}/agent-runtime/github-gateway")" = 1000
test "$(stat -c '%a' "${scratch_dir}/agent-runtime/github-gateway")" = 700

as_root jq -e '
  .roles.control.appSlug == "control-app" and
  .roles.developer.appSlug == "developer-app" and
  .roles.reviewer.appSlug == "reviewer-app"
' "${scratch_dir}/agent-runtime/github-gateway/apps.json" >/dev/null
as_root jq -e '.jobs == []' "${scratch_dir}/agent-runtime/github-gateway/jobs.json" >/dev/null
as_root jq -e '
  (.agents | length) == 3 and
  ([.agents[].id] | sort) == ["developer-a", "dispatcher-planner", "reviewer-a"]
' "${scratch_dir}/agent-runtime/github-gateway/agents.json" >/dev/null

credential_fixture="${scratch_dir}/credential-fixture"
printf '%s\n' fixture >"${credential_fixture}"
for credentials_dir in \
  "${scratch_dir}/agent-runtime/dispatcher/credentials" \
  "${scratch_dir}/agent-runtime/developer/credentials" \
  "${scratch_dir}/agent-runtime/reviewer/credentials"; do
  for credential_name in buzz-private-key buzz-auth-tag kaneo-credentials.json codex-auth.json; do
    as_root install -m 0600 -o 10001 -g 10001 \
      "${credential_fixture}" "${credentials_dir}/${credential_name}"
  done
done
for app_slug in control-app developer-app reviewer-app; do
  app_dir="${scratch_dir}/gateway-credential-base/github-apps/${app_slug}"
  as_root install -d -m 0700 -o 1000 -g 1000 "${app_dir}"
  as_root install -m 0600 -o 1000 -g 1000 "${credential_fixture}" "${app_dir}/app.json"
  as_root install -m 0600 -o 1000 -g 1000 "${credential_fixture}" "${app_dir}/private-key.pem"
done
as_root "${root_dir}/scripts/preflight.sh" "${env_file}" >/dev/null

expect_preflight_failure 'stale gateway image pin' "${stale_gateway_env}"

dispatcher_hash_before="$(as_root sha256sum "${scratch_dir}/agent-runtime/dispatcher/credentials/github-gateway-agent-token")"
developer_hash_before="$(as_root sha256sum "${scratch_dir}/agent-runtime/developer/credentials/github-gateway-agent-token")"
reviewer_hash_before="$(as_root sha256sum "${scratch_dir}/agent-runtime/reviewer/credentials/github-gateway-agent-token")"
as_root node --input-type=module -e '
  import { readFile, writeFile } from "node:fs/promises";
  const file = process.argv[1];
  const config = JSON.parse(await readFile(file, "utf8"));
  delete config.roles.control;
  await writeFile(file, `${JSON.stringify(config, null, 2)}\n`);
' "${scratch_dir}/agent-runtime/github-gateway/apps.json"
PROVISION_RUNTIME_TEST_MODE="${PROVISION_RUNTIME_TEST_MODE:-0}" \
  "${root_dir}/scripts/provision-runtime.sh" "${env_file}" >/dev/null
PROVISION_RUNTIME_TEST_MODE="${PROVISION_RUNTIME_TEST_MODE:-0}" \
  "${root_dir}/scripts/provision-agent-repository.sh" \
  test-org/test-repo main "${env_file}" >/dev/null
dispatcher_hash_after="$(as_root sha256sum "${scratch_dir}/agent-runtime/dispatcher/credentials/github-gateway-agent-token")"
developer_hash_after="$(as_root sha256sum "${scratch_dir}/agent-runtime/developer/credentials/github-gateway-agent-token")"
reviewer_hash_after="$(as_root sha256sum "${scratch_dir}/agent-runtime/reviewer/credentials/github-gateway-agent-token")"

test "${dispatcher_hash_before}" = "${dispatcher_hash_after}"
test "${developer_hash_before}" = "${developer_hash_after}"
test "${reviewer_hash_before}" = "${reviewer_hash_after}"
as_root jq -e '(.agents | length) == 3' \
  "${scratch_dir}/agent-runtime/github-gateway/agents.json" >/dev/null
as_root jq -e '.roles.control.appSlug == "control-app"' \
  "${scratch_dir}/agent-runtime/github-gateway/apps.json" >/dev/null

agents_file="${scratch_dir}/agent-runtime/github-gateway/agents.json"
agents_baseline="${scratch_dir}/agents-baseline.json"
as_root install -m 0600 -o 1000 -g 1000 "${agents_file}" "${agents_baseline}"

restore_agents() {
  as_root install -m 0600 -o 1000 -g 1000 "${agents_baseline}" "${agents_file}"
}

as_root node --input-type=module -e '
  import { readFile, writeFile } from "node:fs/promises";
  const file = process.argv[1];
  const config = JSON.parse(await readFile(file, "utf8"));
  config.agents.push({ ...config.agents.find((agent) => agent.id === "developer-a") });
  await writeFile(file, `${JSON.stringify(config, null, 2)}\n`);
' "${agents_file}"
expect_runtime_failure 'duplicate gateway agent record' "${env_file}"
expect_preflight_failure 'duplicate gateway agent record'
restore_agents

as_root node --input-type=module -e '
  import { readFile, writeFile } from "node:fs/promises";
  const file = process.argv[1];
  const config = JSON.parse(await readFile(file, "utf8"));
  config.agents.find((agent) => agent.id === "developer-a").expiresAt = "2000-01-01T00:00:00.000Z";
  await writeFile(file, `${JSON.stringify(config, null, 2)}\n`);
' "${agents_file}"
expect_runtime_failure 'expired gateway agent record' "${env_file}"
expect_preflight_failure 'expired gateway agent record'
restore_agents

as_root node --input-type=module -e '
  import { readFile, writeFile } from "node:fs/promises";
  const file = process.argv[1];
  const config = JSON.parse(await readFile(file, "utf8"));
  config.agents.find((agent) => agent.id === "developer-a").tokenSha256 = "0".repeat(64);
  await writeFile(file, `${JSON.stringify(config, null, 2)}\n`);
' "${agents_file}"
expect_runtime_failure 'mismatched gateway token' "${env_file}"


# Identity regressions operate only on this test's temporary runtime.
identity_file="${scratch_dir}/agent-runtime/developer/credentials/gitconfig"
identity_baseline="${scratch_dir}/identity-baseline"
as_root cp "${identity_file}" "${identity_baseline}"
restore_identity() {
  as_root install -m 0600 -o 10001 -g 10001 "${identity_baseline}" "${identity_file}"
}
# Restore the intentionally invalid gateway record from the previous test first.
restore_agents
as_root "${root_dir}/scripts/preflight.sh" "${env_file}" >/dev/null
as_root chown 10001:1000 "${identity_file}"
expect_preflight_failure 'identity GID'
restore_identity
as_root chmod 0644 "${identity_file}"
expect_preflight_failure 'identity mode'
restore_identity
as_root rm "${identity_file}"
expect_preflight_failure 'missing identity'
as_root ln -s "${identity_baseline}" "${identity_file}"
expect_preflight_failure 'symlink identity'
expect_runtime_failure 'symlink identity' "${env_file}"
as_root rm "${identity_file}"
restore_identity
as_root install -m 0600 -o 10001 -g 10001 \
  "${scratch_dir}/agent-runtime/reviewer/credentials/gitconfig" "${identity_file}"
expect_preflight_failure 'shared identity'
expect_runtime_failure 'conflicting identity preserved' "${env_file}"
as_root cmp "${identity_file}" "${scratch_dir}/agent-runtime/reviewer/credentials/gitconfig"
restore_identity
as_root "${root_dir}/scripts/preflight.sh" "${env_file}" >/dev/null
printf 'Runtime provisioning and identity tests passed.\n'
