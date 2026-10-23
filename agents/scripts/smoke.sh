#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -r "${root_dir}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${root_dir}/.env"
  set +a
fi

readonly claude_image="${1:-local/buzz-agent-claude:${AGENT_CLAUDE_CODE_VERSION:-2.1.278}}"
readonly codex_image="${2:-local/buzz-agent-codex:${AGENT_CODEX_VERSION:-0.163.0}}"
# No credentials or runtime mounts: verify direct and ACP-selected Codex.
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=10001,gid=10001 \
  --entrypoint node \
  --mount "type=bind,src=${root_dir}/docker,dst=/test,readonly" \
  "${codex_image}" /test/codex-runtime-smoke.mjs \
  "${AGENT_CODEX_VERSION:-0.163.0}" "${AGENT_CODEX_ACP_VERSION:-2.2.2}" \
  "${AGENT_CODEX_ACP_CODEX_VERSION:-0.160.1}"

readonly host_uid="$(id -u)"
readonly host_gid="$(id -g)"
scratch_dir="$(mktemp -d "${root_dir}/.smoke.XXXXXX")"

cleanup() {
  docker run --rm \
    --user 0:0 \
    --entrypoint chown \
    --mount "type=bind,src=${scratch_dir},dst=/smoke" \
    "${claude_image}" \
    -R "${host_uid}:${host_gid}" /smoke \
    >/dev/null 2>&1 || true
  rm -rf "${scratch_dir}"
}
trap cleanup EXIT

credentials_dir="${scratch_dir}/credential-template"
workspace_dir="${scratch_dir}/workspace"
mkdir -p "${credentials_dir}" "${workspace_dir}"
chmod 0700 "${credentials_dir}"

printf '%s' 'test-buzz-private-key' >"${credentials_dir}/buzz-private-key"
printf '%s' 'test-claude-oauth-token' >"${credentials_dir}/claude-oauth-token"
printf '%s' '{}' >"${credentials_dir}/codex-auth.json"
printf '%s' '{}' >"${credentials_dir}/kaneo-credentials.json"
printf '%s' 'test-gateway-agent-token-that-is-never-written-to-config' \
  >"${credentials_dir}/github-gateway-agent-token"
chmod 0600 "${credentials_dir}"/*

for persona in dispatcher-planner developer-a reviewer-a; do
  mkdir -p "${scratch_dir}/${persona}"
  cp "${credentials_dir}"/* "${scratch_dir}/${persona}/"
done
docker run --rm --user 0:0 --entrypoint node \
  --mount "type=bind,src=${root_dir},dst=/test,readonly" \
  --mount "type=bind,src=${scratch_dir},dst=/smoke" \
  "${codex_image}" /test/docker/git-identity.mjs install \
  /test/git-identities.example.json \
  /smoke/dispatcher-planner /smoke/developer-a /smoke/reviewer-a


docker run --rm \
  --user 0:0 \
  --entrypoint chown \
  --mount "type=bind,src=${scratch_dir},dst=/smoke" \
  "${claude_image}" \
  -R 10001:10001 /smoke

common_args=(
  --rm
  --read-only
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001
  --tmpfs /home/agent:rw,nosuid,nodev,size=128m,uid=10001,gid=10001
  --mount "type=bind,src=${root_dir}/prompts,dst=/run/agent/prompts,readonly"
  --mount "type=bind,src=${workspace_dir},dst=/workspace"
  --env BUZZ_RELAY_URL=wss://buzz.example.test
  --env BUZZ_ACP_AGENT_OWNER=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  --env KANEO_API_URL=https://kaneo.example.test
  --env ENABLE_KANEO_MCP=false
  --env ENABLE_NATIVE_MCP=true
)

docker run "${common_args[@]}" \
  --env AGENT_PROVIDER=claude \
  --mount "type=bind,src=${scratch_dir}/dispatcher-planner,dst=/run/agent/credentials,readonly" \
  --env AGENT_ROLE=dispatcher-planner \
  --env AGENT_ROLE_PROMPT=/run/agent/prompts/DISPATCHER_PLANNER.md \
  --env ENABLE_GITHUB_GATEWAY_MCP=true \
  --env GITHUB_GATEWAY_MCP_URL=http://github-gateway.example.test:8787/mcp \
  "${claude_image}" \
  bash -euc '
    test "$(git config --global user.name)" = "Fixture Dispatcher"
    test "$(git config --global user.email)" = "dispatcher@agents.example.test"
    test "$(git config --global user.useConfigOnly)" = true
    test "$(stat -c %u:%g:%a "${HOME}/.gitconfig")" = 10001:10001:600
    git init -q /tmp/identity-repo
    git -C /tmp/identity-repo commit --allow-empty -qm fixture
    test "$(git -C /tmp/identity-repo log -1 --format=%ae)" = "dispatcher@agents.example.test"
    test "$(id -u)" = 10001
    test -n "${BUZZ_PRIVATE_KEY}"
    test -n "${CLAUDE_CODE_OAUTH_TOKEN}"
    test -r "${BUZZ_ACP_SYSTEM_PROMPT_FILE}"
    grep -q "Dispatcher and planner" "${BUZZ_ACP_SYSTEM_PROMPT_FILE}"
    test -r "${XDG_CONFIG_HOME}/kaneo-mcp/credentials.json"
    test -n "${GITHUB_GATEWAY_AGENT_TOKEN}"
    test -z "${BUZZ_ACP_MCP_COMMAND+x}"
    jq -e '\''
      .mcpServers.kaneo.type == "stdio" and
      .mcpServers.kaneo.command == "kaneo-mcp-safe-proxy" and
      .mcpServers.github_gateway.type == "http" and
      .mcpServers.github_gateway.url == "http://github-gateway.example.test:8787/mcp" and
      .mcpServers.github_gateway.headers.Authorization == "Bearer ${GITHUB_GATEWAY_AGENT_TOKEN}"
    '\'' "${HOME}/.claude.json" >/dev/null
    if grep -Fq "test-gateway-agent-token-that-is-never-written-to-config" "${HOME}/.claude.json"; then exit 1; fi
  '

docker run "${common_args[@]}" \
  --env AGENT_PROVIDER=claude \
  --mount "type=bind,src=${scratch_dir}/reviewer-a,dst=/run/agent/credentials,readonly" \
  --env AGENT_ROLE=reviewer \
  --env AGENT_ROLE_PROMPT=/run/agent/prompts/REVIEWER.md \
  --env ENABLE_GITHUB_GATEWAY_MCP=true \
  --env GITHUB_GATEWAY_MCP_URL=http://github-gateway.example.test:8787/mcp \
  "${claude_image}" \
  bash -euc '
    test "$(git config --global user.name)" = "Fixture Reviewer"
    test "$(git config --global user.email)" = "reviewer@agents.example.test"
    test "$(git config --global user.useConfigOnly)" = true
    test "$(stat -c %u:%g:%a "${HOME}/.gitconfig")" = 10001:10001:600
    git init -q /tmp/identity-repo
    git -C /tmp/identity-repo commit --allow-empty -qm fixture
    test "$(git -C /tmp/identity-repo log -1 --format=%ae)" = "reviewer@agents.example.test"
    test -n "${GITHUB_GATEWAY_AGENT_TOKEN}"
    test -z "${BUZZ_ACP_MCP_COMMAND+x}"
    jq -e '\''
      .mcpServers.kaneo.command == "kaneo-mcp-safe-proxy" and
      .mcpServers.github_gateway.type == "http" and
      .mcpServers.github_gateway.url == "http://github-gateway.example.test:8787/mcp" and
      .mcpServers.github_gateway.headers.Authorization == "Bearer ${GITHUB_GATEWAY_AGENT_TOKEN}"
    '\'' "${HOME}/.claude.json" >/dev/null
    if grep -Fq "test-gateway-agent-token-that-is-never-written-to-config" "${HOME}/.claude.json"; then exit 1; fi
  '

docker run "${common_args[@]}" \
  --env AGENT_PROVIDER=codex \
  --mount "type=bind,src=${scratch_dir}/developer-a,dst=/run/agent/credentials,readonly" \
  --env AGENT_ROLE=developer \
  --env AGENT_ROLE_PROMPT=/run/agent/prompts/DEVELOPER.md \
  --env ENABLE_GITHUB_GATEWAY_MCP=true \
  --env GITHUB_GATEWAY_MCP_URL=http://github-gateway.example.test:8787/mcp \
  "${codex_image}" \
  bash -euc '
    test "$(git config --global user.name)" = "Fixture Developer"
    test "$(git config --global user.email)" = "developer@agents.example.test"
    test "$(git config --global user.useConfigOnly)" = true
    test "$(stat -c %u:%g:%a "${HOME}/.gitconfig")" = 10001:10001:600
    git init -q /tmp/identity-repo
    git -C /tmp/identity-repo commit --allow-empty -qm fixture
    test "$(git -C /tmp/identity-repo log -1 --format=%ae)" = "developer@agents.example.test"
    test "$(id -u)" = 10001
    test -n "${BUZZ_PRIVATE_KEY}"
    test -r "${CODEX_HOME}/auth.json"
    test -r "${BUZZ_ACP_SYSTEM_PROMPT_FILE}"
    grep -q "Developer" "${BUZZ_ACP_SYSTEM_PROMPT_FILE}"
    test -r "${XDG_CONFIG_HOME}/kaneo-mcp/credentials.json"
    test -n "${GITHUB_GATEWAY_AGENT_TOKEN}"
    test -z "${BUZZ_ACP_MCP_COMMAND+x}"
    grep -Fq "[mcp_servers.kaneo]" "${CODEX_HOME}/config.toml"
    grep -Fq "[mcp_servers.github_gateway]" "${CODEX_HOME}/config.toml"
    grep -Fq '\''bearer_token_env_var = "GITHUB_GATEWAY_AGENT_TOKEN"'\'' "${CODEX_HOME}/config.toml"
    if grep -Fq "test-gateway-agent-token-that-is-never-written-to-config" "${CODEX_HOME}/config.toml"; then exit 1; fi
    set -o pipefail
    check_mcp_registration() {
    jq -e '\''
      length == 2 and
      (map(.name) | sort) == ["github_gateway", "kaneo"] and
      (.[] | select(.name == "github_gateway") |
        .transport.type == "streamable_http" and
        .transport.bearer_token_env_var == "GITHUB_GATEWAY_AGENT_TOKEN")
    '\'' >/dev/null
    }
    codex mcp list --json | check_mcp_registration
    codex-acp cli mcp list --json | check_mcp_registration
  '

printf 'Container entrypoint smoke tests passed.\n'
