#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly credentials_dir="${AGENT_CREDENTIALS_DIR:-/run/agent/credentials}"
readonly common_prompt="${AGENT_COMMON_PROMPT:-/run/agent/prompts/COMMON.md}"
readonly role_prompt="${AGENT_ROLE_PROMPT:-}"
readonly generated_prompt="${HOME}/.agent/system-prompt.md"
configure_native_mcp=false

die() {
  printf 'agent-entrypoint: %s\n' "$*" >&2
  exit 1
}

read_secret() {
  local variable_name="$1"
  local file_name="$2"
  local required="${3:-false}"
  local path="${credentials_dir}/${file_name}"

  if [[ ! -r "${path}" ]]; then
    if [[ "${required}" == "true" ]]; then
      die "required credential file is missing or unreadable: ${path}"
    fi
    return 1
  fi

  local value
  value="$(<"${path}")"
  [[ -n "${value}" ]] || die "credential file is empty: ${path}"
  printf -v "${variable_name}" '%s' "${value}"
  export "${variable_name}"
}

copy_private_file() {
  local source_name="$1"
  local destination="$2"
  local source="${credentials_dir}/${source_name}"

  [[ -r "${source}" ]] || return 1
  mkdir -p "$(dirname "${destination}")"
  install -m 0600 "${source}" "${destination}"
}

[[ -r "${common_prompt}" ]] || die "common prompt is missing: ${common_prompt}"
[[ -n "${role_prompt}" && -r "${role_prompt}" ]] \
  || die "role prompt is missing: ${role_prompt:-<unset>}"
[[ -d /workspace ]] || die "workspace mount is missing: /workspace"
[[ -n "${BUZZ_RELAY_URL:-}" ]] || die "BUZZ_RELAY_URL is required"
[[ -n "${BUZZ_ACP_AGENT_OWNER:-}" ]] || die "BUZZ_ACP_AGENT_OWNER is required"

# A missing/invalid mounted identity must not fall back to persistent HOME state.
node "$(dirname "${BASH_SOURCE[0]}")/git-identity.mjs" apply \
  "${credentials_dir}/gitconfig" "${HOME}/.gitconfig" "${AGENT_ROLE:-}" \
  || die "Git identity is required; provision approved persona identities before starting"

mkdir -p "$(dirname "${generated_prompt}")" "${XDG_CONFIG_HOME}" "${XDG_CACHE_HOME}"
{
  printf '<common-instructions>\n'
  cat "${common_prompt}"
  printf '\n</common-instructions>\n\n<role-instructions role="%s">\n' "${AGENT_ROLE:-unknown}"
  cat "${role_prompt}"
  printf '\n</role-instructions>\n'
} >"${generated_prompt}"
chmod 0600 "${generated_prompt}"
export BUZZ_ACP_SYSTEM_PROMPT_FILE="${generated_prompt}"

read_secret BUZZ_PRIVATE_KEY buzz-private-key true
read_secret BUZZ_AUTH_TAG buzz-auth-tag false || true
read_secret BUZZ_API_TOKEN buzz-api-token false || true
read_secret GH_TOKEN gh-token false || true

if copy_private_file git-credentials "${HOME}/.git-credentials"; then
  git config --global credential.helper store
fi

if copy_private_file git-ssh-key "${HOME}/.ssh/id_ed25519"; then
  chmod 0700 "${HOME}/.ssh"
  copy_private_file known_hosts "${HOME}/.ssh/known_hosts" || true
fi

if [[ "${ENABLE_NATIVE_MCP:-false}" == "true" ]]; then
  [[ "${ENABLE_KANEO_MCP:-false}" == "false" ]] \
    || die "ENABLE_KANEO_MCP must be false when native MCP configuration is enabled"
  [[ -n "${KANEO_API_URL:-}" ]] || die "KANEO_API_URL is required when Kaneo MCP is enabled"
  copy_private_file kaneo-credentials.json \
    "${XDG_CONFIG_HOME}/kaneo-mcp/credentials.json" \
    || die "Kaneo credential file is missing: ${credentials_dir}/kaneo-credentials.json"
  if [[ "${ENABLE_GITHUB_GATEWAY_MCP:-false}" == "true" ]]; then
    [[ -n "${GITHUB_GATEWAY_MCP_URL:-}" ]] \
      || die "GITHUB_GATEWAY_MCP_URL is required when GitHub gateway MCP is enabled"
    read_secret GITHUB_GATEWAY_AGENT_TOKEN github-gateway-agent-token true
  fi
  unset BUZZ_ACP_MCP_COMMAND
  configure_native_mcp=true
elif [[ "${ENABLE_KANEO_MCP:-false}" == "true" ]]; then
  [[ -n "${KANEO_API_URL:-}" ]] || die "KANEO_API_URL is required when Kaneo MCP is enabled"
  copy_private_file kaneo-credentials.json \
    "${XDG_CONFIG_HOME}/kaneo-mcp/credentials.json" \
    || die "Kaneo credential file is missing: ${credentials_dir}/kaneo-credentials.json"
  export BUZZ_ACP_MCP_COMMAND="kaneo-mcp-safe-proxy"
else
  unset BUZZ_ACP_MCP_COMMAND
fi

case "${AGENT_PROVIDER:-}" in
  claude)
    if read_secret CLAUDE_CODE_OAUTH_TOKEN claude-oauth-token false; then
      :
    elif read_secret ANTHROPIC_API_KEY anthropic-api-key false; then
      :
    else
      die "Claude requires claude-oauth-token or anthropic-api-key"
    fi
    export BUZZ_ACP_AGENT_COMMAND="claude-agent-acp"
    export BUZZ_ACP_AGENT_ARGS=""
    ;;
  codex)
    mkdir -p "${CODEX_HOME}"
    has_codex_auth=false
    if copy_private_file codex-auth.json "${CODEX_HOME}/auth.json"; then
      has_codex_auth=true
    fi
    if read_secret OPENAI_API_KEY openai-api-key false; then
      export CODEX_API_KEY="${OPENAI_API_KEY}"
      has_codex_auth=true
    fi
    [[ "${has_codex_auth}" == "true" ]] \
      || die "Codex requires codex-auth.json or openai-api-key"
    export BUZZ_ACP_AGENT_COMMAND="codex-acp"
    export BUZZ_ACP_AGENT_ARGS=""
    ;;
  *)
    die "unsupported AGENT_PROVIDER: ${AGENT_PROVIDER:-<unset>}"
    ;;
esac

if [[ "${configure_native_mcp}" == "true" ]]; then
  node /usr/local/libexec/generate-mcp-config.mjs "${AGENT_PROVIDER}"
fi

printf 'Starting %s agent with %s; prompts and credentials loaded from mounted volumes.\n' \
  "${AGENT_ROLE:-unknown}" "${AGENT_PROVIDER}" >&2

exec "$@"
