#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -r "${root_dir}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${root_dir}/.env"
  set +a
fi

: "${AGENT_BUZZ_SPRIG_IMAGE:=ghcr.io/block/buzz-sprig:sha-6530b58@sha256:17facfc7608d8ddb33bc056c9aaba1098f4ef6abe5655702fbfd7584d1f74d76}"
: "${AGENT_CLAUDE_CODE_VERSION:=2.1.278}"
: "${AGENT_CLAUDE_ACP_VERSION:=0.79.0}"
: "${AGENT_CODEX_VERSION:=0.154.0}"
: "${AGENT_CODEX_ACP_VERSION:=1.12.0}"
: "${AGENT_KANEO_MCP_VERSION:=0.1.11}"
: "${DOCKER_BUILDKIT:=0}"
export DOCKER_BUILDKIT

readonly claude_image="local/buzz-agent-claude:${AGENT_CLAUDE_CODE_VERSION}"
readonly codex_image="local/buzz-agent-codex:${AGENT_CODEX_VERSION}"

docker build \
  --build-arg "BUZZ_SPRIG_IMAGE=${AGENT_BUZZ_SPRIG_IMAGE}" \
  --build-arg "CLAUDE_CODE_VERSION=${AGENT_CLAUDE_CODE_VERSION}" \
  --build-arg "CLAUDE_ACP_VERSION=${AGENT_CLAUDE_ACP_VERSION}" \
  --build-arg "KANEO_MCP_VERSION=${AGENT_KANEO_MCP_VERSION}" \
  --file "${root_dir}/docker/Dockerfile.claude" \
  --tag "${claude_image}" \
  "${root_dir}"

docker build \
  --build-arg "BUZZ_SPRIG_IMAGE=${AGENT_BUZZ_SPRIG_IMAGE}" \
  --build-arg "CODEX_VERSION=${AGENT_CODEX_VERSION}" \
  --build-arg "CODEX_ACP_VERSION=${AGENT_CODEX_ACP_VERSION}" \
  --build-arg "KANEO_MCP_VERSION=${AGENT_KANEO_MCP_VERSION}" \
  --file "${root_dir}/docker/Dockerfile.codex" \
  --tag "${codex_image}" \
  "${root_dir}"

docker run --rm \
  --entrypoint node \
  --mount "type=bind,src=${root_dir}/docker,dst=/test,readonly" \
  "${codex_image}" \
  --test /test/kaneo-mcp-safe-proxy.test.mjs

"${root_dir}/scripts/smoke.sh" "${claude_image}" "${codex_image}"
"${root_dir}/scripts/test-provision-gateway-agent.sh" "${codex_image}"
