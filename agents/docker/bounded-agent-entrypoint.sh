#!/usr/bin/env bash
set -euo pipefail
# Compose supplies a capacity; credential-free image smoke may use its own tmpfs.
# Run before the original entrypoint creates files or copies credentials into HOME.
if [[ -n "${AGENT_STATE_CAPACITY_BYTES:-}" ]]; then
  node "$(dirname "${BASH_SOURCE[0]}")/check-state-storage.mjs" \
    "${HOME}" "${AGENT_STATE_CAPACITY_BYTES}" || {
      printf 'agent-entrypoint: bounded persistent HOME is required\n' >&2
      exit 1
    }
fi
exec /usr/local/bin/agent-entrypoint "$@"
