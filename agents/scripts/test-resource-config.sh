#!/usr/bin/env bash
# Offline render: no .env, credential reads, daemon calls or runtime mounts.
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
compose=(docker compose)
if [[ -n "${COMPOSE_BIN:-}" ]]; then compose=("$COMPOSE_BIN"); fi
render() {
  # env -i prevents operational overrides/COMPOSE_* leaking into the fixture.
  env -i PATH="$PATH" HOME="$scratch" \
    BUZZ_RELAY_URL=wss://buzz.example.test BUZZ_AGENT_OWNER_HEX="$(printf '%064d' 0)" \
    KANEO_API_URL=https://kaneo.example.test AGENT_RUNTIME_ROOT=/tmp/buzz-resource-config/runtime \
    GITHUB_GATEWAY_CREDENTIALS_ROOT=/tmp/buzz-resource-config/gateway-credentials \
    GITHUB_GATEWAY_RUNTIME_DIR=/tmp/buzz-resource-config/gateway-runtime \
    DISPATCHER_CREDENTIALS_DIR=/tmp/buzz-resource-config/dispatcher-credentials \
    DEVELOPER_CREDENTIALS_DIR=/tmp/buzz-resource-config/developer-credentials \
    REVIEWER_CREDENTIALS_DIR=/tmp/buzz-resource-config/reviewer-credentials \
    DISPATCHER_WORKSPACE=/tmp/buzz-resource-config/dispatcher-workspace \
    DEVELOPER_WORKSPACE=/tmp/buzz-resource-config/developer-workspace \
    REVIEWER_WORKSPACE=/tmp/buzz-resource-config/reviewer-workspace \
    "$@" "${compose[@]}" --project-directory "$scratch" --env-file /dev/null \
    -f "$root_dir/compose.yaml" config --format json > "$scratch/config.json"
}
render env
node "$root_dir/scripts/verify-resource-config.mjs" "$scratch/config.json"
node --input-type=module - "$scratch/config.json" <<'JS'
import fs from 'node:fs'; import assert from 'node:assert/strict';
const { services } = JSON.parse(fs.readFileSync(process.argv[2]));
assert.equal(services['host-operator'], undefined);
for (const [role, cpu, memory, state] of [['dispatcher-planner',1,2,536870912],['developer-a',4,8,2147483648],['reviewer-a',2,4,1073741824]]) {
  const s = services[role]; assert.equal(Number(s.cpus), cpu); assert.equal(Number(s.mem_limit), memory * 1024 ** 3);
  assert.equal(Number(s.environment.AGENT_STATE_CAPACITY_BYTES), state);
}
assert.equal(services['developer-a'].build.args.CODEX_VERSION, '0.163.0');
assert.equal(services['developer-a'].build.args.CODEX_ACP_VERSION, '2.2.2');
JS
render env DEVELOPER_CPUS=2.5 DEVELOPER_MEM_LIMIT=6g DEVELOPER_STATE_BYTES=1073741824
node "$root_dir/scripts/verify-resource-config.mjs" "$scratch/config.json"
node --input-type=module - "$scratch/config.json" <<'JS'
import fs from 'node:fs'; import assert from 'node:assert/strict';
const s=JSON.parse(fs.readFileSync(process.argv[2])).services['developer-a'];
assert.equal(Number(s.cpus),2.5); assert.equal(Number(s.mem_limit),6*1024**3); assert.equal(s.memswap_limit,s.mem_limit);
assert.equal(s.environment.AGENT_STATE_CAPACITY_BYTES,'1073741824');
JS
render env DEVELOPER_CPUS=0
if node "$root_dir/scripts/verify-resource-config.mjs" "$scratch/config.json"; then
  echo 'Expected unlimited CPU override to fail policy validation' >&2; exit 1
fi
echo 'Compose defaults, overrides and negative config checks PASS'
# Fourth role is profile-only: no new mandatory credential/workspace env variables.
render env COMPOSE_PROFILES=host-operator
node "$root_dir/scripts/verify-resource-config.mjs" "$scratch/config.json"
node --input-type=module - "$scratch/config.json" <<'JS'
import fs from 'node:fs';import assert from 'node:assert/strict';
const s=JSON.parse(fs.readFileSync(process.argv[2])).services['host-operator'];
assert(s);assert.equal(Number(s.cpus),1);assert.equal(Number(s.mem_limit),2*1024**3);
assert.equal(s.environment.AGENT_STATE_CAPACITY_BYTES,'536870912');assert(!s.depends_on);
assert.equal(s.build.args.CODEX_VERSION,'0.163.0');assert.equal(s.build.args.CODEX_ACP_VERSION,'2.2.2');
JS
render env COMPOSE_PROFILES=host-operator HOST_OPERATOR_CPUS=1.5 HOST_OPERATOR_MEM_LIMIT=3g HOST_OPERATOR_STATE_BYTES=1073741824
node "$root_dir/scripts/verify-resource-config.mjs" "$scratch/config.json"
node --input-type=module - "$scratch/config.json" <<'JS'
import fs from 'node:fs';import assert from 'node:assert/strict';const s=JSON.parse(fs.readFileSync(process.argv[2])).services['host-operator'];assert.equal(Number(s.cpus),1.5);assert.equal(Number(s.mem_limit),3*1024**3);assert.equal(s.environment.AGENT_STATE_CAPACITY_BYTES,'1073741824');
JS
render env COMPOSE_PROFILES=host-operator HOST_OPERATOR_CPUS=0
if node "$root_dir/scripts/verify-resource-config.mjs" "$scratch/config.json"; then
  echo 'Expected unlimited fourth CPU override to fail' >&2; exit 1
fi
echo 'Disconnected fourth profile defaults, overrides and negatives PASS'
