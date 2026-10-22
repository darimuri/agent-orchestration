#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -r "${root_dir}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${root_dir}/.env"
  set +a
fi

readonly image="${1:-local/buzz-agent-codex:${AGENT_CODEX_VERSION:-0.163.0}}"
readonly host_uid="$(id -u)"
readonly host_gid="$(id -g)"
scratch_dir="$(mktemp -d "${root_dir}/.provision-smoke.XXXXXX")"

cleanup() {
  docker run --rm \
    --user 0:0 \
    --entrypoint rm \
    --mount "type=bind,src=${scratch_dir},dst=/state" \
    "${image}" \
    -rf /state/data \
    >/dev/null 2>&1 || true
  chown "${host_uid}:${host_gid}" "${scratch_dir}" >/dev/null 2>&1 || true
  rmdir "${scratch_dir}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

provision() {
  local state="$1"
  local agent_id="$2"
  local role="$3"
  local ttl="${4:-30}"

  docker run --rm \
    --user 0:0 \
    --entrypoint node \
    --env "GATEWAY_AGENT_TOKEN_TTL_DAYS=${ttl}" \
    --mount "type=bind,src=${root_dir}/scripts/provision-gateway-agent.mjs,dst=/test/provision.mjs,readonly" \
    --mount "type=bind,src=${state},dst=/state" \
    "${image}" \
    /test/provision.mjs "${agent_id}" "${role}" \
    "/state/${agent_id}-credentials" /state/runtime
}

mkdir -p "${scratch_dir}/data"

ttl_state="${scratch_dir}/data/ttl"
mkdir -p "${ttl_state}/developer-a-credentials" "${ttl_state}/runtime"
printf '%s\n' '{"agents":[]}' >"${ttl_state}/runtime/agents.json"
for invalid_ttl in 1e2 30days 30.5 0 366; do
  if provision "${ttl_state}" developer-a developer "${invalid_ttl}" >/dev/null 2>&1; then
    printf 'Invalid TTL was accepted: %s\n' "${invalid_ttl}" >&2
    exit 1
  fi
done
if provision "${ttl_state}" dispatcher-planner invalid-role >/dev/null 2>&1; then
  printf 'Invalid gateway role was accepted.\n' >&2
  exit 1
fi

rotation_state="${scratch_dir}/data/rotation"
mkdir -p "${rotation_state}/developer-a-credentials" "${rotation_state}/runtime"
printf '%s\n' '{"agents":[]}' >"${rotation_state}/runtime/agents.json"
provision "${rotation_state}" developer-a developer >/dev/null
provision "${rotation_state}" developer-a developer >/dev/null

rollback_state="${scratch_dir}/data/rollback"
mkdir -p \
  "${rollback_state}/developer-a-credentials/github-gateway-agent-token" \
  "${rollback_state}/runtime"
printf '%s\n' '{"agents":[]}' >"${rollback_state}/runtime/agents.json"
if provision "${rollback_state}" developer-a developer >/dev/null 2>&1; then
  printf 'Expected token installation failure was not raised.\n' >&2
  exit 1
fi

lock_state="${scratch_dir}/data/lock"
mkdir -p "${lock_state}/developer-a-credentials" "${lock_state}/runtime"
printf '%s\n' '{"agents":[]}' >"${lock_state}/runtime/agents.json"
docker run --rm \
  --user 0:0 \
  --entrypoint flock \
  --mount "type=bind,src=${lock_state},dst=/state" \
  "${image}" \
  --exclusive /state/runtime/.provision-gateway-agent.lock \
  sh -c 'touch /state/lock-held; sleep 2' &
lock_holder_pid=$!
for _ in $(seq 1 20); do
  [[ -f "${lock_state}/lock-held" ]] && break
  sleep 0.1
done
[[ -f "${lock_state}/lock-held" ]] || {
  printf 'Failed to establish the provisioning test lock.\n' >&2
  exit 1
}
provision "${lock_state}" developer-a developer >/dev/null &
blocked_provision_pid=$!
sleep 0.25
if ! kill -0 "${blocked_provision_pid}" 2>/dev/null; then
  printf 'Provisioning did not wait for the shared agents.json lock.\n' >&2
  exit 1
fi
wait "${lock_holder_pid}"
wait "${blocked_provision_pid}"

concurrent_state="${scratch_dir}/data/concurrent"
mkdir -p \
  "${concurrent_state}/dispatcher-planner-credentials" \
  "${concurrent_state}/developer-a-credentials" \
  "${concurrent_state}/reviewer-a-credentials" \
  "${concurrent_state}/runtime"
printf '%s\n' '{"agents":[]}' >"${concurrent_state}/runtime/agents.json"
provision "${concurrent_state}" dispatcher-planner control >/dev/null &
dispatcher_pid=$!
provision "${concurrent_state}" developer-a developer >/dev/null &
developer_pid=$!
provision "${concurrent_state}" reviewer-a reviewer >/dev/null &
reviewer_pid=$!
wait "${dispatcher_pid}"
wait "${developer_pid}"
wait "${reviewer_pid}"

docker run --rm \
  --user 0:0 \
  --entrypoint node \
  --mount "type=bind,src=${scratch_dir}/data,dst=/state,readonly" \
  "${image}" \
  --input-type=module \
  -e '
    import { createHash } from "node:crypto";
    import { readFile, stat } from "node:fs/promises";

    async function assertPair(state, agentId) {
      const tokenPath = `/state/${state}/${agentId}-credentials/github-gateway-agent-token`;
      const agentsPath = `/state/${state}/runtime/agents.json`;
      const token = await readFile(tokenPath, "utf8");
      const config = JSON.parse(await readFile(agentsPath, "utf8"));
      const records = config.agents.filter((agent) => agent.id === agentId);
      if (records.length !== 1) throw new Error(`${state}/${agentId}: expected one agent record`);
      const hash = createHash("sha256").update(token).digest("hex");
      if (records[0].tokenSha256 !== hash) throw new Error(`${state}/${agentId}: token/hash mismatch`);
      const tokenStat = await stat(tokenPath);
      if ((tokenStat.mode & 0o777) !== 0o600 || tokenStat.uid !== 10001) {
        throw new Error(`${state}/${agentId}: invalid token metadata`);
      }
    }

    await assertPair("rotation", "developer-a");
    const rollback = JSON.parse(await readFile("/state/rollback/runtime/agents.json", "utf8"));
    if (rollback.agents.length !== 0) throw new Error("token failure did not roll back agents.json");
    await assertPair("lock", "developer-a");
    await assertPair("concurrent", "dispatcher-planner");
    await assertPair("concurrent", "developer-a");
    await assertPair("concurrent", "reviewer-a");
    const concurrent = JSON.parse(await readFile("/state/concurrent/runtime/agents.json", "utf8"));
    if (concurrent.agents.length !== 3) throw new Error("parallel provisioning lost an agent update");
  '

printf 'Gateway agent provisioning tests passed.\n'
