#!/usr/bin/env bash
# Explicit trusted-host invocation only: root loop mounts + a disposable Compose project.
set -euo pipefail
umask 077
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$EUID" == 0 ]] || { echo 'Run on the trusted test host as root; no implicit sudo.' >&2; exit 1; }
for tool in docker node timeout findmnt losetup mkfs.ext4 fallocate mount umount; do
  command -v "$tool" >/dev/null || { echo "Missing test prerequisite: $tool" >&2; exit 1; }
done
docker info >/dev/null
docker compose version >/dev/null
scratch="$(mktemp -d /tmp/buzz-resource-test.XXXXXXXX)"
export RESOURCE_TEST_ROOT="${scratch}/runtime"
export RESOURCE_TEST_SOURCE="$root_dir"
export RESOURCE_TEST_IMAGE="${1:-local/buzz-agent-codex:0.163.0}"
project="buzz-resource-$(basename "$scratch" | tr '[:upper:].' '[:lower:]-')"
compose=(docker compose --project-directory "$scratch" --env-file /dev/null -p "$project" -f "$root_dir/tests/resources/compose.yaml")
cleanup() {
  local result=$?
  trap - EXIT
  # Never remove host files unless this exact project is gone and loop mounts released.
  if "${compose[@]}" down --volumes --remove-orphans --timeout 5 && \
    node "$root_dir/scripts/state-storage.mjs" unmount "$RESOURCE_TEST_ROOT" 67108864 67108864 67108864; then
    rm -rf -- "$scratch"
  else
    echo "Cleanup blocked; preserve disposable fixture for host inspection: $scratch" >&2
    result=1
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
mkdir "$RESOURCE_TEST_ROOT"
node "$root_dir/scripts/state-storage.mjs" prepare "$RESOURCE_TEST_ROOT" 67108864 67108864 67108864
# Idempotency must preserve image inode and mount identity.
image_inode="$(stat -c %d:%i "$RESOURCE_TEST_ROOT/state-storage/developer-a.img")"
node "$root_dir/scripts/state-storage.mjs" prepare "$RESOURCE_TEST_ROOT" 67108864 67108864 67108864
[[ "$(stat -c %d:%i "$RESOURCE_TEST_ROOT/state-storage/developer-a.img")" == "$image_inode" ]]
# New image wrapper must reject ephemeral HOME before any credential loading.
if docker run --rm --network none --read-only --cpus .25 --memory 128m --memory-swap 128m \
  --user 10001:10001 --tmpfs /home/agent:rw,nosuid,nodev,size=16m,uid=10001,gid=10001 \
  --env AGENT_STATE_CAPACITY_BYTES=536870912 "$RESOURCE_TEST_IMAGE" true >"$scratch/startup-negative.log" 2>&1; then
  echo 'Ephemeral HOME unexpectedly passed image startup guard' >&2; exit 1
fi
grep -q 'bounded persistent HOME is required' "$scratch/startup-negative.log"
"${compose[@]}" config --quiet
"${compose[@]}" create probe oom
probe_id="$("${compose[@]}" ps -aq probe)"
oom_id="$("${compose[@]}" ps -aq oom)"
for attempt in 1 2; do
  docker start "$probe_id" >/dev/null
  [[ "$(timeout 45 docker wait "$probe_id")" == 0 ]]
done
docker logs "$probe_id" | grep -q 'initial state PASS'
docker logs "$probe_id" | grep -q 'restart persistence PASS'
docker start "$oom_id" >/dev/null
[[ "$(timeout 45 docker wait "$oom_id")" == 137 ]]
[[ "$(docker inspect --format '{{.State.OOMKilled}}' "$oom_id")" == true ]]
# Restrict inspect output to limits/state: never dump environment or credential mounts.
docker inspect --format '{{.Name}} CPU={{.HostConfig.NanoCpus}} Memory={{.HostConfig.Memory}} MemorySwap={{.HostConfig.MemorySwap}} OOMKilled={{.State.OOMKilled}} Exit={{.State.ExitCode}}' "$probe_id" "$oom_id"
docker logs "$probe_id"
# Prove restart durability through unmount/remount, not only Docker restart.
node "$root_dir/scripts/state-storage.mjs" unmount "$RESOURCE_TEST_ROOT" 67108864 67108864 67108864
node "$root_dir/scripts/state-storage.mjs" prepare "$RESOURCE_TEST_ROOT" 67108864 67108864 67108864
[[ "$(cat "$RESOURCE_TEST_ROOT/state-storage/developer-a/persistence-marker")" == restart-safe ]]
echo 'Isolated resource limits: CPU throttling, OOM kill, no swap, ENOSPC and restart/remount persistence PASS'
