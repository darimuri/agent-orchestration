#!/usr/bin/env bash
# Explicit disposable ROOT+Docker/ext4 acceptance only. Never target live runtime.
set -euo pipefail
umask 077
(( EUID == 0 )) || { echo 'requires trusted disposable root host' >&2; exit 1; }
[[ $# == 1 && "$1" != -* ]] || { echo 'supply isolated test Codex image tag/digest' >&2; exit 1; }
for tool in docker node git flock findmnt losetup mkfs.ext4 fallocate mount umount; do command -v "$tool" >/dev/null || { echo 'host fixture prerequisite missing' >&2; exit 1; }; done
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d /tmp/host-operator-provisioning.XXXXXXXX)"
runtime="$scratch/runtime"; image="$1"; mounted=false
cleanup(){
 local code=$?;trap - EXIT
 if [[ "$mounted" == true ]]; then
   if ! node "$root_dir/scripts/state-storage.mjs" --agent host-operator unmount "$runtime" 67108864; then echo 'preserving fixture for host inspection' >&2; exit 1; fi
 fi
 rm -rf "$scratch";exit "$code"
}
trap cleanup EXIT
mkdir -p "$runtime" "$scratch/run";chmod 0755 "$runtime"
cp "$root_dir/git-identities.example.json" "$scratch/legacy.json"
cp "$root_dir/host-operator-git-identity.example.json" "$scratch/host.json"
for role in dispatcher-planner developer-a reviewer-a github-gateway; do mkdir -p "$runtime/$role";echo 'old fixture sentinel' > "$runtime/$role/sentinel";done
snapshot(){ find "$runtime/dispatcher-planner" "$runtime/developer-a" "$runtime/reviewer-a" "$runtime/github-gateway" -type f -exec sha256sum {} + | sort; }
snapshot > "$scratch/before"
cat > "$scratch/fixture.env" <<EOF
AGENT_RUNTIME_ROOT=$runtime
AGENT_GIT_IDENTITY_MANIFEST=$scratch/legacy.json
HOST_OPERATOR_GIT_IDENTITY_MANIFEST=$scratch/host.json
AGENT_WORKSPACE_ORGANIZATION=fixture-org
AGENT_WORKSPACE_GIT_URL_TEMPLATE=$scratch/sources/{owner}/{repository}.git
XDG_RUNTIME_DIR=$scratch/run
BUZZ_RELAY_URL=wss://fixture.invalid
KANEO_API_URL=https://fixture.invalid
BUZZ_AGENT_OWNER_HEX=$(printf a%.0s {1..64})
HOST_OPERATOR_EXISTING_BUZZ_PUBKEYS=$(printf 1%.0s {1..64}),$(printf 2%.0s {1..64}),$(printf 3%.0s {1..64})
HOST_OPERATOR_BUZZ_PUBKEY=$(printf 4%.0s {1..64})
HOST_OPERATOR_KANEO_USER_ID=fixture-host-actor
HOST_OPERATOR_STATE_BYTES=67108864
EOF
# No Gateway variables; default legacy invocation fails rather than touching fourth.
if PROVISION_RUNTIME_TEST_MODE=1 bash "$root_dir/scripts/provision-runtime.sh" "$scratch/fixture.env" > "$scratch/default.log" 2>&1; then echo 'legacy default unexpectedly accepted missing Gateway' >&2;exit 1;fi
[[ ! -e "$runtime/host-operator" ]]
for i in 1 2; do PROVISION_RUNTIME_TEST_MODE=1 bash "$root_dir/scripts/provision-runtime.sh" --agent host-operator "$scratch/fixture.env";done
[[ ! -e "$runtime/host-operator/credentials/github-gateway-agent-token" ]]
source_repo="$scratch/sources/fixture-org/example.git";mkdir -p "$source_repo"
git -C "$source_repo" init -q --initial-branch=main
git -C "$source_repo" -c user.name=fixture -c user.email=fixture@example.test commit -q --allow-empty -m fixture
for i in 1 2; do PROVISION_RUNTIME_TEST_MODE=1 bash "$root_dir/scripts/provision-agent-repository.sh" --agent host-operator fixture-org/example main "$scratch/fixture.env";done
[[ ! -e "$runtime/developer-a/workspace" ]]
node "$root_dir/scripts/state-storage.mjs" --agent host-operator prepare "$runtime" 67108864
mounted=true
home="$runtime/state-storage/host-operator";recovery="$home/lost+found"
[[ "$(stat -c %u:%g:%a "$recovery")" == 0:0:700 ]]
[[ -z "$(find "$recovery" -mindepth 1 -print -quit)" ]]
recovery_id="$(stat -c %d:%i "$recovery")"
creds="$runtime/host-operator/credentials"
for n in buzz-private-key buzz-auth-tag kaneo-credentials.json codex-auth.json; do printf '{}' > "$creds/$n";chown 10001:10001 "$creds/$n";chmod 0600 "$creds/$n";done
bash "$root_dir/scripts/preflight.sh" --agent host-operator "$scratch/fixture.env"
for i in 1 2; do
 docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001 \
  --mount "type=bind,src=$home,dst=/home/agent" \
  --mount "type=bind,src=$creds,dst=/run/agent/credentials,readonly" \
  --mount "type=bind,src=$runtime/host-operator/workspace,dst=/workspace,readonly" \
  --mount "type=bind,src=$root_dir/prompts,dst=/run/agent/prompts,readonly" \
  --env AGENT_ROLE=host-operator --env AGENT_PROVIDER=codex \
  --env AGENT_ROLE_PROMPT=/run/agent/prompts/HOST_OPERATOR.md --env AGENT_STATE_CAPACITY_BYTES=67108864 \
  --env ENABLE_NATIVE_MCP=true --env ENABLE_KANEO_MCP=false --env ENABLE_GITHUB_GATEWAY_MCP=false \
  --env BUZZ_ACP_AGENTS=1 --env BUZZ_ACP_RESPOND_TO=owner-only --env BUZZ_ACP_SESSION_TITLE='Host Operator' \
  --env BUZZ_RELAY_URL=wss://fixture.invalid --env BUZZ_ACP_AGENT_OWNER="$(printf a%.0s {1..64})" \
  --env BUZZ_ACP_SYSTEM_PROMPT_FILE=/home/agent/.agent/system-prompt.md --env KANEO_API_URL=https://fixture.invalid \
  "$image" node -e 'const fs=require("fs");fs.writeFileSync(process.env.HOME+"/.cache/f2-marker","fixture");try{fs.writeFileSync("/workspace/forbidden","bad");process.exit(1);}catch(e){if(!["EROFS","EACCES"].includes(e.code))throw e;}'
 node "$root_dir/scripts/state-storage.mjs" --agent host-operator check "$runtime" 67108864
done
[[ "$(stat -c %d:%i "$recovery")" == "$recovery_id" ]]
[[ "$(cat "$home/.cache/f2-marker")" == fixture ]]
echo 'recovery content' > "$recovery/foreign"
if bash "$root_dir/scripts/preflight.sh" --agent host-operator "$scratch/fixture.env" > "$scratch/recovery-negative.log" 2>&1;then echo 'nonempty recovery directory accepted' >&2;exit 1;fi
# Deliberately created fixture content only; production never deletes recovery data.
rm "$recovery/foreign"
snapshot > "$scratch/after";cmp "$scratch/before" "$scratch/after"
echo 'Disposable fourth-only provisioning/ext4/lost+found/startup PASS (no live identity/ACP/Executor acceptance)'
