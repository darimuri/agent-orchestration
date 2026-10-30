#!/usr/bin/env bash
# Explicit disposable ROOT+Docker/ext4 acceptance only. Never target live runtime.
set -euo pipefail
umask 077
(( EUID == 0 )) || { echo 'requires trusted disposable root host' >&2; exit 1; }
[[ $# == 1 && "$1" != -* ]] || { echo 'supply isolated test Codex image tag/digest' >&2; exit 1; }
for tool in docker node git flock findmnt losetup mkfs.ext4 fallocate mount umount sudo id stat install; do command -v "$tool" >/dev/null || { echo 'host fixture prerequisite missing' >&2; exit 1; }; done
# An isolated nonroot fixture account must have existing noninteractive sudo.
: "${HOST_OPERATOR_TEST_HOST_USER:?supply disposable nonroot fixture account}"
[[ "$HOST_OPERATOR_TEST_HOST_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || exit 1
host_uid="$(id -u "$HOST_OPERATOR_TEST_HOST_USER")";host_gid="$(id -g "$HOST_OPERATOR_TEST_HOST_USER")"
(( host_uid != 0 )) || { echo 'fixture host account must be nonroot' >&2;exit 1; }
sudo -n -u "$HOST_OPERATOR_TEST_HOST_USER" sudo -n true
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
mkdir -p "$runtime" "$scratch/run" "$scratch/host-home";chmod 0755 "$scratch" "$runtime"
chown "$host_uid:$host_gid" "$scratch/run" "$scratch/host-home"
cp "$root_dir/git-identities.example.json" "$scratch/legacy.json"
cp "$root_dir/host-operator-git-identity.example.json" "$scratch/host.json"
# These empty disposable role bases are public metadata; sentinel contents stay private.
for role in dispatcher-planner developer-a reviewer-a github-gateway; do
 install -d -m 0755 -o 0 -g 0 "$runtime/$role"
 [[ "$(stat -c %u:%g:%a "$runtime/$role")" == 0:0:755 ]]
 echo 'old fixture sentinel' > "$runtime/$role/sentinel"
done
snapshot(){
 stat -c '%n:%u:%g:%a' "$runtime/dispatcher-planner" "$runtime/developer-a" "$runtime/reviewer-a" "$runtime/github-gateway"
 find "$runtime/dispatcher-planner" "$runtime/developer-a" "$runtime/reviewer-a" "$runtime/github-gateway" -type f -exec sha256sum {} + | sort; }
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
DEVELOPER_CREDENTIALS_DIR=$runtime/developer-a/private
GITHUB_GATEWAY_CREDENTIALS_ROOT=$runtime/github-gateway/private
EOF
chmod 0644 "$scratch/fixture.env" "$scratch/legacy.json" "$scratch/host.json"
as_host(){ sudo -n -u "$HOST_OPERATOR_TEST_HOST_USER" env -i PATH="$PATH" HOME="$scratch/host-home" bash "$@"; }
# No Gateway variables; default legacy invocation fails rather than touching fourth.
if PROVISION_RUNTIME_TEST_MODE=1 bash "$root_dir/scripts/provision-runtime.sh" "$scratch/fixture.env" > "$scratch/default.log" 2>&1; then echo 'legacy default unexpectedly accepted missing Gateway' >&2;exit 1;fi
[[ ! -e "$runtime/host-operator" ]]
# Repeated explicit provisioning under the fixture's umask0077 must preserve modes/inodes.
for i in 1 2; do
 as_host -c 'umask 077; exec bash "$@"' fixture "$root_dir/scripts/provision-runtime.sh" --agent host-operator "$scratch/fixture.env"
 [[ -f "$scratch/run/provision.lock" && ! -L "$scratch/run/provision.lock" ]]
 [[ "$(stat -c %u:%g:%a:%h "$scratch/run/provision.lock")" == "$host_uid:$host_gid:600:1" ]]
 [[ "$(stat -c %u:%g:%a "$runtime/host-operator")" == 10001:10001:755 ]]
 [[ "$(stat -c %u:%g:%a "$runtime/host-operator/credentials")" == 10001:10001:700 ]]
 [[ "$(stat -c %u:%g:%a "$runtime/host-operator/workspace")" == 10001:10001:755 ]]
 layout_ids="$(stat -c %d:%i "$runtime/host-operator" "$runtime/host-operator/credentials" "$runtime/host-operator/workspace")"
 if [[ "$i" == 1 ]]; then first_layout_ids="$layout_ids";else [[ "$layout_ids" == "$first_layout_ids" ]];fi
done
[[ ! -e "$runtime/host-operator/credentials/github-gateway-agent-token" ]]
source_repo="$scratch/sources/fixture-org/example.git";mkdir -p "$source_repo"
git -C "$source_repo" init -q --initial-branch=main
git -C "$source_repo" -c user.name=fixture -c user.email=fixture@example.test commit -q --allow-empty -m fixture
# State-first ordering reproduces the private-store boundary from G3.
node "$root_dir/scripts/state-storage.mjs" --agent host-operator prepare "$runtime" 67108864
mounted=true
[[ "$(stat -c %u:%g:%a "$runtime/state-storage")" == 0:0:700 ]]
# Public offline source only; no credential or private state permissions changed.
chown -R "$host_uid:$host_gid" "$scratch/sources"
chmod -R a+rX "$scratch/sources"
if as_host -c 'node "$1" validate-host-layout "$2"' fixture "$root_dir/docker/git-identity.mjs" "$runtime" > "$scratch/full-negative.log" 2>&1;then echo 'nonroot full validator unexpectedly traversed private state' >&2;exit 1;fi
as_host -c 'node "$1" validate-host-repository-layout "$2"' fixture "$root_dir/docker/git-identity.mjs" "$runtime"
state_snapshot(){
 stat -c '%d:%i:%u:%g:%a:%s' "$runtime/state-storage" "$runtime/state-storage/host-operator.img" "$runtime/state-storage/host-operator"
 findmnt -n -o SOURCE,FSTYPE,OPTIONS --target "$runtime/state-storage/host-operator"
 find "$runtime/state-storage/host-operator" -xdev -printf '%P:%y:%i:%u:%g:%m:%s\n' | sort
 find "$runtime/state-storage/host-operator" -xdev -type f -exec sha256sum {} + | sort
}
state_snapshot > "$scratch/state-before"
# Root denial remains before any TTY/device/auth operation.
if bash "$root_dir/scripts/provision-kaneo-credential.sh" --agent host-operator "$scratch/fixture.env" > "$scratch/kaneo-root-denial" 2>&1;then echo 'Kaneo root invocation accepted' >&2;exit 1;fi
grep -q 'run as the host user' "$scratch/kaneo-root-denial"
# Placement and unchanged privileged credential checks after real private state exists.
for i in 1 2; do
 as_host -c 'node "$1/docker/git-identity.mjs" validate-host-credential-layout "$2" && sudo node "$1/docker/git-identity.mjs" check-host "$3" "$4" "$2/host-operator/credentials"' fixture "$root_dir" "$runtime" "$scratch/host.json" "$scratch/legacy.json"
 state_snapshot > "$scratch/state-credential-after";cmp "$scratch/state-before" "$scratch/state-credential-after"
done
for i in 1 2; do
 as_host "$root_dir/scripts/provision-agent-repository.sh" --agent host-operator fixture-org/example main "$scratch/fixture.env"
 [[ "$(stat -c %u:%g:%a:%h "$scratch/run/provision.lock")" == "$host_uid:$host_gid:600:1" ]]
 dest="$runtime/host-operator/workspace/fixture-org/example"
 clone_snapshot="$(stat -c %d:%i "$dest" "$dest/.git");$(git -c safe.directory="$dest" -C "$dest" rev-parse HEAD);$(git -c safe.directory="$dest" -C "$dest" remote get-url origin)"
 if [[ "$i" == 1 ]];then first_clone_snapshot="$clone_snapshot";else [[ "$first_clone_snapshot" == "$clone_snapshot" ]];fi
 [[ ! -e "$dest/.git/objects/info/alternates" ]]
 [[ -z "$(find "$dest/.git" -type f -links +1 -print -quit)" ]]
 state_snapshot > "$scratch/state-after";cmp "$scratch/state-before" "$scratch/state-after"
done
[[ ! -e "$runtime/developer-a/workspace" ]]
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
