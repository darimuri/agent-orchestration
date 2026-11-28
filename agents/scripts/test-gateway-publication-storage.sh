#!/usr/bin/env bash
# Reviewed disposable host acceptance ONLY. No credentials, network or remote writes.
set -euo pipefail
umask 077
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Run the offline API contract before any privilege or host mutation checks.
node --test "$root_dir/scripts/gateway-publication-fixture-api.test.mjs"
(( EUID == 0 )) || { echo 'Requires trusted disposable root host' >&2; exit 1; }
[[ $# -le 1 ]] || exit 1
for tool in node docker findmnt losetup mount umount fallocate mkfs.ext4 stat sha256sum; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done
image="${1:-local/github-app-agent-gateway:e50a4ad}"
docker image inspect "$image" --format '{{.Id}} {{.Config.User}} {{.Config.WorkingDir}}'
scratch="$(mktemp -d /tmp/gateway-publication-test.XXXXXXXX)"
export AGENT_RUNTIME_ROOT="$scratch/runtime"
export GITHUB_GATEWAY_RUNTIME_DIR="$AGENT_RUNTIME_ROOT/github-gateway"
export GITHUB_GATEWAY_CREDENTIALS_ROOT="$scratch/credentials"
export GITHUB_GATEWAY_PUBLICATION_RECORDS_DIR="$AGENT_RUNTIME_ROOT/publication-storage/records"
export GITHUB_GATEWAY_PUBLICATION_RECORDS_BYTES=67108864
for role in DISPATCHER DEVELOPER REVIEWER; do
  export "${role}_WORKSPACE=$AGENT_RUNTIME_ROOT/${role,,}/workspace"
  export "${role}_CREDENTIALS_DIR=$AGENT_RUNTIME_ROOT/${role,,}/credentials"
done
helper="$root_dir/scripts/gateway-publication-storage.mjs"
store="$AGENT_RUNTIME_ROOT/publication-storage"; target="$store/records"
container="gateway-publication-$(basename "$scratch" | tr '[:upper:].' '[:lower:]-')"
cleanup(){
 local code=$?;trap - EXIT
 if (( code != 0 ));then echo "FAILED; preserve fixture and container for review: $scratch $container" >&2;exit "$code";fi
 docker rm -f "$container" >/dev/null 2>&1 || true
 if ! node "$helper" unmount; then echo "Cleanup blocked; preserve $scratch" >&2;exit 1;fi
 # Helper verified the exact image mapping is detached; no recursive deletion on failure.
 rm -rf -- "$scratch"
}
trap cleanup EXIT
mkdir "$AGENT_RUNTIME_ROOT"
reject(){ if "$@" >"$scratch/negative.log" 2>&1;then echo "Unexpected acceptance: $*" >&2;exit 1;fi; }
reject node "$helper" check
# Disposable-fixture-only reset after an expected failed mutation. Never remove a preexisting lock.
reject_prepare(){
 [[ ! -e "$store/.provision.lock" ]] || return 1
 reject node "$helper" prepare
 [[ -f "$store/.provision.lock" ]] || return 1
 rm -- "$store/.provision.lock"
}
node "$helper" prepare
identity="$(stat -c %d:%i "$store/records.img")"
node "$helper" prepare
node "$helper" check
[[ "$(stat -c %d:%i "$store/records.img")" == "$identity" ]]
# Retain EVERY record kind and compare bytes/inodes through prepare/check/remount/restart.
for kind in pending commit pull-pending pull staged ambiguous;do
 printf 'retained fixture %s\n' "$kind" > "$target/fixture.$kind"
 chown 1000:1000 "$target/fixture.$kind";chmod 0600 "$target/fixture.$kind"
done
snapshot(){ for kind in pending commit pull-pending pull staged ambiguous;do stat -c '%i:%u:%g:%a:%s' "$target/fixture.$kind";sha256sum "$target/fixture.$kind";done; }
snapshot > "$scratch/before"
node "$helper" prepare;node "$helper" check
snapshot > "$scratch/after";cmp "$scratch/before" "$scratch/after"
# Negative existing state is never repaired by prepare/check.
chmod 02700 "$target";reject node "$helper" check;reject_prepare
[[ "$(stat -c %a "$target")" == 2700 ]];chmod 0700 "$target"
chown 1000:1001 "$target";reject node "$helper" check;chown 1000:1000 "$target"
ln "$store/records.img" "$store/hardlink";reject_prepare;rm "$store/hardlink"
GITHUB_GATEWAY_PUBLICATION_RECORDS_BYTES=134217728 reject_prepare
: > "$store/records.img.creating";reject_prepare;rm "$store/records.img.creating"
: > "$store/.provision.lock";reject node "$helper" prepare;reject node "$helper" check;rm "$store/.provision.lock"
# A competing process holding exclusive creation prevents a second prepare.
(node -e 'const fs=require("fs");fs.writeFileSync(process.argv[1],"",{flag:"wx",mode:384});process.send?.("held");setTimeout(()=>fs.unlinkSync(process.argv[1]),1500)' "$store/.provision.lock") &
locker=$!
for ((i=0;i<100;i++));do [[ -e "$store/.provision.lock" ]] && break;sleep .01;done
reject node "$helper" prepare;wait "$locker"
# Force Guard loading in the pinned image; no application/network/publication writes.
probe=(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000
 --mount "type=bind,src=$target,dst=/run/gateway-publications"
 --mount "type=bind,src=$root_dir/scripts/gateway-publication-startup-guard.mjs,dst=/run/gateway-publication-guard.mjs,readonly"
 -e GATEWAY_PUBLICATION_STARTUP_GUARD=1 -e GATEWAY_PUBLICATION_RECORDS_DIRECTORY=/run/gateway-publications
 -e GATEWAY_PUBLICATION_CAPACITY_BYTES=67108864 -e NODE_OPTIONS=--import=/run/gateway-publication-guard.mjs
 --entrypoint node "$image")
"${probe[@]}" --input-type=module -e '
import fs from "node:fs";const p="/run/gateway-publications/uid1000-fsync";
const fd=fs.openSync(p,"wx",0o600);fs.writeFileSync(fd,"durable");fs.fsyncSync(fd);fs.closeSync(fd);
const d=fs.openSync("/run/gateway-publications","r");fs.fsyncSync(d);fs.closeSync(d);'
# Actual pinned publication-record API exercises pending/commit/pull receipt durability offline.
"${probe[@]}" --input-type=module -e '
import assert from "node:assert/strict";
const {PublicationRecords}=await import("./dist/publication-records.js");
const s=new PublicationRecords("/run/gateway-publications");
const c={agentId:"fixture",jobId:"fixture",repository:"fixture/repository",branch:"fixture",baseRef:"main",baseSha:"1".repeat(40)};
const t=s.reserve(c,1,"2".repeat(40));s.recordCommit(t,"3".repeat(40));assert.equal(s.load(c).commitSha,"3".repeat(40));
const p=s.reservePull(c);s.recordPull(p,1);assert.equal(s.pull(c),1);assert.throws(()=>s.reserve(c,1,"2".repeat(40)));'
read_receipt(){
 "${probe[@]}" --input-type=module -e '
import assert from "node:assert/strict";
const {PublicationRecords}=await import("./dist/publication-records.js");
const s=new PublicationRecords("/run/gateway-publications"),c={agentId:"fixture",jobId:"fixture",repository:"fixture/repository",branch:"fixture",baseRef:"main",baseSha:"1".repeat(40)};
assert.equal(s.load(c).commitSha,"3".repeat(40));assert.equal(s.pull(c),1);assert.throws(()=>s.reserve(c,1,"2".repeat(40)));'
}
read_receipt
# Real restart/recreation of a disposable process; no live service is touched.
docker create --name "$container" --network none --read-only --cap-drop ALL --user 1000:1000 \
 --mount "type=bind,src=$target,dst=/run/gateway-publications" \
 --mount "type=bind,src=$root_dir/scripts/gateway-publication-startup-guard.mjs,dst=/run/gateway-publication-guard.mjs,readonly" \
 -e GATEWAY_PUBLICATION_STARTUP_GUARD=1 -e GATEWAY_PUBLICATION_RECORDS_DIRECTORY=/run/gateway-publications \
 -e GATEWAY_PUBLICATION_CAPACITY_BYTES=67108864 -e NODE_OPTIONS=--import=/run/gateway-publication-guard.mjs \
 --entrypoint node "$image" -e 'require("fs").readFileSync("/run/gateway-publications/uid1000-fsync")' >/dev/null
for i in 1 2;do docker start -a "$container";[[ "$(docker inspect --format '{{.State.ExitCode}}' "$container")" == 0 ]];done
node "$helper" unmount
[[ "$(stat -c %u:%g:%a "$target")" == 0:0:0 ]]
reject node "$helper" check
# Simulates boot automatic restart: existing stopped container binds unmounted source.
docker start -a "$container" || true
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$container")" != 0 ]]
reject "${probe[@]}" -e 'process.exit(0)'
# Ordinary UID1000 directory must fail the filesystem/mount guard too.
chmod 0700 "$target";chown 1000:1000 "$target"
reject "${probe[@]}" -e 'process.exit(0)'
reject_prepare
chown 0:0 "$target";chmod 000 "$target"
node "$helper" prepare
read_receipt
snapshot > "$scratch/after";cmp "$scratch/before" "$scratch/after"
[[ "$(stat -c %d:%i "$store/records.img")" == "$identity" ]]
# Exhaust blocks then inodes INSIDE ONLY this disposable store; existing records survive.
"${probe[@]}" -e '
const fs=require("fs"),d="/run/gateway-publications/";let fd=fs.openSync(d+"block-fill","wx",384),ok=false;
try{for(;;)fs.writeSync(fd,Buffer.alloc(65536));}catch(e){if(e.code!=="ENOSPC")throw e;ok=true;}finally{fs.closeSync(fd);}if(!ok)process.exit(1);'
snapshot > "$scratch/after";cmp "$scratch/before" "$scratch/after"
read_receipt
# Removing test-generated fill data is fixture-only, never journal pruning.
rm "$target/block-fill"
"${probe[@]}" -e '
const fs=require("fs"),d="/run/gateway-publications/";let n=0;
try{for(;;)fs.closeSync(fs.openSync(d+"inode-fill-"+n++,"wx",384));}catch(e){if(e.code!=="ENOSPC")throw e;}
if(fs.statfsSync(d).ffree!==0)throw Error("inode exhaustion not established");'
snapshot > "$scratch/after";cmp "$scratch/before" "$scratch/after"
read_receipt
# No remote publication operations occur: every container has --network none.
echo 'Disposable storage persistence/startup/UID1000/fsync/retention/ENOSPC PASS; zero network publication calls'
