#!/usr/bin/env bash
# Offline dispatch fixtures only. Doubles below are NOT cryptographic/relay/auth acceptance.
set -euo pipefail
umask 077
[[ "$(id -u):$(id -g)" == 10001:10001 ]] || { echo 'Identity source fixture requires unprivileged10001:10001; no UID skip counted as PASS.' >&2; exit 1; }
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d)"
bin_dir="$(mktemp -d "${TEST_EXECUTABLE_TMPDIR:-/tmp}/host-identity-bin.XXXXXX")"
trap 'rm -rf "$scratch" "$bin_dir"' EXIT
mkdir -p "$bin_dir" "$scratch/runtime/host-operator/credentials" "$scratch/run"
chmod 0755 "$scratch/runtime/host-operator"
# Only dummy sentinels are ever read by these controlled local command doubles.
node --input-type=module - "$scratch" <<'JS'
import fs from'node:fs';const root=process.argv[2],owner='a'.repeat(64);
for(const [role,key]of[['dispatcher-planner','1'],['developer-a','2'],['reviewer-a','3'],['host-operator','4']]){
 const d=root+'/runtime/'+role+'/credentials';fs.mkdirSync(d,{recursive:true,mode:0o700});fs.chmodSync(d,0o700);
 fs.writeFileSync(d+'/buzz-private-key','fixture-'+key,{mode:0o600});fs.writeFileSync(d+'/buzz-auth-tag',JSON.stringify(['auth',owner,'','0'.repeat(128)]),{mode:0o600});}
fs.writeFileSync(root+'/owner','fixture-owner',{mode:0o600});
JS
cat > "$bin_dir/docker" <<'JS'
#!/usr/bin/env node
import fs from'node:fs';const args=process.argv.slice(2);fs.appendFileSync(process.env.FIXTURE_CALLS,args[0]+' '+args.slice(1,3).join(' ')+'\n');
if(args[0]==='image'){console.log('c8f73213089cbd5a0f1e675d3193558280d46e10');process.exit(0);}
if(args[0]!=='run')process.exit(91);
const mounts=args.flatMap((x,i)=>x==='--mount'?[args[i+1]]:[]);const source=mounts.map(m=>/src=([^,]+)/.exec(m)?.[1]).find(Boolean);
const ep=args[args.indexOf('--entrypoint')+1];
if(ep==='cat'){process.stdout.write(fs.readFileSync(source));process.exit(0);}
if(ep==='sh'){
 const literal=args.at(-1);
 if(literal.includes('test -f "/run/agent/credentials/')){const n=args.find(x=>x.startsWith('CREDENTIAL_FILENAME=')).split('=')[1];process.exit(fs.existsSync(source+'/'+n)?0:1);}
 if(literal.includes('test ! -L /run/agent/credentials')){
  for(const n of fs.readdirSync(source)){const s=fs.lstatSync(source+'/'+n);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||(s.mode&0o777)!==0o600)process.exit(1);}process.exit(0);
 }
}
process.exit(92);
JS
cat > "$bin_dir/nak" <<'JS'
#!/usr/bin/env node
import fs from'node:fs';const args=process.argv.slice(2);fs.appendFileSync(process.env.FIXTURE_CALLS,'nak '+args[0]+'\n');
if(args[0]==='key'){const text=fs.readFileSync(0,'utf8');console.log(text==='fixture-owner'?'a'.repeat(64):(process.env.FORCE_FIXTURE_PUBKEY??text.slice(-1).repeat(64)));process.exit(0);}
if(args[0]==='req'){
 const kind=Number(args[args.indexOf('--kind')+1]);let pubkey=args[args.indexOf('--author')+1],key=kind===0?pubkey:args[args.indexOf('--tag')+1].slice(2);const name=({'1':'Dispatcher Planner','2':'Developer A','3':'Reviewer A','4':'Host Operator'})[key[0]];
 console.log(JSON.stringify({id:'0'.repeat(64),created_at:1,kind,pubkey,tags:kind===0?[['auth','a'.repeat(64),'','0'.repeat(128)]]:[['d',key]],content:JSON.stringify(kind===0?{display_name:name}:{name,parallelism:1,respond_to:'owner-only'})}));process.exit(0);
}
process.exit(93); // Any signing/publication request is a failed verify-only fixture.
JS
chmod 0755 "$bin_dir/docker" "$bin_dir/nak"
cat > "$scratch/fixture.env" <<EOF
AGENT_RUNTIME_ROOT=$scratch/runtime
BUZZ_RELAY_URL=wss://fixture.invalid
BUZZ_AGENT_OWNER_HEX=$(printf 'a%.0s' {1..64})
BUZZ_OWNER_PRIVATE_KEY_FILE=$scratch/owner
BUZZ_NAK_BIN=$bin_dir/nak
HOST_OPERATOR_EXISTING_BUZZ_PUBKEYS=$(printf '1%.0s' {1..64}),$(printf '2%.0s' {1..64}),$(printf '3%.0s' {1..64})
HOST_OPERATOR_BUZZ_PUBKEY=$(printf '4%.0s' {1..64})
DISPATCHER_CREDENTIALS_DIR=$scratch/runtime/dispatcher-planner/credentials
DEVELOPER_CREDENTIALS_DIR=$scratch/runtime/developer-a/credentials
REVIEWER_CREDENTIALS_DIR=$scratch/runtime/reviewer-a/credentials
EOF
export PATH="$bin_dir:$PATH" FIXTURE_CALLS="$scratch/calls" XDG_RUNTIME_DIR="$scratch/run" AGENT_ENV_FILE="$scratch/fixture.env"
: > "$FIXTURE_CALLS"
# validate-host-layout insists on real 10001 ownership; caller in source image is10001.
if [[ "$(id -u):$(id -g)" == 10001:10001 ]]; then
  before="$(sha256sum "$scratch/runtime/host-operator/credentials/buzz-auth-tag")"
  bash "$root_dir/scripts/provision-buzz-agent-identity.sh" --verify-only --agent host-operator > "$scratch/output" 2>&1 || { cat "$scratch/output"; exit 1; }
  [[ "$(sha256sum "$scratch/runtime/host-operator/credentials/buzz-auth-tag")" == "$before" ]]
  grep -q 'Verified 1' "$scratch/output"
  if FORCE_FIXTURE_PUBKEY="$(printf '1%.0s' {1..64})" bash "$root_dir/scripts/provision-buzz-agent-identity.sh" --verify-only --agent host-operator > "$scratch/negative" 2>&1; then echo 'Copied identity accepted' >&2; exit 1; fi
fi
# Existing default still chooses three, even with fourth public settings present.
bash "$root_dir/scripts/provision-buzz-agent-identity.sh" --verify-only > "$scratch/default" 2>&1
grep -q 'Verified 3' "$scratch/default"
for args in 'host-operator' '--agent developer-a' '--agent host-operator reviewer-a' '--agent host-operator --agent host-operator'; do
  read -ra words <<< "$args"
  if bash "$root_dir/scripts/provision-buzz-agent-identity.sh" "${words[@]}" > "$scratch/negative" 2>&1; then echo 'Mixed/implicit selector accepted' >&2; exit 1; fi
done
if grep -Eq 'fixture-owner|fixture-[1234]' "$scratch/output" "$scratch/default" "$scratch/negative" 2>/dev/null; then echo 'Fixture secret leaked' >&2; exit 1; fi
if grep -q 'nak event\|build' "$FIXTURE_CALLS"; then echo 'verify-only attempted publication' >&2; exit 1; fi
echo 'Offline identity dispatch/verify-only fixtures PASS (synthetic; no live auth/cryptographic acceptance)'
