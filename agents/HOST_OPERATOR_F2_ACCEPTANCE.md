# F2 owner-run identity/ACP acceptance (not execution authorization)

F2 source supports explicit fourth provisioning. A merged/source-reviewed PR does not
approve any command in this runbook. The owner must first approve the exact source
HEAD/tree, isolated runtime image digest/project/env/override paths, public identity
mapping, channel, fixture task, non-owner test account and observation window. No live
row below is fulfilled by source tests. F3 IPC, AGE #7 H1–H9, issue #21, human approval
and merge remain separate. The fourth stays disconnected from an Executor.

Record only SHA/tree/image digest, public pubkeys/actor/comment/message IDs, booleans,
counts and fixed redacted errors. Never post auth files/hashes, raw env/config/inspect,
owner keys, one-time device codes, credential URLs, tokens, auth tags or private logs.
The owner privately reviews operational output before recording public evidence.

## Prerequisites and fixed paths

Use Linux with separately approved root loop/ext4 tools, Git, Node, jq, flock, sudo,
Docker/Compose (including real2.40.3 normalization coverage), compiler/sanitizers and
offline dependencies where validation requires them. Source gate failures remain
unmet checks. No runtime/package/Gateway policy change is implied.

Let F2_ENV be an external trusted shell env; F2_ROOT its canonical AGENT_RUNTIME_ROOT.
It must not alias/nest old credentials/workspaces, the checkout, protected host paths
or state/credential roots. Fourth paths are fixed under F2_ROOT:

- host-operator/credentials:10001:10001/0700, ordinary single-link files0600.
- host-operator/workspace:10001:10001/0755, independently cloned and mounted RO.
- state-storage/host-operator.img and its bounded ext4 target, no unbounded fallback.

Required public inputs: external HOST_OPERATOR_GIT_IDENTITY_MANIFEST (one fourth record),
legacy AGENT_GIT_IDENTITY_MANIFEST (exactly three approved records),
HOST_OPERATOR_EXISTING_BUZZ_PUBKEYS (exactly three comma-separated distinct lowercase
hex public keys in Dispatcher/Developer/Reviewer order), HOST_OPERATOR_BUZZ_PUBKEY
(new fourth public key after owner generation), HOST_OPERATOR_KANEO_USER_ID (dedicated
approved actor), owner public key, approved endpoints and storage bytes.
Never supply a fourth Gateway token/App, GH/SSH credential, socket or host-private ledger.

Owner records old-three container/image IDs and public identities plus private backup
references and baseline path/state comparisons. Existing third-role/Gateway credentials
must not be rotated/read for public evidence. Unknown fourth objects or conflicts stop
acceptance; preserve them rather than recursively fixing ownership or overwriting identity.

## Prepare only the fourth (after separate owner approval)

From repository root, with public mappings and trusted external env prepared:

```bash
bash agents/scripts/provision-runtime.sh --agent host-operator "$F2_ENV"
sudo node agents/scripts/state-storage.mjs --agent host-operator prepare "$F2_ROOT" 536870912
sudo node agents/scripts/state-storage.mjs --agent host-operator check "$F2_ROOT" 536870912
bash agents/scripts/provision-agent-repository.sh --agent host-operator darimuri/agent-orchestration main "$F2_ENV"
```

Runtime preparation creates only fourth layout/Git identity, not auth/state/Gateway.
No-argument/default provisioners still select exactly three, even with fourth variables
or COMPOSE_PROFILES set. Never select a mixed list or wildcard. Verify actual repo SHA
and canonical origin independently; a branch name alone is not an immutable binding.
Existing clones are preserved, not fetched/reset. Runtime workspace remains RO.

State operations use the root-owned private store/exclusive lock and exact existing
image/loop/size checks. Stop the fourth before prepare/remount/unmount; verify no users
remain and boot ordering mounts bounded HOME before startup. No fstab/service or old
image migration is installed. A partial .creating file/orphan lock is manual inspection,
not automatic retry. Normal root-owned0700 empty lost+found stays untouched; nonempty,
wrong-owner/mode/type/link metadata blocks acceptance. Do not chown or delete it.

## Separate Buzz, Kaneo and Codex custody

Owner generates a NEW Nostr key with the existing pinned nak procedure in a private
temporary file and installs only fourth buzz-private-key0600. Do not copy old role keys.
Record its public key after checking it differs from owner and the approved three-key
roster. Set the expected public mapping in the external env. The provisioner expects
an installed key; it never creates/replaces one or grants relay/channel membership.

```bash
AGENT_ENV_FILE="$F2_ENV" bash agents/scripts/provision-buzz-agent-identity.sh --agent host-operator
AGENT_ENV_FILE="$F2_ENV" bash agents/scripts/provision-buzz-agent-identity.sh --verify-only --agent host-operator
```

The first operation uses the existing owner-authenticated signing flow; only the owner
runs it. Validate public name Host Operator, profile owner attestation and signed30177
parallelism1/respond_to owner-only. Verify-only publishes/writes no identity state.
Owner separately registers the fourth relay member and adds it as bot to the approved
channel through the supported Buzz membership command. No owner/relay-admin key enters
the long-lived LLM container. Names alone do not authenticate identity or assignment.

For Kaneo, owner logs into a dedicated host-operator account with minimum approved
fixture task read/comment scope and runs:

```bash
bash agents/scripts/provision-kaneo-credential.sh --agent host-operator "$F2_ENV"
```

This installs a separate device session, not an account or workspace role. Browser/device
approval is owner-side. Do not call whoami: the proxy blocks it for token-exposure risk.
Independently verify actual comment author against HOST_OPERATOR_KANEO_USER_ID during
live acceptance below. If a distinct actor cannot be supplied, stop for owner decision;
a second session for the same human is not a distinct actor. --replace is a separate
explicit fourth maintenance/revocation approval, never a retry or default rotation.

For Codex, use an independently authenticated private fourth host CODEX_HOME, never a
copy of another role's login or host config. Inspect the pinned0.163.0 binary's
`codex login --help` before choosing supported device/file-cache options. A private
profile directory is a custody label, not a runtime --profile or custom config.toml.
After owner browser/device authorization (for example supported `login --device-auth`),
install ONLY its auth.json into fourth credentials/codex-auth.json as10001:10001/0600.
Alternatively choose an explicitly owner-issued fourth-only API key mode. Prefer one
mode in acceptance so fallback cannot conceal a broken login. Do not copy host config,
AGENTS/hooks/session DB or set CODEX_PATH/provider environment overrides. Actual ACP
turn/model entitlement is required; CLI help/models/version is insufficient.

The generic loader recopies credential-side codex-auth.json on EVERY startup. Before
restart/recreation after provider refresh, stop ONLY fourth and checkpoint its updated
ordinary private HOME auth to its OWN private profile/mounted credential through
owner-reviewed fixed paths, or reauthenticate ONLY that session. Confirm ownership and
identity privately without printing contents. Never copy config/session DB back or claim
stale mounted auth survives rotation indefinitely. No external keeper/check/refresh
script exists here; changes to external host scripts need separate scope.

## Selected preflight and start only the reviewed fourth

```bash
sudo bash agents/scripts/preflight.sh --agent host-operator "$F2_ENV"
bash agents/scripts/test-resource-config.sh
```

Preflight checks fourth manifests, public mapping, private ordinary files, workspace
metadata, exact selected storage image/mount and recovery-directory emptiness. It does
not prove network account identity, model entitlement or live ACP behavior. A future
private Compose override may change ONLY the fourth image to the reviewed isolated tag.
Render privately and validate the unchanged F1 resource policy; retain RO workspace,
credentials, no Gateway dependency/token and no host authority. No secrets dump.

Define C as owner-reviewed argv: docker compose --env-file "$F2_ENV" -f agents/compose.yaml
-f <private-image-only-override> --profile host-operator. Use the same approved project.
After authorization, C up -d --no-deps --no-build --pull never host-operator starts ONLY
fourth. No global profile change, Compose down, remove-orphans or old-three recreation.
Confirm process path buzz-acp -> codex-acp, configured allowed model and Kaneo-only MCP
catalog privately; no Gateway/Executor MCP, socket, cgroups, private ledger or extra caps.

## Required live acceptance evidence

1. Four public Buzz keys pairwise distinct and distinct from owner; profile/tag/policy,
   relay membership and channel bot mapping verified by owner. Verify-only repeat has
   no publication/state change. Wrong/duplicate roster or expected key denies before
   signing/writing/publishing; fixture evidence is not cryptographic acceptance.
2. Owner sends a fresh nonce with explicit fourth pubkey mention in the approved channel
   and root. Instruct one nonce reply, disconnected status, read of the approved fixture
   task and one approved nonce comment, with no extra mentions/tool mutations. Verify
   exactly one signed response from fourth pubkey at the same channel/root and exact
   nonce. An actual LLM turn must succeed with the configured model.
3. Owner independently reads the fixture task/comment and confirms exact commentId,
   taskId/nonce/author equals HOST_OPERATOR_KANEO_USER_ID. No task deletion/membership
   mutation; no whoami. Device session separation alone does not satisfy this row.
4. An already-approved non-owner account in the channel sends a DIFFERENT benign nonce
   mention. In an owner-agreed bounded window (recommended120s), capture inbound event,
   runtime no-admission/no-dispatch evidence and no response. Silence alone is not a
   global guarantee. Then owner positive control must succeed. Unexpected admission
   stops acceptance; never silently change owner policy or attempt host execution.
5. RO workspace and dummy credential bind reject writes; private HOME marker persists.
   Test writes on fixture credentials, never overwrite live secret files. No broad
   host mounts, GH/SSH/Gateway/Executor credentials or runtime environment overrides.
6. Same fourth HOME second disposable guard process/container exits75 before generic
   credential loading; first listener survives. Do not start a second live listener in
   another HOME. Lock file stays; no stale lock deletion. This is cooperative per-HOME
   exclusion, not hostile same-UID or distributed same-key leasing.
7. After fourth-only auth checkpoint if needed, restart ONLY fourth and repeat a fresh
   owner nonce. Recreate ONLY fourth with the exact image/HOME and repeat. Same public
   key/owner mapping, marker and intended credential custody persist; exactly one reply.
   ACP conversation ID reuse is not required; identity/state persistence is.
8. Compare old-three IDs/images/public keys/private baselines; no restart, rewrite,
   credential/session rotation, Gateway mutation or state unmount occurred. Record only
   approved public booleans, not private files or hashes.
9. Source/review, real ext4 startup, identity, ACP, tool actor, negative admission and
   restart/separation rows must all pass independently before F2 live acceptance.
   F2 does not complete overall AGE13/F3 or AGE #7 H1–H9.

## Validation and rollback

At exact committed head: full Node suite, test-resource-config.sh, github-apps/test-create-apps.sh,
unchanged pinned integration/native/Gateway harness, offline identity dispatch fixture,
legacy test-provision-runtime.sh and separately approved real-root/Docker
`test-host-operator-provisioning.sh <isolated-test-Codex-image>`, test-workspace-mounts.sh,
test-resource-limits.sh and build-and-smoke.sh. Scope PROVISION_RUNTIME_TEST_MODE=1 only to
disposable runtime fixture invocations; no production bypass. No skipped native/root/
Docker gate presented as PASS. Preserve executable bits; Gateway mode limitations require
owner-reviewed concrete publication, not new credentials/ref/job or policy changes.

Rollback: C stop host-operator, verify its entire ACP tree ended and lock released.
Preserve fourth HOME/key/profiles/sessions and private backups. Container removal, if
separately approved, is C rm -f host-operator only after stop; never down/--volumes.
Optionally selected unmount only after all users stop, preserving image/recovery data.
Restore only explicitly backed-up fourth config/auth; avoid rolling back refreshed OAuth
cache blindly, reauthenticate that session if needed. Session revocation/membership
removal is a separate owner choice. Never delete AGE #7 claims/proofs/journal, renew
pending intents, repair UNKNOWN or reset old-three identities/tokens/images. Source
rollback is an independently reviewed revert with profile off.
