# Host-only workspace requests (AGE #5)

`workspace-provisioner.mjs` adds an owner-mediated request adapter. It reuses the
manual provisioner's independent `--no-hardlinks` clone flow through
`scripts/repository-clone.sh` and applies the runtime provisioner's canonical,
protected and disjoint-root rules with additional ownership/symlink checks. It does
not run `provision-runtime.sh`, provision credentials, start containers, or publish
an agent-accessible endpoint. The existing Compose mounts remain authoritative:
Dispatcher/Reviewer read-only, Developer read-write. UID ownership alone does not
establish this policy.

This draft defines a **required host verifier integration**, not a deployed Gateway
endpoint or a replacement job ledger. The supplied Gateway MCP identity/repository
reads do not expose base SHA, expiry and full job state. No production verifier is
included or assumed available. Until an owner connects and validates the existing
Gateway authorization logic, requests fail closed; unattended provisioning is not
ready for use. Do not substitute a static assignment, a fixture verifier, or an
agent-supplied job JSON for live authorization.

## Trusted invocation and configuration

The adapter CLI requires root. `hostUid` selects the trusted administrative host
account (for example UID 1000); UID 10001 is forbidden. Managed path parents may
be owned by root or this host UID, never group/other-writable. Install the reviewed adapter and shared clone helper
on a root-owned filesystem; every source/config/verifier parent must be root-owned,
without group/other write permission or symlinks. Run with a trusted executable PATH,
Node installation and sanitized host environment; never sudo an agent-writable source
checkout. There is no CLI test-mode bypass. Node, Bash, Git and util-linux `flock`
are required. Host authentication uses an existing trusted SSH/askpass setup; raw
credentials must never appear in URLs, request arguments, config or verifier output.
The adapter uses fixed `https://github.com/<owner>/<repository>.git` origins, disables
Git system/global configuration, and retains host askpass environment. Validate the
actual private-repository authentication path separately; this change grants none.

A host operator prepares separate workspace roots, state and lock directories. All
workspace ancestors through `<workspace>/<owner>` must remain **host-owned** (0755
or stricter), while installed clone trees become UID:GID 10001:10001. This prevents
an agent replacing destination parents during publication. Existing agent-owned
workspace roots from the manual runtime provisioner are rejected, never chowned or
adopted. Any migration requires a separate owner-approved host operation. Configure
`lockDirectory` to the SAME `XDG_RUNTIME_DIR` (or host
`$HOME/.cache/darimuri-agent-orchestration`) used by both existing scripts, so all
three use the same persistent `provision.lock` inode. Precreate this regular mode-0600 file
owned by `hostUid`, so the existing host-user scripts can also open it; the root
adapter refuses a missing lock instead of creating an incompatible root-owned file. Do not delete/replace the lock
while provisioners run. State/lock directories must be host-private (0700), durable
local storage with working flock, exclusive creation, rename and directory fsync.

Example root-owned mode-0600 config (paths are illustrative, not provisioned):

```json
{
  "hostUid": 1000,
  "runtimeRoot": "/srv/buzz-workspaces",
  "workspaces": {
    "dispatcher-planner": "/srv/buzz-workspaces/dispatcher",
    "developer-a": "/srv/buzz-workspaces/developer",
    "reviewer-a": "/srv/buzz-workspaces/reviewer"
  },
  "stateDirectory": "/var/lib/buzz-workspace-receipts",
  "lockDirectory": "/var/lib/buzz-provision-locks",
  "verifier": "/usr/local/libexec/buzz-verify-workspace-job",
  "allowedRepositories": ["darimuri/agent-orchestration"],
  "protectedPaths": [
    "/srv/buzz-credentials", "/srv/buzz-gateway",
    "/srv/buzz-agent-state", "/home/operator/.config", "/home/operator/.ssh"
  ]
}
```

List **all** host credential, Gateway runtime, agent HOME/state, operational source
and other protected roots. System sensitive paths, the adapter source checkout and
host HOME credential subdirectories are additionally excluded. Equal/nested roots,
noncanonical paths, symlinks (including dangling components), agent-writable
ancestors, shared objects/alternates, non-full/shallow clones and submodules are
rejected. Submodule checkout provisioning is outside this interface.

The owner authenticates the request's origin before invoking the host adapter. The
verifier must derive the requester from that trusted invocation context (for the
initial owner-mediated workflow, a host-controlled requester binding). The agent
cannot select requester identity, executable, destination, URL, config or ledger.
Do not expose `sudo <script> <arbitrary-config>` to agents. A future transport must
provide an authenticated requester binding and replay/revocation handling; an
untrusted environment variable or request `agentId` is insufficient.

The only accepted request keys are:

```json
{"jobId":"age5-agent-orchestration-developer","repository":"darimuri/agent-orchestration","baseRef":"main","baseSha":"7cd5a8fa43d762593feb7b7fd50a2fc78a8d9c96"}
```

Pass serialized JSON on stdin to the **installed** host copy:

```bash
sudo /usr/local/bin/node /usr/local/lib/buzz/workspace-provisioner.mjs \
  /etc/buzz/workspace-provisioner.json < reviewed-request.json
```

## Verifier contract: host integration gate

The host-owned executable receives that request on stdin, no arguments, and must
return exactly one JSON object with these keys on stdout:

```json
{"requesterId":"developer-a","role":"developer","enabled":true,"jobId":"age5-agent-orchestration-developer","repository":"darimuri/agent-orchestration","baseRef":"main","baseSha":"7cd5a8fa43d762593feb7b7fd50a2fc78a8d9c96","status":"active","expiresAt":"2026-10-28T12:00:00Z"}
```

This is a normalized verifier result, **not** a claimed Gateway ledger schema.
Reuse the actual deployed Gateway verifier/ledger semantics; do not create a second
authorization database. The verifier must resolve enabled authenticated requester,
current role, job-to-agent membership, operation authorization, active/noncompleted
status, expiry, exact repository/baseRef/full SHA and host owner allowlist from
current authoritative state. Unknown/disabled/mismatched identities, missing or
ambiguous jobs, completed/expired jobs, revoked permission or unreadable/malformed
state must exit nonzero. It must not echo raw ledgers, tokens, keys or Git errors.
The adapter rejects extra result keys, mismatches and expiry, verifies again under
the shared lock, after cloning, and before each publication. This does not create an
atomic transaction with concurrent Gateway revocation: owner acceptance must verify
actual verifier freshness and define job-state coordination if stronger atomicity
is needed. Do not claim live authorization acceptance from fixture results.

## Existing clones, locking and audit

The job ID is durably bound to requester/repository/base before staging. A conflicting
reuse fails closed. All existing destinations are preflighted before clone staging
and rechecked before any publication. Only clean full clones with the exact
credential-free origin and exact HEAD are reused. Tracked, staged, untracked and
ignored dirt, index assume-unchanged/skip-worktree flags (including sparse
checkouts), wrong origin/SHA, includes/worktree extensions and object alternates
fail closed. Git optional locks are disabled: read-only checks must not refresh the
index. Git and config parsing on existing agent-owned clones run under their owner
UID, not root, with a minimal environment that excludes host authentication. Existing
root-owned checkouts are rejected; only host-private fresh stages are inspected as root. No reset/clean/stash/pull/ownership repair is performed on existing
clones. Agents should be quiescent for stable content verification; concurrent
content writers can invalidate a clean result after it is read. Host-owned parent
checks prevent agents replacing installation parents.

All missing clones are staged independently on their destination filesystems and
must match the current requested ref tip AND exact SHA; moved refs fail rather than
silently selecting a newer commit. Publication uses atomic rename **per role**, not
a three-directory transaction. A failure can leave verified clones for earlier
roles. Do not roll them back destructively. Retry the same live-authorized request:
clean matches remain unchanged, remaining clones are staged afresh. Conflicting or
dirty leftovers require owner investigation and a new isolated destination, never
automatic repair. Interrupted `.provision-*` staging directories are host-private;
an owner may inspect/remove only confirmed abandoned staging directories under the
shared lock. The adapter does not automatically adopt/delete unknown leftovers.

Each authorized attempt entering locked checkout preflight writes and fsyncs a started receipt before
installing clones, then writes and fsyncs a result receipt. Receipts contain only
random receipt ID, requester/job/repository/base, timestamp, logical role outcomes,
result and a fixed error code. No host paths, raw stderr or credential values are
returned. Audit write/fsync failure never yields success; after publication this can
mean clones exist with only a started receipt. Check all three destinations and
retry under the lock; do not infer success from a started receipt. Requests rejected
before authorization or host preflight produce a sanitized rejection on stdout;
the host must retain these rejection results in its own durable invocation log.
Use filesystem quotas/retention for audit storage under separate owner policy.

## Verification and manual fallback

```bash
node --test agents/docker/*.test.mjs agents/scripts/*.test.mjs
bash github-apps/test-create-apps.sh
bash agents/scripts/test-provision-runtime.sh
bash agents/scripts/build-and-smoke.sh
sudo bash agents/scripts/test-workspace-mounts.sh
```

The new Node fixtures exercise real local Git, a deterministic host-verifier fixture,
identity/job mismatches, expiry, malformed responses, path/symlink/parent trust,
clean repeat requests, dirty/origin/SHA conflicts, independent objects, shared flock,
ref movement, revocation after partial installation/retry, result-audit storage
failure/retry and secret-canary failures.
They do not establish production verifier integration, UID switching as root, private
GitHub authentication or actual runtime mounts. Fixtures require an executable local
temporary filesystem; if `/tmp` is noexec, prepare a private executable scratch directory and set
`TEST_EXECUTABLE_TMPDIR` to it. Only fixture verifier/Git executables go there;
repository data stays in `TEST_TMPDIR` (default `/tmp`), outside the protected source
checkout. In the isolated development checkout, an ignored
`.age5-state/fixture-executables` directory can hold these executables. The separate root/Docker mount fixture
verifies read-only writes fail for two roles and writes succeed for Developer using
disposable directories; it does not recreate running agents or change runtime config.
Owner live acceptance must also verify the existing Compose mounts and all relevant
protected roots with the production config before rollout.

Keep the original manual fallback, host-only:

```bash
bash agents/scripts/provision-agent-repository.sh darimuri/agent-orchestration main /host/runtime.env
```

It retains its previous preserve-existing behavior and does not enforce the new
live job/exact-SHA contract. The host operator must independently verify authorization,
origin, clean state, SHA, destinations and runtime mounts before using it. It is not
an authorization bypass for failed requests. Reverting this draft removes the new
adapter and restores the original single clone command; it does not remove clones,
receipts or change deployed runtime/credentials. Rollout and host preparation remain
separate owner actions.
