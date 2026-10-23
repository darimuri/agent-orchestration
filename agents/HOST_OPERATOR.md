# Host Operator phase 1: offline protocol and journal

This change supplies **libraries and disposable fixtures only**. It is a prerequisite
for AGE #7, not a deployed Host Operator or completion of issue #10. Nothing consumes
Buzz messages, starts a service/socket, executes a process, publishes a message or
calls Kaneo. There is no stdin CLI accepting a `verified` context and no default
verifier. Never wire these modules directly to untrusted chat/model JSON or expose
an agent-controlled journal directory/configuration.

## Trust model and scope

Untrusted data includes mentions/display names, relay events before verification,
quoted assignments, task text, repository code/hooks/configuration, test output,
completion claims and request JSON. A copied owner event ID is not authentication.
The future host boundary must verify signatures/owner policy and current enabled
requester/job membership, operation authorization, task/repository/ref/SHA scope,
expiry, revocation, channel/thread and the signed payload hash. Prompts and the
existing Compose owner-only policy do not replace this boundary.

Trusted inputs to the library constructor are an installed reviewed operation
registry, exact source/dependency binding, owner pubkey, private local journal,
clock, and authorization/receipt verification adapters. These adapters are ordinary
in-process functions selected by trusted host code, never request fields. The
fixtures simulate their verdicts. They do **not** implement cryptographic Buzz
validation, the live Gateway job ledger or a process termination verifier.

The threat model covers replay, scope substitution, arbitrary command/path/env/mount
injection, lost responses, concurrent consumers, process crashes, symlink/hardlink
state substitution, storage failures and output/exception poisoning. Host-admin or
same-host-UID compromise, rollback of storage snapshots, physical power-loss/storage
hardware guarantees, global exactly-once across separate journals and atomicity with
concurrent authorization revocation are not claimed.

There is no rollout, rollback, checkout, workspace migration, credential operation,
Docker integration, systemd unit, root shell or sudo policy change. A fixed script
name and SHA do not make repository code safe to execute with host privileges.

## Library boundary

`host-operator-protocol.mjs` validates/canonicalizes data. Request keys are exactly:

```json
{
  "version": 1,
  "requestId": "request-one",
  "taskId": "task-one",
  "jobId": "job-one",
  "repository": "test-org/project",
  "baseRef": "main",
  "baseSha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "operationId": "status.revision",
  "channelId": "00000000-0000-0000-0000-000000000001",
  "threadId": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "authorizationEventId": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
}
```

Requests are limited to 4096 UTF-8 JSON bytes. IDs/refs have bounded restricted
alphabets; SHA is 40 lowercase hex; event IDs/pubkeys are 64 lowercase hex. Unknown
keys, caller identity, arbitrary argv/shell/path/env/mount/URL and nonregistered
operations are rejected. Canonical hashes sort object keys; JSON whitespace/key
order never changes the logical request binding.

`HostOperatorJournal` is constructed with:

- `directory`: pre-existing canonical private directory, resolved by the host.
- `source`: exact `{repository, baseRef, baseSha, workspaceId, sourceDigest}`. The
  digest must identify the whole owner-reviewed source/dependency set, not a value
  asserted by the requesting agent. Logical workspace IDs are not filesystem paths.
- `ownerPubkey`, `authorize(request, descriptor)`,
  `verifyReceipt(evidence, intent, {request, identity})`, optional trusted `clock`.

`next(request)` returns a **data intent**, `needs_user`, a complete normalized result,
`outcome_unknown`, or a fixed blocked result. Consumers are offline fakes in this PR.
`record(request, evidence)` verifies and records a positive authoritative receipt;
it is also the reconciliation API. It does not execute a runner, search a relay,
clear a lock, reset a journal or automatically retry a missing effect. There is no
production transport or adapter supplied by this PR.

### Required authorization adapter contract

Return exactly these normalized keys (unknown keys and thrown errors fail closed):

| Fields | Meaning |
| --- | --- |
| `requesterId`, `role`, `kind` | Enabled identity/role; kind `owner_event` or `assignment` |
| `eventId`, `signerPubkey`, `ownerPubkey`, `mentionPubkey` | Verified event, signer, configured owner, owner-approved callback recipient |
| `requestHash`, `descriptorDigest` | Canonical SHA-256 of the exact request and immutable descriptor |
| `verifiedAt`, `expiresAt` | Integer epoch ms, verification no older than 60s, job not expired |
| `enabled`, `status` | Exactly `true`, `active` |
| `taskId`, `jobId`, `repository`, `baseRef`, `baseSha`, `operationId`, `channelId`, `threadId` | Exact binding to the request |

An event envelope supplies its event ID; do not try to embed an event’s own ID
inside its signed content. The adapter validates the signed payload’s request fields
(or the signed assignment capability), binds the verified envelope ID to
`authorizationEventId`, then computes the complete normalized request hash.

For owner events, signer must equal configured owner and role is `owner`. For
assignments, the adapter must verify actual owner attestation/delegation plus live
job-to-agent membership/current role; a syntactically valid delegated signer is
insufficient. The library cannot establish those external facts itself. It checks
normalized shape, freshness and equality, including the descriptor digest. Missing,
malformed, disabled, expired, revoked, wrong-owner/thread/task/SHA or changed registry
context denies before emitting any intent. The adapter is called before journal
access and again under the lock before every new effect, including report/resume.

### Fixed registry v1

All descriptors have registry version `host-operator-offline-v1`, source/dependency
SHA-256, repository/ref/full SHA, logical workspace, timeout and output-byte quota.
They contain **no executable path, shell snippet or runner implementation**.

| Operation ID | Future privilege class | Timeout | Output bound | Registered user action |
| --- | --- | --- | --- | --- |
| `status.revision` | read_only | 5s | 4096 | none |
| `validate.node` | isolated_validation | 120s | 65536 | none |
| `validate.resource-config` | isolated_validation | 30s | 16384 | fixture preparation |
| `validate.preflight` | host_gate | 30s | 16384 | fixture preparation |
| `validate.build-smoke` | host_gate | 600s | 65536 | fixture preparation |
| `validate.resources` | host_gate | 120s | 65536 | fixture preparation |

These limits are intent metadata. Enforcement of subprocess output/resource quotas,
source/dependency identity and process-tree lifetime belongs to a later restricted
executor. No fixture result establishes such enforcement. Existing preflight sources
an env file and requires root; build/smoke/resource suites have Docker/mount side
effects. They must never be treated as unprivileged read-only status operations.

## Durable transitions, replay and reconciliation

Before returning an execution/report/user-action intent, the journal writes a private
exclusive temporary file, fsyncs it, atomically renames it, and fsyncs the directory
chain child-before-parent. This follows the dispatcher-handoff durability pattern
without modifying its three-step helper or existing persistent journal.

Normal progression is execution intent -> verified execution receipt -> Kaneo report
intent/receipt -> Buzz report intent/receipt -> complete. Report payloads contain
only normalized result data and the original task or channel/thread/approved mention.
The receipt verifier must validate native Kaneo/Buzz delivery and content/identity
against the full intent digest, including actual task/comment/event/mention evidence.
There is no direct live publisher here. A failed/ambiguous delivery is not permission
to resend; a pending report holds its earlier execution/report receipts intact.

The journal durably binds `(jobId, requestId)` to one canonical request and identity.
Conflicting reuse fails. Complete replay returns the stored result and emits zero
intents. A new authorized request ID may select another operation after completion.
Any active request reserves its job and logical workspace; another ID cannot bypass
that reservation. A global exclusive `journal.lock` serializes independent processes
inside the configured namespace, including record/reconciliation calls. Persistent
pending entries retain the reservation after the lock is released.

One journal namespace is bound to one trusted source/registry/workspace configuration.
Changing that configuration fails closed against existing entries; do not switch to
another journal to evade pending work. The host must centrally route a job/workspace
to its unique namespace. Cross-namespace/global exactly-once is not provided. The
journal is bounded to 128 requests and 1 MiB; archival/upgrade/migration needs separate
operator design and must preserve replay evidence, not delete/reset live state.

A pending intent after restart is `outcome_unknown`, whether a consumer crashed before
or after performing the effect. No empty search result, chat “done”, timeout or
unconfirmed worker death clears it. Positive authoritative matching evidence can be
recorded even after job expiry; fresh live authorization is still required before
any next effect. Duplicate identical receipts are idempotent; conflicting receipts
or wrong hashes/steps/targets reject. Deadlines do not prove process termination;
timeout/cancellation leaves the execution pending. A later trusted receipt must prove
termination/no descendants plus the actual result before progress is allowed.

### needs_user

A verified execution receipt `needs_user` means **no operation ran** and the selected
registered prerequisite is required. Only operations with a fixed user action can
emit a user intent. In phase 1 the sole command presentation is deliberately inert:

```text
HOST_OPERATOR_FIXTURE_ONLY prepare-host
```

It is not an installed tool, sudo command, login instruction or recommendation to
execute it. There is exactly one argv presentation, derived from the internal
registry and bound by the intent/request/job/SHA hashes. No model/chat command is
copied or executed. A missing action or repeated prerequisite blocks with
`host_preparation_required`. Replaying a pending user intent returns outcome_unknown
without issuing another handoff. After an authoritative same-intent user receipt and
fresh authorization, the protocol can issue one resumed execution intent in the same
journal. The receipt adapter must require owner-approved authoritative host evidence
for the user action; a requester’s chat completion claim is insufficient. It then
reports the terminal result. Live publication of prerequisite
handoffs and actual reviewed user commands are later integration work.

## State protection and non-disclosure

The caller must precreate a mode-0700 directory under trusted non-writable ancestors.
Directory/file symlinks, multiple file hardlinks, wrong ownership, permissive modes,
noncanonical paths and malformed state deny. Root-owned system ancestors are allowed;
unprivileged fixtures may use sticky `/tmp` with a private child. This exception is
for disposable tests, not a deployment storage recommendation. Production journals
must use durable host-only local storage outside agent workspaces/HOME/mounts.

State files are 0600. A stale exclusive lock after process death or leftover atomic
temporary file blocks, with no automatic cleanup/adoption. Operators must investigate
authoritative evidence under separate host procedure; this PR has no stale-lock
clearing or state repair command. ENOSPC/open/write/rename/fsync failures never return
an intent. Failure after rename may leave a pending entry even though no consumer saw
it, so the next attempt conservatively requires reconciliation. Power-loss behavior
on the intended filesystem/mount remains a host acceptance gate.

Receipts have an exact bounded schema: version, receipt/intent IDs, intent digest,
request hash, step, fixed outcome, timestamp, opaque evidence reference/digest and
bounded passed/failed/skipped/exit/signal summary. They contain no stdout/stderr,
environment, arbitrary log text, host paths or credentials. Raw evidence is limited
to 8192 bytes and is not stored; only trusted normalized evidence is accepted.
Unexpected adapter/storage errors become fixed `authorization_denied`,
`receipt_invalid` or `journal_io` codes. Do not put secrets in normalized identifiers;
opaque evidence storage and its access control are future host responsibilities.

## Verification and remaining host gates

```bash
node --test agents/scripts/host-operator.test.mjs
node --test agents/docker/*.test.mjs agents/scripts/*.test.mjs
bash github-apps/test-create-apps.sh
bash agents/scripts/test-resource-config.sh
```

The new fixtures need no subprocess executor, network, credentials or elevated UID.
They use real temporary filesystem durability/permission checks, two disposable Node
processes for lock contention, injected storage faults and a killed fixture process.
Fake authorization/receipt adapters and fake runner/report consumers test denial,
replay, independent report recovery, expiry, scope/registry binding, sanitized canary
failures and needs_user. Existing AGE #5 fixtures require executable scratch if `/tmp`
is noexec: set `TEST_EXECUTABLE_TMPDIR` to a private executable temporary directory;
all fixture repository data remains outside the protected source checkout.

Remaining gates before any real host operation is reachable:

- AGE #5: integrate its live authoritative verifier/authenticated requester; extend
  proof with AGE #7 task/operation/registry/transport binding without another ledger.
  Separately approve and test host-owned workspace ancestry/migration. This PR never
  calls workspace provision(), runtime provisioning or state-storage prepare.
- Root/executor: root-owned reviewed install/config/action registry and full dependency
  review; least-privilege UID, private durable state, trusted clock and sanitized env;
  resource/output limits, process-tree termination and real crash/power-loss acceptance.
  No Docker socket, root shell or NOPASSWD sudo in an LLM process.
- Docker/systemd: separately reviewed isolated worker design, pinned images, no secrets
  or operational mounts; peer authentication, boot/mount ordering, resource limits and
  restart/reconciliation tests before installing/enabling a service or socket.
- Live Buzz/Kaneo: owner signature/delegation/current policy integration, separate least-
  privilege reporting identities outside LLM secrets, exact original-thread/task/content
  binding, native delivery/mention receipts and lost-response reconciliation.
- Full root/Docker build/runtime/mount/resource suites and independent Reviewer/CI evidence
  at the final head. Missing gh/Docker/Compose/root prerequisites are unavailable, not pass.

Removing these new libraries/docs rolls back phase-1 source only. It must not remove
journals, alter deployed runtime/credentials/jobs or perform operational rollback.
The overall Host Operator and its live acceptance remain incomplete after this PR.
