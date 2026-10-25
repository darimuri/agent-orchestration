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
original phase-1 fixtures simulate their verdicts. The opt-in A1 adapter described
below adds public signature verification; neither phase supplies the live Gateway
job ledger or a process termination verifier.

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

## A1: direct-owner public event authentication

`host-operator-auth/owner-event.mjs` now supplies real NIP-01 event ID and
BIP-340 Schnorr verification, and `authorization.mjs` supplies an opt-in
`createAuthorizationAdapter` for the unchanged phase-1 journal. This is a library
with injected host seams, not a live Gateway verifier or Host Operator installation.
The original phase-1 fake-adapter tests retain their meaning; the new suite uses
real signatures and the same journal/receipt APIs. There is no runner, polling,
network provider, CLI, default policy, secret loader or delegated-assignment path.
Only `status.revision` is admitted by this adapter, and an intent still executes
nothing. Every `validate.*` request is denied even though v1 retains those registry
names for future reviewed integrations.

### Signed wire format and fixed bounds

Pass serialized event JSON as a string or UTF-8 Buffer to
`verifyOwnerEvent(raw, {ownerPubkey, targetPubkey, channelId, threadId, source, now})`.
It returns `{request, descriptor, signerPubkey, expiresAt}` or throws the fixed
`authorization_denied` ProtocolError. Raw objects, cached verification booleans,
extra fields, duplicate keys (including escaped spellings), malformed UTF-8,
unpaired surrogates and excessive nesting are denied. Every call rebuilds the
NIP-01 hash from `[0,pubkey,created_at,kind,tags,content]` and verifies the signature;
there is no verification cache. Public signatures prove integrity/authorship only.

The event has exactly `id,pubkey,created_at,kind,tags,content,sig`. Require kind 9,
configured owner signer and exactly one of each routing tag:
`["h",channelId]`, `["p",targetPubkey]`, `["e",threadId,"","root"]`.
Other bounded tags carry no authorization; additional h/p/e tags, reply targets
and routing hints in these three security tags are rejected as ambiguous. This
strict structured command format does not execute conversational Buzz assignments.
Signed `content` is JSON with exactly:

```json
{
  "type": "host-operator.request",
  "version": 1,
  "request": {
    "version": 1,
    "requestId": "request-one",
    "taskId": "task-one",
    "jobId": "job-one",
    "repository": "test-org/project",
    "baseRef": "main",
    "baseSha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "operationId": "status.revision",
    "channelId": "00000000-0000-0000-0000-000000000001",
    "threadId": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  },
  "descriptorDigest": "canonical digest of the trusted v1 descriptor",
  "expiresAt": 1800000600000
}
```

The descriptor digest above is an illustrative placeholder, not a valid command.
The verified envelope ID supplies `authorizationEventId`; embedding it is rejected.
The source is the trusted reviewed `{repository,baseRef,baseSha,workspaceId,sourceDigest}`
binding. The request and descriptor digest must match it exactly.

Limits are fixed: event 16 KiB, content 8 KiB, v1 request 4096 bytes, JSON nesting
16, at most 32 tags of 1–4 strings each and at most 256 UTF-8 bytes per tag string.
`created_at` is integer epoch seconds, expiry/clock are integer epoch milliseconds;
future skew is at most 60 seconds, event age at most 10 minutes, signed lifetime
strictly positive and at most 10 minutes, and expiry must be strictly after now.
No request may override those bounds or supply executable shell/path/env/mount/argv.

### Trusted synchronous policy composition

Construct `createAuthorizationAdapter` with trusted configuration
`{ownerPubkey,requesterId,mentionPubkey,targetPubkey,channelId,threadId,source,
resolveEvent,currentJob,clock}`. `clock` defaults to Date.now. The owner/requester
and callback mapping is host-pinned, never taken from request text or display names.
`resolveEvent(eventId)` must return raw event bytes/string. The adapter independently
checks that the derived request equals the journal request and recomputes the
trusted descriptor; a resolver cannot substitute another valid event.

The mandatory `currentJob(request, verifiedIdentity, descriptor)` is a synchronous
host-selected function. Its arguments are detached copies. No live implementation
is shipped. It must derive facts from the existing authoritative authorization
source; echoing arguments, a static assignment or a caller-provided `verified=true`
is not live policy evidence. Promise, missing, unreadable, malformed, inherited,
accessor or symbol-bearing results deny. The return is a strict DTO of at most
4096 serialized bytes, **not a Gateway ledger schema**:

| Exact fields | Required value |
| --- | --- |
| taskId, jobId, repository, baseRef, baseSha, operationId, channelId, threadId | Exact request binding |
| requesterId, role, ownerPubkey, mentionPubkey, targetPubkey | Configured owner mapping; role `owner` |
| workspaceId, sourceDigest, descriptorDigest, requestHash | Reviewed source/descriptor and complete request hashes |
| enabled, status, requesterMember, ownerAllowed | `true`, `active`, `true`, `true` |
| allowedOperations | Exactly `["status.revision"]` for this bounded adapter |
| verifiedAt, expiresAt | Safe integer epoch ms; verification at most 60s old, never future; unexpired job |

These booleans are conclusions of trusted provider code, not self-authenticating
JSON assertions. The provider must prove owner allowlist, requester membership,
job/task/operation scope and current enabled/noncompleted/nonrevoked state. A
Gateway repository read alone does not establish them. Exceptions are sanitized.
The normalized phase-1 authorization expiry is min(signed expiry, job expiry).
Missing provider denies; it never issues a user command to expose credentials or
ledgers. Future integration must establish bounded synchronous freshness without
blocking network I/O under the journal lock, or separately review an API redesign.
No atomic transaction with concurrent remote revocation is claimed.

The journal reauthenticates before access and under lock before every new intent;
A1 reruns event and current-policy checks each time. Completed replay creates no new
effect, pending remains outcome_unknown, and expired authorization starts nothing.
`verifyReceipt` remains a separate mandatory authority: an owner request signature
is never proof of execution, reporting or user completion. Proven historical receipts
can still reconcile after request expiry; the next intent then denies. The inert
needs_user fixture and all existing journal schemas/identities remain unchanged.
No journal migration, reset, nonce database or operational resume is introduced.

### Dependency and verification evidence

Install the scoped locked dependencies using:

```bash
npm ci --prefix agents/host-operator-auth --ignore-scripts
node --test agents/scripts/host-operator-auth.test.mjs agents/scripts/host-operator.test.mjs
node --test agents/docker/*.test.mjs agents/scripts/*.test.mjs
```

Node >=20.19 is required. The manifest pins `@noble/curves` 2.4.0; the lockfile
pins its sole dependency `@noble/hashes` 2.4.0 with registry URLs and SHA-512 integrity.
Only the Schnorr API is imported in production. No signing, wallet or transport API
is exposed. No lifecycle scripts are used. See the
[upstream security history](https://github.com/paulmillr/noble-curves#security):
it reports broad Trail of Bits review at 2.3.0, plus earlier independently scoped
audits. Those reports do not certify every change in 2.4.0 or this adapter. The
release/source/lockfile still need independent review; npm audit is an advisory
lookup, not a cryptographic audit. The tests use the public
[BIP-340 vector 0](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv)
and deterministic signed command fixtures. The public vector scalar is test-only
and must never be used for operational identities. Tests need no private live keys.

A1 reduces the simulated owner-signature boundary only. AGE #5 live requester/job
verification and host-owned workspace migration, immutable reviewed installation,
resource/process-tree enforcement, root/Docker/systemd/peer authentication, durable
host storage and live dedicated Buzz/Kaneo reporting/native reconciliation remain
separate host gates. No new identity, credential, service, permissions or runtime
is created. C-prime issue #16, rollout and operational rollback remain outside A1.
Source rollback removes only these A1 modules, dependency, tests and docs; preserve
all existing journals and receipts and never resume production with fake policy.

## A3 / A7: offline writer, admission and journal lifecycle conformance

The test-only `scripts/check-host-operator-integration.mjs` closes the A2 DTO-only
compatibility gap. A7 extends it to compose the actual merged A6
`createHostAdmissionWriter`, the actual A1 signed-event adapter, the actual built
Gateway `createHostPolicySource`, and the actual journal. It imports no live config,
starts no service, discovers no operational ledgers and executes no intent. Events
use the public BIP-340 vector-0 test scalar; A8 resolves exact-ID raw fixture files,
and receipt verification is a separate positive fixture authority. Private disposable
agents/jobs files go through the unchanged A2 ownership, ancestry and safe-file checks.
The execution subject remains distinct from the requesting owner.

Run from a **clean committed** orchestration checkout at the head being reviewed:

```bash
# Operator-supplied source checkout, not a host request or live ledger path.
# This exact dependency HEAD/tree is mandatory; a moving main or existing dist is refused.
gateway_source=/workspace/darimuri/github-app-agent-gateway-post-a6
orchestration_head=$(git rev-parse HEAD)
node agents/scripts/check-host-operator-integration.mjs "$gateway_source" "$orchestration_head"
```

Pinned dependency: `darimuri/github-app-agent-gateway`
`9e1989010c80c04e15002adee8f49af5723ed02d`, tree
`882fcd06ebfbee442b20694ebb24035e861ca5c1` (merged A6 jobs-only writer). Orchestration must descend from A1 merge
`1b3bc2b41e2767273053e8e03bd89e9d3149d3e1`. The harness checks canonical origins,
exact heads/trees, clean tracked and untracked source state, and rechecks them after
validation. Both supplied source roots must be canonical paths. It archives the
committed sources into private scratch, installs their unchanged locks using
`npm ci --ignore-scripts --offline --no-audit --no-fund`, runs full Gateway
`check`, `test`, `build`, then focused lifecycle integration and the full
orchestration Node suite. Gateway, focused integration and full orchestration
summaries must each show zero skips. It never fetches,
checks out or installs packages in either supplied source.
An offline npm cache containing both lockfiles' dependencies is a prerequisite;
a cache miss is a failure, never a reason to fetch or weaken the pin.

Use an ordinary Linux UID and protected executable scratch. If `/tmp` is `noexec`,
set `TEST_EXECUTABLE_TMPDIR` to a precreated private mode-0700 executable directory
under trusted ancestors outside both source checkouts. Only its newly created
`host-integration-*` child is used. Successful runs remove that child; failed runs
retain private logs/fixtures there for local investigation. These are synthetic
fixtures, never operational ledgers or secrets. Review then remove only that scratch
child. The harness passes a minimal subprocess environment without Buzz credentials,
NODE_OPTIONS or inherited npm configuration and emits fixed summaries rather than
raw upstream errors. Its operations are fixed build/test commands, not request-selected
shell/argv. Existing gh/Docker/Compose/root suites require separate host verification;
the harness does not claim those or CI passed.

The integration suite covers valid durable intent/complete replay, each pending
execution/report boundary after reopening, separate receipt authority, event integrity
and signed scope substitutions, owner/callback/target/task/source/descriptor and
agent/job binding, missing capability/provider, Promise/error provider, disabled,
expired/completed/cancelled subjects, atomic revocation before/under lock and before
later report intents, unsafe/oversized/malformed/unstable files, expiry minima and
clock units, timeout without termination proof, historical positive receipt after
expiry/revocation, and canary/hash/path non-disclosure. Only fixed `status.revision`
requests can reach admission. Without the harness-provided private build, these new
cross-repository tests explicitly skip in ordinary Node runs; a run with those skips
is **not** A3/A7 integration evidence. The harness run must report zero skipped tests.

This demonstrates offline composition against pinned real code, not live host policy
or receipt authority. Immutable installation/artifact verification, trusted UID/path
and atomic ledger writers, bounded storage/latency, synchronous filesystem stalls,
nontransactional revocation/ABA, existing dependency advisory assessment, AGE #5,
executor/process/resource controls and native Buzz/Kaneo receipts remain host gates.
Independent exact-head Reviewer/CI and human approval remain separate. No live
capability, endpoint, runner, validate/reporting, root/Docker/systemd or runtime is
installed. Reverting only these tests/harness/docs and discarding their scratch rolls
back these A3/A7 source changes; preserve Gateway writer code and all operational
journals/receipts. Overall AGE #7 is incomplete.

### A7 evidence and the administrative unknown-outcome boundary

The lifecycle fixtures start with no capability, then use the **actual built writer**
with constructor-selected synthetic path/UID/owner/task/source/descriptor policy.
Confirmed set makes the same valid signed request eligible for one durable status
DATA intent; all non-capability and forge fields, including unrelated jobs and absent
defaults, remain unchanged. Confirmed remove is scheduled before outside-lock and
inside-lock authorization at execution and both later report boundaries. Denial
preserves journal history. Reopened pending execution/Kaneo/Buzz intents stay unknown
without duplicate effects; separately verified historical positive receipts can
still record after removal, while the next intent remains denied. Complete replay
under valid policy emits no new effect. Signed-event, disabled/expired subject,
binding and unsafe-file failures still pass through real A1/A2 denial.

Positive capability grant/removal uses no copied writer and no raw fixture rewrite.
Existing malformed/hostile ledger and disabled-agent cases deliberately retain raw
synthetic replacement as attacker/fault inputs, not durable administrative evidence.
Stale raw-byte digest conflict and denied mutation are checked without changing the
active file. Writer confirmed/conflict/denied/unknown results, reconciliation DTOs,
signed events and current-policy facts cannot normalize into execution or native
report receipts, even when a fixture receipt adapter returns them. No actual intent
consumer, native publisher or live transport is installed or called.

A synthetic post-rename parent-fsync failure explicitly produces
`outcome_unknown` with a visible candidate and retained writer lock. Read-only
reconciliation reports `visibility:candidate`, `durability:unproven` and blocked
administrative coordination, without changing bytes/artifacts. **A2 does not consume
writer outcome or lock/durability state; the journal does not consume administrative
write results.** The same visible candidate can pass real A1/A2 and permit a DATA
intent. This test exposes the existing separation; it is neither a durable recovery
claim nor an automatic policy denial/fence. A test driver can stop on unknown, but
no installed production driver/fence exists here. Live administrative sequencing,
unknown-commit recovery and startup consumption require explicit host procedure and
separate acceptance. There is no automatic administrative retry, cleanup, rollback,
lock adoption or recovery sync in this phase.

Confirmed administration alone proves neither enabled agent policy, valid raw event,
execution/termination nor native receipt delivery. Cooperative writer locking and
expected-byte comparison are not universal CAS against uncooperative same-UID actors.
Actual storage/power-loss/latency, all real jobs-writer coordination, agents/token
rotation and cross-file recovery remain H4/H5/H6 gates. H1–H9 live outcomes remain
**NOT_READY**; A5's deliberately pinned A4 contract baseline is unchanged. Stronger
identity/isolation remains deferred to issue #21; Gateway Ready defect #11 is separate.
No Gateway/production/schema/dependency/lock/runtime/credential/live-ledger changes
are part of this three-file conformance slice. Rollback reverts only its test/harness/
docs, preserving writer source and operational evidence; independent exact-head
review/CI/human merge remain separate from operational approval and activation.

## A4: host acceptance preparation — NOT READY

[HOST_OPERATOR_HOST_ACCEPTANCE.md](HOST_OPERATOR_HOST_ACCEPTANCE.md) records the
pinned A1/A2/A3 baseline, evidence owners, unresolved inventory and go/no-go rules
for host installation, administrative ledger writers and journal/storage acceptance.
It is a documentation-only contract/template. Actual host UID/GID/access, installed
paths/artifacts, writer source/procedure, storage/latency/risk decisions and live
event source remain **UNRESOLVED / NOT READY**; no default values are inferred from
fixtures or existing runtime preflight IDs. Group-read access does not satisfy A2's
exact ledger file UID/private-mode requirements. The contract preserves separate
requester/subject/receipt authority and existing journal/receipt history.

A3 conformance remains offline evidence. Neither the contract nor its merge activates
live event/current-policy processing, execution or native reporting. Future host
positive/negative acceptance, independent review of evidence and owner authorization
remain separate. A4 changes no code, tests, dependencies, installer, live ledger,
capability, job, runtime, credential, container/service or deployment.

## A8: bounded local candidate-event byte source — live NOT_READY

`host-operator-auth/event-source.mjs` exports
`createFileEventResolver({directory, uid, clock?, monotonic?})`. Its result is the
synchronous `resolveEvent(eventId)` callback accepted by the unchanged A1 adapter.
Trusted host construction selects one canonical absolute **non-secret-event-only**
namespace and its expected ordinary runtime UID, which must equal the process UID.
No live path, new identity or installation is selected by this module or these tests.
Do not select a ledger, journal or agent HOME as an event namespace. Constructor
configuration is not requester input, and this library is not a generic file endpoint.

The request supplies only an exact 64-character lowercase hexadecimal event ID;
the filename is internally derived as `eventId + '.json'`. Objects, path segments,
URLs, suffixes, uppercase, malformed and oversized IDs deny without file lookup.
The configured directory is bounded to 4096 UTF-8 bytes, and the derived path must
also fit that bound. Each lookup validates existing canonical ancestry, opens and
anchors the directory, then opens one named file with no-follow/nonblocking flags.
The event directory must be expected-UID mode 0700; the event must be a same-device,
single-link regular file, expected-UID mode 0600, with size **1..16384 raw bytes**.
Ancestors must be root/configured-UID owned and not group/other writable; only the
sticky `/tmp` fixture ancestor is excepted. Symlinks, unsafe ancestry/permissions,
wrong owner/device, missing/inaccessible files, FIFO/device/directory entries,
hardlinks and observed directory/file replacement or metadata instability deny.
No permissions are repaired or paths created by the source.

A lookup performs one positional bounded file read (at most recorded size plus one
byte), checks named/opened identity, owner/mode/link/size/time metadata before and
after the read, revalidates the anchored directory and returns an ordinary detached
Buffer. Repeated calls actually reopen and revalidate; there is no byte, negative
lookup or verification cache. A later complete atomic file replacement is read
fresh; replacement during a read is rejected when observed. The source never lists,
searches or glob-matches the directory and never reads Gateway agents/jobs files.
A9 below adds a local placement library. There is no network/relay listener, subprocess, service,
startup wiring, ambient configuration/env discovery or automatic fallback.

Every lookup checks wall and monotonic clocks around the I/O, rejecting invalid or
backward values and observed elapsed time greater than **100ms** on either clock.
Defaults are `Date.now` and `performance.now`; optional clock functions are trusted
construction inputs only. This is an observed per-lookup budget, not cancellation:
a synchronous syscall can stall beyond the budget before the code regains control.
No hard deadline, transactional revocation/ABA defense, hostile same-UID isolation
or hardware power-loss guarantee follows from these checks. The existing accepted
local status-only P5 limit and separately deferred issue #21 isolation remain.

The Buffer is intentionally **untrusted raw event data**, not sanitized public output
or a parsed/authenticated verdict. Do not print/log it as a receipt. This source
performs no JSON, UTF-8, hash, signature, routing, expiry or authorization parsing.
A1 rechecks those properties and exact request/event-ID/source binding on every
read; even a different correctly signed event under the requested filename cannot
satisfy the unchanged adapter. A2 independently rechecks current capability/subject
policy. Filename, file mtime, successful read and owner placement are not proof of
signer identity or current lifetime. Errors from constructor and lookup have only
fixed `event_source_denied` code/message/stack, without paths, IDs, raw bytes or
underlying exceptions. A1 converts source failure to `authorization_denied` before
any next journal intent.

The resulting chain is trusted local source configuration → untrusted candidate
bytes → actual A1 signed request verification → actual A2 policy → journal DATA
intent. The positive lifecycle integration uses the actual A9 placer for synthetic raw event files
and uses this actual resolver with the actual A6 writer/provider/journal. Explicit
fake/error/Promise seams remain negative fixtures only. Tests cover fresh rereads,
byte boundaries, ID rejection, permissions/links/file types, I/O faults, observed
file/directory/size/time races, clocks and real A1 wrong-owner/signature/context/
request/expiry denial. Deleting or replacing a file before outside-lock, inside-lock
or later execution/Kaneo/Buzz authorization denies new intent without changing prior
journal history. Missing/malformed event data does not prevent separate matching
historical positive receipt recording; the next intent and complete replay still
require valid current event authorization. A7's unknown-writer/candidate visibility
and independent receipt-authority cases remain intact; this source adds no fence,
recovery manager, journal repair or completion authority.

Use the unchanged A7 provenance harness above for exact-head acceptance, including
pinned Gateway install/check/full tests/build and full orchestration with **zero
integration skips**. The ordinary Node suite deliberately reports dependency-bound
integration skips when no harness build is supplied; report them honestly rather
than treating that run as cross-repository acceptance. The new standalone resolver
suite is `scripts/host-operator-event-source.test.mjs`. All files/events/identities
in tests are disposable public fixture data; no operational credential or spool
is accessed. A1/owner-event/authorization/protocol/journal, A4/A5 contract baseline,
Gateway source, harness pin and dependency locks remain unchanged.

H7 gains a real candidate-byte reader, **not live ingestion acceptance**. Before
actual composition, the owner still must select/prove a non-secret event namespace,
placement/retention custodian and complete atomic-placement procedure, reviewed
installed code/config/source digest, actual UID/access/ancestry/storage/latency and
how bytes arrive by exact ID. No ingest/writer or command for those tasks is invented
here. H1–H9 remain operationally **NOT_READY**; native execution/termination/report
receipts, host acceptance, independent review/CI and human operational approval are
separate gates. No sudo, Docker/systemd, runtime/container/service, credentials,
live ledger, Ready, approval, merge or deploy is performed by this slice.

Source rollback removes the module/new tests and reverts integration/docs only,
preserving journal/receipt/source/namespace bindings and real jobs authority. A
future installed consumer must stop accepting new requests if its source is removed,
not silently fall back to fake/in-memory authorization. No event-deletion procedure,
pending-intent reset, administrative replay or stale-lock cleanup is provided.

## A9: create-only local signed-event placement — live NOT_READY

`createFileEventPlacer({directory, uid, ownerPubkey, targetPubkey, channelId,
threadId, source, clock?})` from `host-operator-auth/event-placement.mjs`
returns `{place(raw)}`. A trusted local caller supplies serialized string or
ordinary detached Buffer bytes, bounded to 16KiB, without reserialization. Objects,
proxies, accessors, extended/shared Buffers and caller-selected ID/path/options
are rejected. The constructor fixes an existing canonical private directory,
actual ordinary process UID and source/context; it creates no namespace or keys.

The existing A1 verifier authenticates the raw signed status request and derives
its public event ID internally; it rechecks freshness before publication. Placement
does not query or assert current job policy. A8 reads bytes afresh, A1 verifies
again, A2 checks current policy and the journal decides whether to emit a data
intent. Placement is neither transport authentication nor execution/report receipt.
Synchronous syscalls/crypto are not preemptible: expiry may pass during a syscall,
and consumers independently enforce it. Invalid/backward clock readings deny.

Publication uses a random exclusive same-directory private staging file, complete
writes, file fsync, staged inode/metadata/byte checks, directory identity guards,
then atomic create-only hardlink to the verified ID plus `.json`. Only this call's
positively identified staging name is removed on the successful path. Parent fsync
and exact final inode/bytes/private0600/UID/device/single-link readback precede
confirmation. There is no overwrite rename, in-place copy, permission repair,
unsupported-filesystem fallback, retry or global lock. Protected ancestors and
exact0700 directory semantics match A8, including disposable sticky /tmp fixtures.
Same-UID hostile administrators and physical power-loss guarantees remain outside
this local trust model.

| status | Meaning |
| --- | --- |
| confirmed / durability_confirmed | This call completed publication, parent fsync and final readback. |
| already_present / durability_unproven | Safe existing bytes exactly match; no historical durability confirmation is invented. |
| conflict | Existing safe bytes differ, including whitespace-only wire changes for the same event ID; unchanged. |
| denied | No publication was attempted by this call; partial staging may remain. |
| outcome_unknown | Link was attempted; publication/cleanup/fsync/readback is uncertain. |

Results contain only fixed status/code and, after verification, public eventId.
Errors never echo raw input, signature, private path/digest or upstream exception.
Constructor errors use the fixed event_placement_denied code/message/stack.

During publication's two-link interval A8 deliberately denies nlink2. A contender
may also deny when it observes this interval. After own-stage unlink, nlink1 bytes
may be A8-readable and A1-valid before parent fsync or after an unknown outcome.
Visibility and current A2 eligibility do not prove durable placement. There is no
automatic admission fence. EEXIST during a publication race is conservatively
outcome_unknown; call-owned staging evidence remains. Subsequent identical input
can only report already_present/unproven (or deny unsafe metadata), never confirm
the earlier unknown operation. No stale-artifact cleanup, adoption, reconciliation,
unpublication or rollback is performed. At most one create-only publisher can win
one final name; this is not global exactly-once execution.

Offline tests exercise real placer→A8→A1→A2/actual writer→journal, short writes,
staged substitutions, unsafe metadata/parents, write/fsync/link/unlink/readback
faults, independent concurrent processes and SIGKILL boundaries. Test-only hostile
raw file replacements remain explicitly negative fixtures. A placement result
cannot satisfy the journal's independent positive receipt verifier; historical
receipts and every next-intent reauthorization retain their prior semantics.

Per-event bounds do not bound namespace growth. Before live use the owner must
choose and prove actual non-secret namespace/UID/custody, input transport,
installation/source binding, same-device no-replace/fsync storage behavior,
quota/retention ownership and ambiguous-publication investigation. No live path,
service, ingest, executor, reporter, credential or ledger is selected or changed.
All live H1–H9 remain NOT_READY; #21 isolation and #11 Ready workflow are separate.
Source rollback removes the two A9 files and reverts integration/docs only; preserve
all eventual event/journal/receipt evidence without deleting live files or supplying
an authority fallback.

## A10: one-shot local raw-event ingress — live NOT_READY

`host-operator-auth/local-ingress.mjs` exports the synchronous production composition
`createLocalEventIngress({eventDirectory, journalDirectory, uid, ownerPubkey,
requesterId, mentionPubkey, targetPubkey, channelId, threadId, source, currentJob,
verifyReceipt, clock?, monotonic?}) -> frozen {ingest(raw)}`. Importing it starts
nothing. A trusted in-process caller supplies one serialized event; there is no
CLI/stdin endpoint, transport, listener, service, executor or native reporter.

Construction snapshots ordinary own configuration/source data and fixes distinct,
canonical, existing private0700 event and journal namespaces at the actual ordinary
UID. Neither namespace may contain the other. It rejects proxies/accessors/symbols,
unknown options, unsafe ancestry and missing currentJob/verifyReceipt functions.
It creates/repairs no directory and accepts no caller-selected placer or journal.
The same frozen source/context and checked nondecreasing wall clock feed the actual
A9 placer, A8 resolver, A1 adapter and HostOperatorJournal. Optional monotonic clock
is the existing A8 observed lookup-budget seam, not an ingress-wide timeout.

`ingest(raw)` takes exactly one string or ordinary detached Buffer of1..16384 raw
UTF-8 bytes. It rejects parsed objects, proxies, shared/extended/getter Buffers,
extra arguments and UTF-8 BOM before verification. The bounded snapshot is copied
before callbacks can mutate caller bytes. Actual A1 validates/derives the request
and event ID; no caller-supplied request or verified flag is accepted. Actual A9
receives the same snapshot exactly once. Only **this invocation's** matching
`confirmed/durability_confirmed` result permits one actual `journal.next(request)`.
That API reopens A8 and reruns A1/currentJob outside and inside its lock. Placement
proof never substitutes for fresh current A2 policy and never grants a capability.

| Input/outcome | Ingress result and effect |
| --- | --- |
| Raw/A1 denial | `ingress_denied`; no placement or journal call. |
| Existing identical bytes / unknown placement | `placement_unconfirmed`; zero journal calls. |
| Existing different wire bytes | `placement_conflict`; zero journal calls. |
| Placement denial / unexpected placement result | `placement_denied`; zero journal calls; staging evidence may remain. |
| Confirmed placement, current authorization denial | `admission_denied`; candidate remains, no new intent. |
| Known journal reservation/conflict/limit | `blocked` with fixed allowlisted code. |
| Journal I/O/unconfirmed persistence/unknown error or malformed result | `outcome_unknown/journal_unconfirmed`; pending disk state may exist. |
| Normal durable journal result | Existing bounded public DATA `intent`, `outcome_unknown`, `blocked` or `complete` shape. |

Public projection checks exact result/intent/public-receipt fields, source/request
bindings, intent digest and primitive bounds before returning detached data. No raw
event body/signature, private path/ledger identifiers/digests, callback error text,
arbitrary summaries or stack is returned. Constructor errors have fixed
`ingress_denied` code/message/stack. Projection is not a second journal schema or a
receipt verifier: the existing journal validates its state and independent receipt
authority. This composition calls neither `record` nor verifyReceipt and exposes
no receipt endpoint. A DATA intent is not operation execution or delivery success.

This is deliberately **not transparent replay/resume**: identical retransmission
stops at already_present/unproven even if a previous response was lost, policy is
now valid, or the journal holds a pending/completed request. No retry, adoption,
re-fsync, file/temp deletion, rollback, namespace switch, cache or recovery manager
is provided. Existing direct journal APIs retain their separate semantics. A fresh
confirmed placement can legitimately reach existing journal pending/report/complete
states if an authorized external fixture/operator supplied that file lifecycle;
ingress itself does not create that recovery procedure.

Placement and admission are not one transaction. SIGKILL after confirmed placement
but before journal.next leaves a file without admission; SIGKILL/persistence or
response failure after journal writes may leave an unresolved pending effect with
no returned intent. Resubmission still stops at the pre-existing file, preserving
both namespaces and any stale journal evidence. A visible nlink1 unknown candidate
may remain A8-readable/A1-valid/A2-eligible to separate direct journal code. This
coordinator's confirmed-only rule is not a universal admission fence or a claim of
global exactly-once execution. Synchronous syscalls/crypto may stall, and revocation
is not transactionally atomic across components. Same-UID malicious code is outside
this trusted local composition boundary.

Offline tests cover real sequencing and exactly-one calls, raw/config safety and
snapshot mutation, actual A1 rejection, A9 write/link/unlink/sync/readback faults,
current policy/file rechecks, sanitizer failures, concurrent identical ingress and
placement/journal/response SIGKILL splits. The separate pinned integration path
uses actual Gateway A2 provider/A6 writer; standalone policy DTOs are explicitly
fixtures. Existing direct A1–A9 conformance and historical receipt tests remain.
Run the unchanged exact-head harness for Gateway check/full tests/build and full
orchestration with zero integration skips; ordinary runs report disconnected
integration skips separately and honestly.

Actual local invocation still needs owner acceptance of disjoint namespaces/UID,
installed immutable code/source bindings, input custody/transport, storage capacity,
quota/retention and split-outcome investigation. No such live value, service or
activation is selected here. H1–H9 remain live NOT_READY; #21 isolation and #11 Ready
workflow remain separate. Source rollback removes coordinator/new tests and reverts
integration/docs only; preserve all operational event/journal/receipt evidence and
jobs authority. Never remove an orphan file/stale lock or invent fallback authority
as part of rollback. Ready, approval, merge, deployment, runtime and credential
changes are outside this implementation slice.
