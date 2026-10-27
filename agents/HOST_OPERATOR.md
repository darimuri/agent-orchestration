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

## A11: process-free detached HEAD pointer observer — live NOT_READY

`host-operator-auth/revision-source.mjs` exports
`createDetachedRevisionObserver({sourceDirectory, uid, source, clock?, monotonic?})`
with frozen `{observe()}`. This is a read-only observation primitive for one trusted
constructor-selected source, with no import-time observation, CLI, listener,
subprocess, Git invocation, environment/config discovery, operation registry,
executor, journal access, receipt generation or integration wiring.

Construction rejects nonordinary/proxy/accessor/symbol/unknown configuration and
snapshots the existing protocol `binding(source)`. The actual ordinary Linux UID
must match `uid`. `sourceDirectory` must be a bounded canonical absolute path, not
an argument to `observe`. Each `observe()` accepts zero arguments, freshly checks
the existing source/ancestor and literal `.git` directories, anchors both source
and `.git` with no-follow/nonblocking directory descriptors, and opens only the
fixed `.git/HEAD` file. No directory/ref/object/config/alternate search is provided.

Directories/ancestors must be root/configured-UID owned, without group/other write
or special mode bits; only the existing sticky-root `/tmp` disposable fixture
exception applies. HEAD follows the approved same-ordinary-UID handoff: regular,
single-link, same-device as the anchored `.git`, with no group/other write or
special bits. Non-secret source metadata0600/0644 is supported; protected0755
source/metadata directories are also supported. These are source metadata rules,
not a relaxation of the private0700/0600 event/ledger/journal rules elsewhere.
No mkdir/chmod/chown, source repair or permission adoption is performed.

The one positional read is bounded to **42 bytes** and accepts only exactly40
lowercase ASCII hexadecimal bytes, optionally followed by one LF. Root/metadata
named and held descriptors, file named/opened metadata, owner/mode/device/link/
size/time fingerprints and canonical ancestry are checked before/after reading.
Observed metadata changes, short/overrun reads, substitutions, symlinks, gitfile/
worktree indirection, bare/missing layout, symbolic `ref:` HEAD, uppercase SHA,
CRLF/multiline/BOM/arbitrary text and I/O/close failures deny. No symbolic reference
or packed-ref resolution, Git command or fallback to configured expectedSha occurs.

A successful bounded public result contains only:

```json
{"status":"observed","repository":"test-org/project","workspaceId":"pointer-fixture","expectedSha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observedSha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observedAt":1800000000000}
```

`observed` means the actual detached pointer equals trusted `source.baseSha`;
`mismatch` returns the actual different valid pointer with the same expectedSha.
This is a **HEAD POINTER ONLY** observation. A synthetic pointer to a nonexistent
object can be observed: it does not prove commit/object existence, tree hash,
worktree cleanliness, repository origin, dependency/install integrity or actual
sourceDigest correspondence. Logical repository/workspace fields are constructor
mapping, not discovered Git facts. No PASS/READY/completed/execution receipt or
current-policy verdict follows. Returned data cannot itself authorize dispatch or
satisfy the journal's independent receipt authority.

Every invocation reopens/rechecks; there is no byte/verdict/error cache. Invalid,
backward or nonfinite clock readings and observed elapsed wall/monotonic time over
**100ms** deny. `observedAt` is an integer from the final checked wall reading.
The budget cannot interrupt a stalled synchronous syscall and does not enforce the
registered5000ms whole-operation executor limit. External changes after the final
check, malicious same-UID/host-admin writers and ABA/atomic revocation protection
remain outside this local boundary. No child process is started; that does not
establish a generic executor termination proof.

Invalid/unavailable/unsupported reads and constructor failures throw only fixed
`revision_source_denied` code/message/stack. Raw HEAD/error text, private paths,
sourceDigest and other unverified source details are never returned. Tests use
synthetic protected directories, actual reads/mismatch/rereads, unsafe layouts and
metadata, positional-read/directory races, clock/I/O/close faults and canaries.
No actual installed source or host inventory is selected by these tests.

The unchanged full pinned harness remains regression acceptance with zero
integration skips; ordinary disconnected skips are reported separately. A1–A10,
registry/protocol/journal/receipt/Gateway/dependencies/harness stay unchanged.
A future authorized consumer still needs exact pending-intent identity/current
policy, observation-to-native-receipt binding and unknown/retry discipline. Actual
source selection/UID/protected access/immutable installation/storage and consumer
wiring require separate owner acceptance. All live H1–H9 remain NOT_READY;
#21 isolation and #11 Ready workflow remain separate.

Source rollback removes the observer/new tests and this section only, preserving
real source/event/journal/receipt bindings and jobs authority. A future consumer
must stop on observation failure, never echo expected SHA or manufacture a receipt.
No operational rollback, deployment, runtime, credentials or live path mutation is
part of this slice.

## A12: non-consuming pending revision observation — live NOT_READY

`HostOperatorJournal.inspectPendingExecution(request, {intentId, intentDigest})`
is an additive inspection API. It hardens bounded own primitive data before the
existing request/descriptor/JSON helpers, then reauthenticates outside and inside
the existing exclusive journal lock. The full stored state is validated by the
existing lock path. The exact existing request hash, descriptor and stored identity
must match current authorization; the last effect must be an unreceipted execution
for `status.revision`/`read_only` with no user action, matching ID/digest and an
unexpired deadline. Clocks are rechecked after policy and must not reverse.
Missing/consumed/report/user/conflicting/expired execution is never authority.

The result is a detached copy `{intent, intentDigest}` of the actual pending effect.
It creates no entry/intent/reservation/receipt, calls no persistence callback, and
never rewrites `state.json` or advances sequence. Existing schema, `next` and `record`
semantics are unchanged. **State-read-only is not filesystem-side-effect-free:**
inspection creates, syncs and removes the normal `journal.lock`; death or unlink
failure can leave a stale lock. Existing unresolved-temp/stale-lock refusal stays
intact, with no automatic cleanup/adoption. All inspection failures throw fixed
`pending_execution_denied` code/message/stack, including authorization/storage/lock
failures; denial is not a claim that a transient lock was never created.

`host-operator-auth/revision-observation.mjs` exports
`createRevisionObservationBridge({eventDirectory,journalDirectory,sourceDirectory,
uid,ownerPubkey,requesterId,mentionPubkey,targetPubkey,channelId,threadId,source,
currentJob,verifyReceipt,clock?,monotonic?}) -> frozen {observe(raw, expected)}`.
Construction fixes canonical existing protected, distinct, non-nested roots and
ordinary actual UID, snapshots own configuration/source and requires the existing
trusted host seams. Event/journal private0700 and A11 source-mode rules are kept.
There is no injected observer/journal/handler or request-controlled path, environment,
argv, registry, command, process, transport, service or live configuration discovery.
`verifyReceipt` is required for the real journal but is not called by this bridge.

`observe` takes exactly one bounded detached serialized raw event and the exact
`{intentId,intentDigest}` data pair. It uses actual A1 to derive the request; raw
objects, proxies, shared/extended/getter Buffers, BOM, extra arguments and malformed
or oversized data deny. The event must already be safely placed and pending work
must already exist: this bridge calls neither placer/ingress nor `next`/`record`.
Actual A8 and the actual A1 authorization adapter, with mandatory currentJob policy,
remain the journal authority on every inspection.

Sequence is **actual inspection → actual A11 observer once → actual inspection**.
Each inspection independently checks policy before/under lock. No journal lock is
held across source observation. The second check must still find the same pending
request/intent/digest before deadline. Observation fields/time/source/expected SHA
are normalized against the pinned context and final clock. Removal/replacement of
the signed event, policy revocation or a genuine receipt recorded during the source
read suppresses output. The earlier read happened; suppression does not undo it.

A bounded result (<=4096 bytes) contains status `observed` or `mismatch`, intentId,
intentDigest, requestHash, descriptorDigest and the normalized actual A11 observation.
This is **HEAD POINTER ONLY**, with the same object/tree/dirty/origin/sourceDigest/
install-integrity limits as A11. It contains no PASS/READY/completed/native receipt,
raw event/signature/private path/callback text/private administrative digest. All
bridge constructor/call failures throw fixed `revision_observation_denied`
code/message/stack; a failed final check never returns a stale successful observation.

This API is explicitly **non-consuming**. Repeated and concurrent authorized calls
may repeat a read-only observation. Pending execution and its receipt stay unchanged;
direct `next` still reports pending `outcome_unknown` until a separate genuine
receipt is recorded. Inspection/observation/signature/policy results cannot satisfy
`record`'s independent completion evidence. Historical receipt reconciliation stays
with that separate API. No claim, scheduler, automatic retry/resume, receipt creation,
execution completion or native reporter is added.

Two checks narrow observed races without creating a transaction across source,
policy and released locks. A final-check revoke/ABA/same-UID writer or later change
remains outside the guarantee. A11's observed100ms read budget cannot preempt a
blocked syscall or enforce the registered5000ms whole-operation limit; the bridge
checks the stored execution deadline but cannot interrupt synchronous I/O. No global
exactly-once execution or universal admission/durability fence is claimed.

Tests use actual ingress/journal/authorization/A11 against protected fixtures and
actual pinned Gateway provider/A6 writer integration. They check state bytes/mtime/
sequence/receipt preservation, transient lock behavior, both inspection auth checks,
real mismatch, missing/forged/consumed/expired work, raw/config hardening, source and
storage failures, receipt/event/revocation races, concurrent non-consuming reads and
SIGKILL stale-lock preservation. Existing journal death/ENOSPC/receipt suites remain
regression coverage. The unchanged pinned harness requires zero integration skips;
ordinary disconnected skips are recorded separately.

Actual disjoint namespaces/UID/protected access/current policy integration/input
custody/immutable installation/storage/capacity/recovery and later consumer/receipt
protocol still need owner acceptance. H1–H9 live NOT_READY; #21 isolation and #11
Ready workflow remain separate. No live paths, privileges, runtime, credentials or
Gateway/dependencies are changed. Source rollback removes the additive inspector,
bridge/new tests and integration/doc additions only; preserve real schema/state/
intents/receipts/source mappings. Future callers fail closed rather than trust
serialized intent JSON, reset a journal, switch namespace or clear stale locks.

## A13: one-shot new-event revision invocation — live NOT_READY

`host-operator-auth/local-invocation.mjs` exports
`createLocalRevisionInvocation(options) -> frozen {invoke(raw)}`. This is a local
library composition of actual A10 admission and actual A12 pending observation.
There is no installed command, listener, transport, service, dispatcher, executor,
registry, native publisher or receipt endpoint.

Options are exactly A12's trusted fields: eventDirectory, journalDirectory,
sourceDirectory, uid, ownerPubkey, requesterId, mentionPubkey, targetPubkey,
channelId, threadId, source, currentJob, verifyReceipt, optional clock/monotonic.
Own ordinary configuration and source are snapshotted; proxies, getters, symbols,
unknown fields and injected ingress/observer/journal/context are refused. The
required currentJob and verifyReceipt host seams remain unchanged. Actual A12 is
constructed **before** actual A10, validating protected disjoint/nonnested source,
event and journal namespaces before any admission. Construction creates no event,
intent or HEAD observation. No environment/argv/default policy discovery occurs.
The two components share one selected nondecreasing wall clock; existing component
read budgets remain independent, with no aggregate hard timeout.

`invoke` accepts exactly one raw string or ordinary non-shared Buffer, detached
once before any trusted callback, 1..16384 bytes. Both stages receive that same
private snapshot (their existing internal defensive copies remain). No caller
intent, parsed request, verified context, path or resume option exists. Input
brand/size/Unicode/BOM or constructor failures throw fixed
`local_invocation_denied` code/message/stack. Malformed signed content is rejected
by actual A10/A1, without duplicating the signed-event parser or authority engine.

Actual ingress is called once. Only this call's newly returned `intent`, step
`execution`, with exact registered `status.revision`/`read_only`/no-user-action
source descriptor, digest and timing shape can advance. Expected intentId/digest
come exclusively from that return. These DATA checks confer no authority: actual
A12 independently rechecks event, current policy and real pending state before and
after actual A11's source read. The bridge is called once, with no outer journal
lock; existing A10 and two A12 inspection locks retain separate lifetimes.

Bounded (<=8192 bytes), recursively frozen results contain only allowlisted fields:

- `{status:'observed'|'mismatch', admittedIntent:{intentId,intentDigest},
  observation:<actual normalized A12 bridge result>}`.
- `{status:'not_observed', stage:'admission', code:<fixed code>}` for every other
  ingress result. Known codes include ingress_denied, placement_unconfirmed,
  placement_conflict, placement_denied, admission_denied, request_conflict,
  workspace_busy, journal_locked, journal_full, host_preparation_required,
  outcome_unknown, complete and nonexecution_intent. Unexpected/malformed or
  uncertain journal results use admission_unconfirmed. No underlying error or
  public execution receipt is projected.
- `{status:'not_observed', stage:'observation',
  code:'revision_observation_denied', admittedIntent:{intentId,intentDigest}}` after
  a positively returned execution intent, including bridge/result validation faults.

**Partial progress is durable.** `not_observed` never means that no event or intent
was persisted. Observation failure never rolls back/unlinks admission, resets the
journal, switches namespace, calls next again, records a receipt or retries. A
second invocation of already placed raw input stops at placement_unconfirmed,
including after restart/crash. It never adopts a pending event or resumes A12.
Existing unknown/blocked/complete/report/nonexecution outcomes stop before source
observation. The separate explicit A12 API retains its documented authorized,
non-consuming behavior; this coordinator adds no resume entry point.

An admittedIntent only identifies an earlier returned intent. It does not assert
that the intent remains pending at response time. Legitimate concurrent receipt
recording can suppress observation or finish independently after the final check;
the coordinator never undoes it. No observation constitutes execution success,
completion, receipt, PASS or READY. The actual HEAD pointer may refer to a missing
object; object/tree/dirty/origin/install/sourceDigest integrity is not proven.
Mismatch grants no permission to checkout or repair anything.

A local in-flight guard rejects same-instance callback reentrancy, throws the fixed
input error and clears in finally. This is no cross-process claim, scheduling,
queue, retry or exactly-once guarantee. Separate journal lock/temp failures remain
conservative, including stale locks after death, with no cleanup/adoption. Existing
same-UID trust, final-check/ABA/later mutation, synchronous syscall stalls and A11
observed100ms/component budgets remain limitations; neither source nor policy is
transactionally frozen across the two released locks. Actual host installation,
caller/input custody, policy wiring, namespaces, UID and storage still require
owner acceptance. H1–H9 live remain NOT_READY; #21 isolation and #11 Ready workflow
remain separate.

Tests use the actual chain and protected ordinary-UID disposable fixtures, with
standalone DTO policy/receipt authorities explicitly marked. Pinned integration
uses actual Gateway provider and writer. Coverage includes one next/one HEAD read,
no held journal lock over HEAD, state bytes/mtime/effect/receipt preservation,
mismatch, no-resume/busy workspace, raw/config mutation, reentrancy, revoked policy,
expiry, event/receipt changes between stages/during source read, storage/clock and
ENOSPC faults, malformed result projection, and SIGKILL after placement/admission/
inspection/HEAD. Instrumentation wraps real methods for fault injection, never
replaces authority with canned observation success. Full Node and unchanged pinned
harness counts are reported per exact head, with ordinary integration skips separate.
Source rollback removes only this API/new tests and integration/doc additions;
preserve already created events, journal state, intents and receipts. No schema
migration or operational rollback is supplied.

## A14: explicit non-consuming observation resume — live NOT_READY

The same trusted `createLocalRevisionInvocation(options)` factory now returns
frozen `{invoke(raw), resume(raw, locator)}`. `invoke` retains the A13 new-event-only
path and result semantics: existing placement never automatically resumes. The
additional method is one explicitly requested read-only attempt, not a recovery
worker, admission fallback, discovery API, result store, capability token or CLI.
Constructor options and actual bridge-first source preflight remain unchanged.

`resume` accepts exactly two arguments. Raw uses the same strict detached
1..16384-byte string/ordinary non-shared Buffer boundary. Locator is exactly own
bounded primitive `{intentId,intentDigest}` using existing identifier/hex rules.
Both are snapshotted **before any trusted clock/provider callback**. Whole A13
results, receipts, observations, policy DTOs and parsed verified contexts are not
locators; proxies/getters/symbols/exotic inherited data/extra fields/Promise and
oversized data are refused without evaluating getters or unsafe JSON first.
Input/arity/reentrancy errors throw fixed `local_invocation_denied`
code/message/stack, preserving the existing input failure boundary.

Locator is untrusted lookup data, not authority or proof of admission. Actual
`verifyOwnerEvent` derives the request under fixed owner/target/channel/thread/
source and the selected current clock; its normalized request hash correlates the
output. This signature check does not grant pending execution authority. The
already constructed actual A12 bridge observes once with that same raw snapshot
and locator, re-verifying signed event, current policy and actual existing pending
state before/after A11's source read. The existing observation projection retains
invoke's ID/digest/request/descriptor/source correlation checks unchanged.

Success uses the existing recursively frozen <=8192-byte observed/mismatch envelope
with admittedIntent and normalized actual A12 observation. It identifies previously
admitted work, not new admission or a guarantee of current pending state at response
time. A valid-shaped input that fails signature, policy, pending, observation or
projection checks returns ONLY
`{status:'not_observed',stage:'resume',code:'revision_observation_denied'}`.
There is no locator/admittedIntent echo on failed resume because this call did not
establish an earlier admission, and no complete/report/receipt payload or underlying
error is returned. Concurrent legitimate changes are not asserted absent.

Resume calls no ingress, placer, next, record, persistence callback or receipt
verifier. Actual A12 still requires the existing trusted verifyReceipt dependency;
no fabricated positive authority replaces it. No event, intent, sequence, effect,
reservation, timestamp renewal, schema or state format is created. Existing
state.json bytes/mtime stay unchanged unless another legitimate writer changes it.
A12's two transient inspection locks remain separate, with no outer lock or lock
held across HEAD. Non-consuming is not filesystem-side-effect-free; death may leave
a stale lock. No stale lock/temp deletion, cleanup, reset or namespace switch occurs.

The original status.revision execution deadline remains **5000ms from its original
creation**. Resume must pass A12's initial and final pending/deadline checks before
that same deadline. A fresh factory/restart never renews it. This API cannot rescue
expired work or stale locks. If the locator was lost, it does not discover one by
job/event or read raw journal state to mint another; separately authorized
investigation is required. A placement-only crash without pending work cannot
resume. Retained raw/locator and same trusted namespace/current policy can be
explicitly submitted after restart only while the original pending remains valid.

Both methods share the same local in-flight guard and finally release. Cross-method
or same-method reentry fails before a second side effect. No queue/timer/automatic
retry/scheduling, cross-process claim or exactly-once guarantee is introduced.
Repeated explicit valid resumes may reread HEAD, without consuming execution or
creating completion evidence. Result output cannot satisfy independent real record
receipt authority. Genuine concurrent receipt recording is never rolled back.

Missing/forged/consumed/report/user/complete/expired state, revoked policy, missing
or substituted event, unsafe source, corrupt state, temp/lock or I/O faults fail
closed. A legitimate receipt, revoke, event change or deadline crossing during
source read can suppress the final output. Before/after checks remain nontransactional;
final-read/ABA/later changes, accepted same-UID shared-admin trust, host rollback and
non-preemptible synchronous syscall limits remain. Component observed100ms budgets
are not hard aggregate timeouts. HEAD pointer remains pointer-only, not proof of
object existence/tree/dirty/origin/install/sourceDigest integrity or authority to
repair/check out a mismatch.

Tests exercise actual partial A13 admission -> explicit resume, unchanged state and
original deadline, repeated/new-factory reads, no admission/record/receipt verifier,
two locks/one HEAD/no held source lock, verifier correlation and immutable results.
Standalone DTO/receipt policy is explicitly fixture-only; pinned integration uses
actual Gateway provider/writer. Negative coverage includes caller data mutation in
clock/provider callbacks, context/locator/authority substitution, current revoke,
receipt/event races, expiry/restart, corrupt/temp/stale storage, ENOSPC/open/sync/
unlink/clock faults and SIGKILL during inspection/after HEAD. Existing invoke
regressions stay intact. No test result is live acceptance.

All H1–H9 live remain NOT_READY. Actual installed provenance/UID/namespaces/storage/
current policy and signed raw/locator custody still need owner acceptance. No new
bootstrap/transport/service/executor/Gateway/dependency/live path or operational
activation exists; #21 isolation and #11 Ready workflow remain separate. Source
rollback removes this additive method/tests/docs while preserving invoke and all
already-created events/intents/receipts/state. Callers must fail closed when resume
is absent; never fall back to re-admission, another namespace or automatic repair.

## A15: restricted completion verification and opt-in reservation release — live NOT_READY

`host-operator-auth/revision-completion.mjs` exports
`createRevisionCompletionVerifier({source,authorityId,resolveCompletion,clock?})`.
The returned synchronous `verify(evidence,intent,{request,identity})` fits the
existing trusted verifyReceipt contract. Source, opaque authorityId and resolver
are fixed trusted constructor inputs. There is no default issuer, file/store,
provider, environment/module loader, executor or bootstrap. This module verifies
independently supplied terminal evidence; it does not produce that evidence.

Caller evidence is only exact own bounded `{ref,digest}` (identifier and 64 lowercase
hex). The verifier hardens and detaches caller evidence, intent and context before
JSON helpers or trusted callbacks. It rejects proxies/getters/symbols/extra fields,
exotic data, Promises and oversized input. `resolveCompletion(ref)` must independently
resolve retained historical positive evidence, not echo caller JSON or derive
termination from observation, a signed request, current policy, locator, receipt
outcome, timeout, cancellation or elapsed deadline. The trusted resolver must have
its own bounded execution/evidence provenance. Synthetic proof maps in tests are
explicit independent fixture authorities, not deployed issuers or termination proof.

The exact <=8192-byte attestation v1 shape is:
`{version:1,type:'host-operator.revision-completion',authorityId,completionId,
requestHash,intentId,intentDigest,descriptorDigest,startedAt,finishedAt,outcome,
execution,resultDigest,summary}`.
Execution is exactly `{kind:'in_process_read_only',settled:true,descendants:0}`.
Only success/failed outcomes for the registered status.revision/read_only/no-user-
action execution are accepted. Request/context/authorization event, descriptor/
source/workspace/base/sourceDigest/registry and exact execution intent are correlated.
Intent sequence is zero and its original registered5000ms deadline must match.
Caller digest must equal the existing canonical digest of the detached attestation.

`startedAt >= intent.createdAt`, `finishedAt >= startedAt` and `finishedAt <=` trusted
current time. Success must positively attest a finish **before** the original
deadline, even if recorded historically after expiry. A positively proven settled
failed attempt may finish after that deadline. Expiry never supplies finish evidence
or permits new work. Nondecreasing trusted clock checks surround resolution.
For this non-test in-process operation summary must be exactly
`{passed:0,failed:0,skipped:0,exitCode:null,signal:null}`; no invented test counts,
child exit code or signal is accepted. A pointer mismatch does not by itself decide
completion outcome. `resultDigest` identifies a retained actual bounded run result;
it is not standalone proof of its contents or installed integrity.

The normalized existing-schema receipt uses receiptId=completionId, exact intent/
request digests, step=execution, attested outcome/finishedAt, evidenceRef=ref and
evidenceDigest=digest(attestation), with that zero/null summary. Existing receipt
validation also runs. The receipt remains detached. Verifier constructor/call errors
have fixed `revision_completion_denied` code/message/stack, without underlying
proof, callback error, canary or private path. Normal journal record errors retain
their existing receipt-invalid/conflict/storage boundaries.

`HostOperatorJournal` adds an OPTIONAL trusted constructor hook
`verifyRevisionCompletion`. Missing preserves the old reservation behavior exactly;
non-functions are refused. For restricted wiring, an owner-selected verifyReceipt
dispatcher routes status.revision execution to the actual new verifier and report/
user receipts to separate independent authorities (or denies them). Configure the
same restricted verifier as verifyRevisionCompletion. No always-positive adapter,
caller callback or raw observation is a completion authority.

`record` remains the sole receipt persistence/reconciliation API, with unchanged
schema, return shape and historical semantics. It resolves the independent evidence,
validates and durably persists the normalized execution receipt first. Same-proof
reconciliation on the current effect is idempotent; conflicting normalized receipts
deny. Timeout/cancelled still return termination_unproven and never persist a receipt.
No native publisher or receipt producer is introduced, and execution record returns
recorded, not lifecycle complete.

Only competing **new entry** admission uses the new reservation predicate. Completed
lifecycles release as before. Every other entry holds by default. An opt-in candidate
must be status.revision/read_only/no user action, contain exactly one execution
effect and have a persisted success/failed execution receipt. Under the existing
journal lock the predicate reconstructs `{ref:receipt.evidenceRef,
digest:receipt.evidenceDigest}`, re-verifies against the actual stored execution
intent/request/identity, runs existing receipt validation and requires exact digest
equality with the persisted normalized receipt. Only that matching independently
resolved proof permits ignoring this entry for execution job/workspace reservation.

Missing/revoked/unavailable/invalid/conflicting proof, generic stored success without
independently resolving restricted authority, pending/needs_user/timeout/cancelled,
report-only or other operations continue to hold. No persisted release flag or
migration is added. Same request replay never re-executes: its next step remains
Kaneo then Buzz with fresh authorization and separate genuine native receipts.
Old task/thread/mention/result/report payloads stay bound to the original request,
even if a second authorized execution is pending. Report obligations, replay history,
128-entry/1MiB bounds and archival needs remain. Reports are not silently delivered,
deleted or bypassed, and execution proof cannot verify a report step.

Record proof resolution/persistence and new admission proof revalidation use the
existing global lock. New admission either sees a pending effect and blocks, or a
persisted matching receipt and may proceed. No new outer lock, HEAD observation,
process, automatic retry or recovery discovery occurs. Stale lock/temp artifacts
remain refused. Restart requires the same namespace/source and retained independent
proof; if authority disappears, future admission may conservatively hold again. It
does not revoke an already-issued new intent or reset old entries. A persistence
error is not a release acknowledgement: actual durable state plus revalidated proof
control a later admission. Lost-response reconciliation remains explicit record.

The trusted producer must positively establish that the bounded synchronous attempt
has settled with zero descendants capable of workspace mutation. This PR supplies
no actual producer/OS quiescence mechanism. Callback stalls are not preemptible, and
shared-UID/final-check/ABA/source-policy/host rollback limits remain. Historical proof
does not replace current authorization for a new execution or report; original
invoke/resume/non-consuming behavior and execution5000ms deadline are unchanged.

Tests cover actual receipt persistence and restricted revalidation before a second
execution, opt-in versus unchanged default behavior, report ordering while newer
execution remains pending, duplicate/conflicting/unavailable proofs, original/late
failure timing and historical auth expiry, issuer/request/descriptor/effect/result
bindings, input/proof hardening, zero-descendant/settled semantics, generic receipt
refusal, lock serialization, persistence faults and SIGKILL before/after temp/rename/
directory sync. Pinned integration uses actual signed ingress/current Gateway policy
and writer, while terminal/native receipt authorities remain explicitly synthetic.
Existing invoke/resume/receipt/journal tests stay regression coverage. Exact-head
full suite/pinned harness counts are reported with ordinary skips separately.

All H1–H9 live remain NOT_READY, especially actual H8 producer/termination/native
report evidence. No install/bootstrap/CLI/service/executor/issuer implementation,
raw/locator/result recovery store, schema migration, dependency/Gateway/runtime/
credential/live path or operational activation changes. Before real wiring the
owner must accept producer identity/provenance/retention/storage/termination and
installed host facts; no deployed values are invented here. Rollback disables/removes
this opt-in hook and reverts source/tests/docs; unchanged stored receipts/schema stay
readable and incomplete lifecycles conservatively hold as before. Preserve all
already-admitted work/state/receipts; disabling cannot undo a previously issued new
execution. No namespace reset or operational rollback is supplied.

### A16 supervised revision source and fixture evidence (not installed)

A16 supplies one fixed `status.revision` producer conditional on an owner-trusted
supervisor. It does not supply a production supervisor, cgroup backend, configuration
loader, public CLI, installer, service or live activation. H1–H9 remain NOT_READY.
The fixture supervisor runs a real fixed child and observes its close/reap event;
its no-escape, sealed and empty-boundary assertions are **synthetic**. These tests
are not host/kernel/cgroup quiescence acceptance.

`createSupervisedRevisionIssuer(options)` returns frozen `{issue(raw, locator)}`.
`issue` is async; the only request inputs are signed raw bytes (1–16384) and exact
`{intentId,intentDigest}` lookup data. They are detached before trusted callbacks.
The constructor requires the existing fixed event/journal/source paths, ordinary UID,
owner/requester/mention/target/channel/thread/source bindings and actual `currentJob`,
plus `evidenceDirectory`, `authorityId`, `issuerArtifactDigest`,
`workerArtifactDigest`, `clockId`, `supervisor` and `settlementWaitMs` (1–60000).
Optional `clock`/`monotonic` are fixed owner-trusted providers. No construction values
are discovered from request JSON. Issuer and worker pins must match their actual
fixed source bytes; runtime/dependency inventory remains a future supervisor and
host acceptance obligation. Source/event/journal/evidence roots must be protected,
canonical, distinct and nonnested. The factory installs nothing.

Actual owner-event verification, file event resolution, current authorization and
A12 pending inspection derive the existing revision intent and original 5000ms
deadline. The inspector has a deny-only receipt verifier. No admission, raw placement,
observation adoption, record, release or reporting occurs inside the issuer. A durable
exclusive intent claim precedes a second authorization/pending inspection. Any claim
prevents reexecution, including crashes and prelaunch failures. Reentry/concurrent
calls on an instance fail closed; independent instances serialize through custody.
There is no retry, discovery, stale-lock cleanup, claim reset or deadline renewal.

The mandatory supervisor is exactly `{run(spec)}`. There is no default simulated or
production backend. Its async port receives an immutable issuer-built specification:
fixed `process.execPath` and repo-owned worker entry; canonical private input containing
only source path/UID/source binding, run nonce/request/intent digests and the parent's
wall sample; fixed LANG/TZ environment; input8192/stdout4096/stderr4096 limits; worker
artifact/clock/run binding, original deadline and bounded settlement wait. No inherited
credential/config/NODE_OPTIONS environment, caller argv/cwd/shell, raw event, ledger
or callbacks are passed. The worker uses the actual A11 detached HEAD observer once,
without Git, shell, subprocesses or network. Its observation timestamp is anchored
to the parent's supplied sample; it is result data, never completion-time authority.
A11's independent elapsed read budget still applies. Results remain pointer-only:
no object/tree/dirty/origin/install/sourceDigest integrity claim is implied.

The port returns bounded exact `{status:'settled',boundary,stdout,stderr}` or an
unconfirmed result. It owns launch/output/deadline stop, actual artifact/runtime
verification, containment-before-operation, dedicated never-reused boundary identity,
no escape/reattachment/untracked descendants, reaping and positive terminal emptiness.
Leader exit, EOF, kill request, timeout or populated=0 alone is insufficient. A future
backend must substantiate every boundary assertion against actual kernel evidence.
No journal or evidence lock is held during supervisor/worker execution. Journal→
evidence resolution under record/admission is allowed; evidence code calls no journal
or policy callback under its lock, avoiding inverse lock order.

Boundary v1 is exact `{version,runId,boundaryId,requestHash,intentDigest,
workerArtifactDigest,clockId,startedAt,leaderExitedAt,settledAt,leaderReaped,noEscape,
sealed,populated,exitCode,signal}`. It requires reaped/noEscape/sealed true, populated0,
ordered times and either exitCode0–255 with null signal, or null exitCode with
SIGTERM/SIGKILL. The issuer binds it to the claimed run/request/intent/worker/clock
and parent-observed interval. Wall and monotonic reversals deny. Success requires
normal exit0, a bounded actual observed/mismatch result, and final real authorization/
pending verification before the original deadline (also bounded by monotonic elapsed
time). SHA mismatch is a successful completed observation. Parent `finishedAt` follows
settlement/final verification; storage durability can finish later without renewing it.

Positively settled nonzero/signal/protocol/output failure, late completion or denied
final postcondition produces only a fixed failed result with code `worker_failed`,
`output_limit`, `deadline_exceeded` or `postcondition_denied`; it suppresses SHA and
stderr. Failed proof may finish late. Unproven settlement, escape/live descendants,
unreaped worker, attribution/provenance/clock failure or wait expiry returns frozen
`{status:'unknown',code:'issue_unconfirmed'}` and publishes no completion proof.
Late supervisor resolution has no background publication continuation. The supervisor
still owns containing/stopping its run. Unknown publication means writes may have
happened; it never asserts rollback or that no artifact exists.

Confirmed issuance returns frozen `{status:'issued',outcome,evidence:{ref,digest}}`.
The caller must explicitly compose independent resolution, verification and the
existing journal record; issuance itself leaves journal bytes/mtime untouched.
Successful result is the exact A11 observation plus runId/requestHash/intentDigest;
failed result is exact `{status:'failed',code,runId,requestHash,intentDigest}`.

New proof version2 retains type `host-operator.revision-completion` and v1 fields,
adding `issuerArtifactDigest` and `clockId`. Its execution is exactly
`{kind:'supervised_process_v1',settled:true,descendants:0,runId,boundaryId,
boundaryDigest,workerArtifactDigest}`; completionId=runId. Result and boundary hashes
are transitive proof-root bindings. Summary remains zero counts/null exit/null signal;
actual terminal status lives in the boundary, not fabricated test receipt fields.
The normalized execution receipt remains the existing v1 schema.

`createRevisionCompletionVerifier` accepts optional exact
`supervised:{issuerArtifactDigest,workerArtifactDigest,clockId}`. Default remains v1
only. v2 additionally requires the actual evidence store's independently branded
resolver with matching source/authority/artifact/clock pins; a generic callback that
returns loose v2 proof JSON cannot substitute for complete retained bundle validation.
Explicit opt-in preserves exact v1 `in_process_read_only` behavior, never relabels v1,
and rejects unknown kinds/versions or inconsistent source/request/intent/time/result
bindings. Wire the same extended verifier to execution `verifyReceipt` and
`verifyRevisionCompletion`; report steps still need separate genuine authorities.
The unchanged record durably persists normalized receipt before later admission
revalidates it. Existing Kaneo→Buzz obligations, invoke/resume and historical semantics
remain unchanged. Expired authorization may reconcile historical proof but cannot
admit a new effect or report without fresh authorization.

`createRevisionEvidenceStore({directory,uid,source,authorityId,issuerArtifactDigest,
workerArtifactDigest,clockId})` privately returns `reserveAttempt(binding)`,
`publish(handle,bundle)`, synchronous `resolveCompletion(ref)`. Preexisting root,
`claims` and `objects` require0700; files require0600/same UID/one link. Canonical
paths/ancestry, no-follow opens, inode/size/time stability and bounded fatal UTF-8
canonical JSON readback are checked. No request surface exposes publication or
arbitrary authority JSON ingestion. No raw event/locator recovery or enumeration API.

Claims `<intentDigest>.json` contain only version/runId/intentDigest/requestHash/
descriptorDigest/deadline/issuerArtifactDigest. Private handle identity is required to
publish; copy/forgery fails. Objects `<proofDigest>.json` contain exact
`{version:1,proof,result,boundary}` bundles (32768 maximum; proof8192/result4096/
boundary8192). Ref and digest both equal canonical protocol digest(proof), not the
bundle byte hash. Duplicate/trailing/noncanonical JSON and inconsistent hashes deny.
Cooperating owner immutability uses a durable exclusive evidence.lock, exclusive temp,
write+file fsync+rename+parent/root fsync+full readback, then unlock+root sync. Existing
objects are never overwritten; identical trusted publication must match the original
claim and bytes. Stale locks/unresolved temp deny independent resolution, including
renamed but unconfirmed publication. Errors retain conservative artifacts; an unlock
parent-sync failure may occur after durable publication and lock removal, so explicit
historical resolution can still confirm those bytes. No automatic repair is supplied.
This is not a hostile same-UID no-replace CAS or global exactly-once guarantee.

At most128 claims,128 objects and4MiB object bytes are retained per namespace; a full
store denies, never evicts. Retain claims/bundles/results/boundaries while execution,
reporting or replay obligations remain. There is no GC, store reset or namespace
switch procedure. Missing/corrupt/unavailable retained proof can conservatively hold
future reservation release again; it cannot revoke a newly admitted intent.

Focused tests cover actual child correlation and explicit record/release, v1/v2
confusion, match/mismatch, current-policy changes/deadlines, unproven descendants/
escape/reap, clock/attribution failure, timeout/no late publication, bundle custody/
restart/corruption/capacity, claim no-reexecution and lock serialization. Persistence
faults include ENOSPC/EIO/fsync/rename/readback/unlock and SIGKILL claim/publication
split points. Pinned integration exercises actual writer/A1/A2/journal composition.
Exact committed/published-head full Node and unchanged pinned Gateway check/test/build
with zero integration skips are reported separately from ordinary integration skips.

Future host acceptance still needs actual cgroup boundary/containment/reap/empty
proof, pinned runtime/dependency inventory, real paths/providers/clock and protected
mount/quota/durability/retention evidence. No production backend, native reporting,
Docker/Compose/root-host acceptance or operational activation is claimed. Same-UID
admin tampering, hidden ABA, host rollback, uninterruptible I/O and clock/callback
stalls remain. Rollback disables the supervised opt-in/caller, preserving all claims,
bundles and journal receipts. Old code rejects v2 and may conservatively re-hold
reporting-incomplete entries. Disabling cannot undo already-admitted execution;
no cleanup/reset/reissue or live rollback is supplied.

### A17 delegated native retainer source (not installed)

A17 implements a fixed `createCgroupRevisionSupervisor(config)` port for the existing
A16 issuer. It returns exactly frozen `{run}`. This is a source/fixture phase, with no
bootstrap entry, service file, installation, activation, native reporter or live
cgroup test. All live H1–H9 remain NOT_READY. The earlier transient-service experiment
pruned both normal-exit and killed boundaries; absence is UNKNOWN_PRUNED, never empty.
The retainer instead owns a request leaf until positive sampling and exact removal.

The constructor's exact owner-private keys are `uid,unitName,invocationId,controlGroup,
cgroupMount,controlDirectory,sourceDirectory,source,clockId,runtimePath,runtimeDigest,
workerPath,workerDigest,helperPath,helperDigest,managerPath,managerDigest,
managerEnvironment`. No request-selected configuration, loader, default manager,
PATH/runtime fallback or injected production syscall backend exists. UID, effective
UID, GID and effective GID must all be1000 on Linux; another UID fails construction.
The fixed runtime is Node22.23.3 with SHA256
`fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48`.
Both process.execPath and /proc/self/exe must identify it. Exact installed paths stay
in private configuration, not this repository. Default Node20.11.1 is rejected.

Runtime/helper/worker hashes are read in bounded64KiB chunks from no-follow ordinary
single-link opened files, with inode/size/mtime/ctime/owner/mode stability checks.
They are rehashed at construction, prelaunch and READY before GO. Runtime max256MiB,
helper16MiB, worker131072. Runtime/helper/worker require UID1000, no special bits or
group/other write. The fixed pinned manager executable may be protected root-owned.
Native checks security.capability on itself and opened runtime/worker before clone;
no capabilities are granted or repaired. Service and process capability sets must be
empty. Accepted same-UID import/artifact TOCTOU and administration risks remain.

`controlDirectory/artifacts.json` is a preexisting private0600 owner-accepted artifact
inventory, not a bootstrap/configuration loader. Its exact shape is
`{version:1,issuerDigest,files:{relativeAuthPath:sha256,...}}`. It must cover the entire
installed auth directory, including all installed dependency files, with no missing
or surplus names, symlinks or writable components. The issuer entry must match
issuerDigest. Bytes and complete closure are rechecked before GO; absent inventory
denies. No inventory values are invented or committed. Owner host acceptance must
validate this inventory and full native/runtime loader closure against the build
manifest; source fixtures simulate inventory and do not establish an installed set.

The only manager command is the pinned managerPath with `--user show
host-operator.service --no-pager` and explicit property selectors. Its timeout is250ms
and output limit8192. No shell, mutation, default environment or arbitrary property
language is accepted. The owner supplies exactly manager environment
`{XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS,LANG:'C.UTF-8',TZ:'UTC'}`. Unique exact
properties must match the expected invocation, MainPID=process.pid and ControlGroup;
actual /proc/self/cgroup must be that group plus /supervisor. Root dev:inode and cgroup2
filesystem identity are retained and checked. Unexpected leftover run groups deny
new launches; there is no adoption, discovery/recovery or cleanup API.

The required dedicated user-manager service contract is documentation only:
Type=exec; ExitType=main; Delegate=yes; DelegateSubgroup=supervisor;
RemainAfterExit=no; Restart=no; KillMode=control-group; KillSignal=SIGTERM;
FinalKillSignal=SIGKILL; SendSIGKILL=yes; TimeoutStopSec=2s; UMask=0077;
NoNewPrivileges=yes; CapabilityBoundingSet=; AmbientCapabilities=.
ExecStart must directly exec the owner-private pinned Node and future fixed trusted
entry as MainPID; A17 supplies neither that entry nor an installable unit. No hooks,
PIDFile, reload/background shell, automatic restart, socket activation or controller
changes are supplied. Systemd owns outer service/supervisor placement. Only the fixed
native helper writes request children below that explicit delegation. User-manager
ownership is not authority to create arbitrary siblings outside this subtree.

An unsafe helper loss, corrupt/partial terminal protocol, unconfirmed cleanup or
unreaped helper permanently poisons the adapter and immediately exits the dedicated
MainPID with code70. This deliberate service-fatal behavior relies on the fixed outer
ExitType=main/KillMode=control-group contract to stop request descendants. There is no
configurable fatal callback or unrelated PID signal. Actual group stop on MainPID/
helper/manager loss remains a mandatory future host acceptance test; manager death,
blocked kernel tasks or failed stop is UNKNOWN/manual investigation, not proof.
Source tests exercise exit70 only in disposable VM subprocesses.

`run(spec)` keeps the exact A16 spec and validates all fields, canonical input,
source/run/request/intent/worker/clock binding, fixed worker entry, process.execPath,
LANG/TZ environment, limits8192/4096/4096 and original deadline before spawning.
Both inputs and configuration reject nonordinary objects/accessors/proxies/extra
keys. No raw signed event, ledger, callback, proof, operation registry or locator is
sent to native code. A16 remains the authority for actual authorization/currentJob/
pending checks and final proof publication. Backend emits no receipt, journal or
report, never releases reservation, and holds no evidence/journal lock.

The helper argv is exactly its pinned path, no options. Private inherited FDs:
0 request/lifeline,1 framed response,2 bounded sanitized diagnostics,
3 opened delegated root,4 opened runtime,5 opened worker,6 fresh backend lock.
Each call freshly opens controlDirectory/supervisor.lock (0600/nlink1/UID1000), passes
a distinct open-file description and immediately closes its own copy after spawn.
Native holds a nonblocking exclusive F_OFD_SETLK through removal/reply; lock files
are never unlinked or stolen. This is live serialization, not an attempt/recovery
store. A16's durable one-attempt claim remains the replay guard.

Wire records use four-byte ASCII magic and uint32 BE payload length<=16384. Strings
are uint16 BE length with bounded non-NUL UTF8. Integers use explicit BE encoding;
C never parses JSON, native struct padding or a requested command language.
Q17A carries in exact order runId,raw requestHash32/intentDigest32/workerDigest32,
clockId,startedAt/deadline u64,settlementWaitMs u32,input<=8192,runtimePath/workerPath,
then runtime and worker dev/ino/size u64. Paths repeat fixed owner-resolved identities
for FD agreement; the caller cannot select them. Native validates the exact frame,
current UID/context/FDs/OFD lock, original time and an exclusive run_<runId> leaf.
Collisions, unsupported clone3, permission/domain/seccomp errors have no fallback.

R17A READY carries runId,random boundaryId32 and root dev/ino; no worker has cloned.
Node revalidates manager/invocation/process/root and all pins/closure before sending
the single GO byte0x47. Setup/hash/handshake consume the original budget. Other bytes,
EOF, repeated/trailing records or timeout cannot start another worker. Parent input
EOF/death triggers native cancellation; helper PR_SET_PDEATHSIG is an extra wakeup.
Production uses only clone3(CLONE_INTO_CGROUP|CLONE_PIDFD), exit_signal SIGCHLD, target
open request FD, no namespace/thread/shared-files flags. There is no spawn-then-move
or ordinary fork fallback. The child is placed before operation code, closes every
management/lifeline/artifact/lock descriptor, executes opened runtime with
execveat(AT_EMPTY_PATH) and fixed worker argv, and receives only stdin/stdout/stderr
plus LANG/TZ. C never invokes shell/Git/network/manager.

The retainer stays in the manager-provided supervisor leaf and holds request/events/
kill/pidfd identities. It feeds bounded input and concurrently drains bounded output
through nonblocking CLOEXEC pipes. Overflow cancels the group and remains UNKNOWN,
never a truncated successful observation. It tracks wall and monotonic time, rejects
backward/uncertain clocks, stops on the earliest original deadline/wait cutoff and
writes exact child cgroup.kill only once. A separate maximum2000ms settling/removal
window does not extend operation success or A16 publication authority.

PR_SET_CHILD_SUBREAPER, pidfd+waitid/waitpid and adopted-child reaping establish leader
status and no unreaped attributable children. Pipe EOF, leader exit, kill ack, empty
cgroup.procs or missing path never establish settlement. The same still-existing
parent/child/events dev:inode and named paths, no child groups, domain and empty leaf
subtree_control, leader reaped and recursive events populated0 are required before
terminal snapshot. noEscape/sealed are lifecycle assertions within accepted same-UID
trust, not protection against adversarial admins. Then only the exact owned empty
leaf is removed and ENOENT is confirmed from the retained parent. Missing/replaced/
pruned/foreign boundary or unconfirmed cleanup is service-fatal/UNKNOWN. No stale-lock
cleanup, controller enablement, retry, namespace switch or recovery discovery exists.

T17A carries fixed status/reason/run/boundary/request/intent/worker/clock identities,
started/exited/settled times, private root/child dev:ino, reap/noEscape/sealed/populated,
actual exit code or supported TERM/KILL, cleanup confirmation and bounded stdout/
stderr. Exit0 is allowed only with exact settled+removed frame; exit2 is safe UNKNOWN
with confirmed containment/cleanup; exit70 is unsafe service-fatal. Node waits for
actual helper close/reap and exact terminal shape/code before returning frozen
`{status:'settled',boundary,stdout,stderr}` or `{status:'unknown'}`. Private dev:ino
fields never change A16's exact boundary/proof schema. Unsupported signals and invalid
UTF8 are never repaired into a fake outcome. A16 alone classifies actual SHA match/
mismatch and final policy/deadline; late backend responses cannot publish proof after
A16 returned UNKNOWN. Existing v1/v2 compatibility, journal/evidence/receipt/report/
invoke/resume/deadline contracts remain unchanged.

Build command is the selected compatible Node invoking
`agents/scripts/build-host-operator-supervisor.mjs <existing-private-output-directory>`.
It uses fixed /usr/bin/cc with no CC/CFLAGS/PATH override or package/network install.
The shared compiler flags include fixed `-B/usr/bin/` for subordinate programs
under the sanitized environment; the linker inventory uses the same selector and
the manifest records the complete argv. Production and both native harness builds
use these flags. No inherited PATH is supplied.
Production flags: -std=c17 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror -Wformat=2
-Wconversion -Wshadow -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie
-Wl,-z,relro,-z,now,-z,noexecstack. Source-prefix mapping avoids embedded build roots.
The generated revision-supervisor.build.json inventories actual source/header,
compiler bytes/version/target, linker, argv, ELF binary and dynamic loader/library
identities. Observed host gcc13.3/glibc2.39 are not substituted for measured pins.
Exclusive private staging, fsync, rename, parent sync and readback protect build
publication. Existing outputs are refused. No binary/manifest is committed and no
cross-toolchain bit reproducibility is claimed.

The new mandatory native suite compiles/runs production plus distinct C syscall/
parser/pipe/retainer fixtures and separate ASan+UBSan. Its compile-time fake cgroup/
clone operations are never part of production; real disposable pipes/children/waits
are conditional source tests, not kernel placement/emptiness acceptance. Positive
adapter tests load the actual module under --experimental-vm-modules in disposable
subprocesses with synthetic UID1000, filesystem/manager/process/child facades. They
include actual A16 issuer/worker→adapter IPC→immutable evidence→A15 verification and
reservation/report separation. UID normalization and kernel assertions exist only
inside those test facades, never a production option. Native full fixtures run beside
all package tests; no silent native skip is permitted.

The archive integration harness builds native before Gateway/auth installation and
passes its private artifact path to package tests. Gateway pin and zero-skip gates
remain unchanged. In the Developer container no gcc/cc/clang/ld/lld/make is available;
mandatory native build/test and the updated pinned harness therefore FAIL explicitly.
This is an unresolved prerequisite, not a skipped PASS or completed native acceptance.
Per owner direction the Draft may be published with this evidence, but the owner/host
coordinator must compile and run native production/harness/sanitizer tests at the exact
published head using measured host toolchain before independent Reviewer handoff.
No compiler installation/container change is authorized. Full package/native/host
results must be reported separately, without implying failed native gates passed.

Separate future owner-authorized host acceptance must substantiate effective service
properties, actual delegation/clone3-before-operation, runtime/closure/build pins,
fast exit/descendants/deadline kill, positive retained same-inode empty+reap before
removal, no management FD leak and exact cleanup. Helper/MainPID/manager death,
clock/pin/permission/seccomp/kill/I/O stalls and critical crash boundaries require
measured evidence. Untested catastrophic conditions stay NOT_TESTED. No live tests,
service installation or cgroup mutation are performed in this source job.

Rollback is a reviewed source revert with unchanged v2/journal format. Operational
rollback remains separate: stop admissions, establish exact owned-work containment,
retain attempts/proofs/report obligations, then change binaries. Never delete claims,
reset namespaces or re-admit to conceal UNKNOWN. Shared-UID mutation/ABA, imported
artifact TOCTOU, manager liveness, D-state, storage/quota/power-loss and service-stop
races remain host gates. Native reporting/bootstrap/activation/broader operations,
#21 isolation and Gateway#11 are excluded; H1–H9 live remain NOT_READY.
