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

## A3: offline two-source admission conformance

The test-only `scripts/check-host-operator-integration.mjs` closes the A2 DTO-only
compatibility gap by composing the actual A1 signed-event adapter, the actual built
Gateway `createHostPolicySource`, and the actual journal. It imports no live config,
starts no service, discovers no operational ledgers and executes no intent. Events
use the public BIP-340 vector-0 test scalar, the resolver is an ID-indexed raw fixture,
and receipt verification is a separate positive fixture authority. Private disposable
agents/jobs files go through the unchanged A2 ownership, ancestry and safe-file checks.
The execution subject remains distinct from the requesting owner.

Run from a **clean committed** orchestration checkout at the head being reviewed:

```bash
# Operator-supplied source checkout, not a host request or live ledger path.
# This exact dependency HEAD/tree is mandatory; a moving main or existing dist is refused.
gateway_source=/workspace/darimuri/github-app-agent-gateway-age7-a3-source
orchestration_head=$(git rev-parse HEAD)
node agents/scripts/check-host-operator-integration.mjs "$gateway_source" "$orchestration_head"
```

Pinned dependency: `darimuri/github-app-agent-gateway`
`59fca5e863c99dd44b7d8d0ad762e00f03402517`, tree
`b1e1430793bcd26b02df9a77aa49a5b5ce16a24b`. Orchestration must descend from A1 merge
`1b3bc2b41e2767273053e8e03bd89e9d3149d3e1`. The harness checks canonical origins,
exact heads/trees, clean tracked and untracked source state, and rechecks them after
validation. Both supplied source roots must be canonical paths. It archives the
committed sources into private scratch, installs their unchanged locks using
`npm ci --ignore-scripts --offline --no-audit --no-fund`, runs full Gateway
`check`, `test`, `build`, then the full orchestration Node suite. It never fetches,
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
is **not** A3 integration evidence. The harness run must report zero skipped tests.

This demonstrates offline composition against pinned real code, not live host policy
or receipt authority. Immutable installation/artifact verification, trusted UID/path
and atomic ledger writers, bounded storage/latency, synchronous filesystem stalls,
nontransactional revocation/ABA, existing dependency advisory assessment, AGE #5,
executor/process/resource controls and native Buzz/Kaneo receipts remain host gates.
Independent exact-head Reviewer/CI and human approval remain separate. No live
capability, endpoint, runner, validate/reporting, root/Docker/systemd or runtime is
installed. Reverting only these tests/harness/docs and discarding their scratch rolls
back A3 source; preserve all operational journals/receipts. Overall AGE #7 is incomplete.

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
