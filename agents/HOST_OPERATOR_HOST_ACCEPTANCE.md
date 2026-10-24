# Host Operator host acceptance contract — A4 preparation

**Current decision: NOT READY for host installation or live activation.** All host
facts in the inventory below are **UNRESOLVED**. This document is a reviewable
contract/template, not evidence that a Host Operator is installed. Approval or
merge of this documentation does not fill any row or authorize host changes.
Overall AGE #7 remains incomplete.

A4 adds only this document and links in [HOST_OPERATOR.md](HOST_OPERATOR.md) and
[README.md](README.md). Its authority is Kaneo AGE #7 task
`r2908ui7wjzv8bek75we457e`, plan `w2j2cbpu683o850uuxzomdf1`, assignment
`piro74suiy8cn0b9lgm670hc`, and owner authorization
`e465aca6836d1d210bf9a7b6efb5f35d74f3a3d53a83504a0a2a22154d454d8b`.
Those records authorize documentation preparation only; they are not live
`hostAdmission` grants. No executable setup or privileged command is prescribed.

## Pinned source baseline

| Component | Exact reference | What it establishes |
| --- | --- | --- |
| A1 and phase-1 protocol/journal | Orchestration A1 merge `1b3bc2b41e2767273053e8e03bd89e9d3149d3e1`; unchanged production modules in the A3 merge below | Real direct-owner signature admission, injected current policy, separate receipt authority and durable intent APIs |
| A2 policy library | Gateway `59fca5e863c99dd44b7d8d0ad762e00f03402517`, tree `b1e1430793bcd26b02df9a77aa49a5b5ce16a24b` | Opt-in private-file policy reader/evaluator, not an installed writer or live endpoint |
| A3 conformance and A4 documentation base | Orchestration `5a90e6acd1f4e00d832e53ce77541e189a15bbb7`, tree `6b49bf43dae5fd69ca101fea2ee5f9499ab0387c`; reviewed A3 head `5fcf816a8cb0c8a7a6e2816a3d2fdd29d46f8c46` has the same tree | Offline composition against pinned real A1/A2/journal, not installed artifacts or live host acceptance |

Source references below are immutable baseline links. Future installed artifacts
must have their own approved evidence; a matching Git HEAD alone does not establish
which built files, dependencies or configuration a host actually loads.

- [A1 authorization adapter, lines 27–62](https://github.com/darimuri/agent-orchestration/blob/5a90e6acd1f4e00d832e53ce77541e189a15bbb7/agents/host-operator-auth/authorization.mjs#L27-L62): mandatory synchronous `resolveEvent` and `currentJob`, exact owner/source/descriptor/request binding, `status.revision` only, signed/policy expiry minimum.
- [A2 safe-file reader, lines 53–129](https://github.com/darimuri/github-app-agent-gateway/blob/59fca5e863c99dd44b7d8d0ad762e00f03402517/src/host-policy-source.ts#L53-L129): ancestry, exact file UID, single-link private regular files, bounded reads and two-pass consistency.
- [A2 evaluator](https://github.com/darimuri/github-app-agent-gateway/blob/59fca5e863c99dd44b7d8d0ad762e00f03402517/src/host-policy.ts): current enabled subject/job, explicit capability and owner mapping; no implicit host permission from forge access.
- [A2 bounds, writer obligations and limitations, lines 331–355](https://github.com/darimuri/github-app-agent-gateway/blob/59fca5e863c99dd44b7d8d0ad762e00f03402517/README.md#L331-L355): 1 MiB/file, 4096 records/ledger, observed 100ms budget, atomic replacement writers and nontransactional revocation limits.
- [Journal](https://github.com/darimuri/agent-orchestration/blob/5a90e6acd1f4e00d832e53ce77541e189a15bbb7/agents/scripts/host-operator-journal.mjs): `next` reauthorizes outside/inside the lock and persists before returning intent; `record` requires separate positive evidence and preserves ambiguous termination.
- [A3 fixture composition](https://github.com/darimuri/agent-orchestration/blob/5a90e6acd1f4e00d832e53ce77541e189a15bbb7/agents/scripts/host-operator-integration.test.mjs): private disposable ledgers, in-memory raw-event resolver and Map receipt authority. Fixture rename is not production writer durability evidence.
- [A3 harness](https://github.com/darimuri/agent-orchestration/blob/5a90e6acd1f4e00d832e53ce77541e189a15bbb7/agents/scripts/check-host-operator-integration.mjs): offline archived source builds and conformance checks, not an installer.
- [Existing runtime preflight, lines 81–86](https://github.com/darimuri/agent-orchestration/blob/5a90e6acd1f4e00d832e53ce77541e189a15bbb7/agents/scripts/preflight.sh#L81-L86): root-only agent/Gateway mount inspection, not a Host Operator acceptance validator. Its existing IDs are not an A4 host identity decision.

## Evidence rules and decision ownership

Use sanitized inventory and stable evidence references, never operational ledger
contents, bearer token hashes, keys, tokens, credential files, private raw logs or
unredacted host paths in public PR/chat. Protected evidence can be referenced by an
opaque ID with an access owner; an independent reviewer must have authorized access
to verify it. Do not invent a successful measurement, installed path, API or identity
to complete a cell. Logical labels in this document are not filesystem paths.

| Evidence role | Responsibility | Named person/account or procedure |
| --- | --- | --- |
| Owner / accountable host administrator | Supply actual non-secret host inventory, assign evidence custodians, approve risk decisions and any future host action | UNRESOLVED |
| Installation evidence custodian | Prove the complete installed source/artifact/dependency/configuration set and protected access boundaries | UNRESOLVED |
| Administrative writer custodian | Identify actual agents/jobs writer source revision, authorization, serialization and recovery procedure | UNRESOLVED |
| Storage/operations evidence custodian | Prove journal namespace routing, filesystem/mount/durability/capacity, restart and latency behavior | UNRESOLVED |
| Independent Reviewer | Check source claims and each authorized evidence reference; identify unsupported readiness claims | Future scoped Reviewer assignment UNRESOLVED |

These are accountability roles, not instructions to create users or services.
Developer prepares the contract; Developer does not approve its own evidence.
Human risk acceptance and later activation authorization remain separate decisions.

## Host inventory and go/no-go table

Every row currently has the outcome **NOT READY**. A future revision may replace an
UNRESOLVED fact only with an owner-approved value, evidence custodian, immutable
reference, relevant source/artifact revision, measurement date and independent
review disposition. Missing, stale, contradictory or unverifiable evidence leaves
that row NOT READY. A blank cell is never a default. No row is waived by A3 success.

| Gate | Required host fact and evidence | Evidence owner | Current fact / evidence | Go/no-go rule |
| --- | --- | --- | --- | --- |
| H1 Installation provenance | Full loaded module/build/dependency/lock/configuration inventory; reviewed registry and `sourceDigest` meaning; protected immutable install ownership and writable-vs-executable boundaries | Installation custodian + owner | UNRESOLVED / none supplied | NOT READY until complete installed set, not just Git HEAD, is verifiable |
| H2 Reader identity and access | Actual admission runtime identity, UID/GID, configured reader UID, ledger file ownership/modes and ancestry; agent/LLM exclusion | Owner + installation/writer custodians | UNRESOLVED / none supplied | NOT READY unless compatible with unchanged A2 exact UID/private-file rules |
| H3 Authoritative ledger placement | Host-selected agents/jobs locations, access controls, provenance, current enabled subject/job/capability mapping, and owner/requester/callback/target/allowlist bindings | Owner + writer custodian | UNRESOLVED / none supplied | NOT READY for missing or self-asserted authority; no parallel authorization ledger |
| H4 Administrative writer | Actual writer source/revision and authorized update procedure for each file, validated private temporary file, file fsync, atomic rename, parent fsync, serialization and partial-pair failure recovery | Writer custodian | UNRESOLVED / none supplied | NOT READY for unknown writer or active-file in-place updates |
| H5 Journal/storage | Protected host-only journal location, unique job/workspace namespace routing, ownership/modes/ancestry, filesystem/mount, capacity/ENOSPC, durability and restart/lock investigation evidence | Storage custodian + owner | UNRESOLVED / none supplied | NOT READY without persistent receipt-preserving routing and storage acceptance |
| H6 Time/latency/revocation | Trusted clocks, actual local read/storage latency measurements and explicit acceptance of observed 100ms semantics, syscall stalls, final-read revocation, hidden ABA and whole-host rollback limits | Storage custodian + owner | UNRESOLVED / none supplied | NOT READY until risks are accepted or a stronger design is separately reviewed |
| H7 Raw event source | Authoritative raw signed bytes by exact ID, provenance, bounds/deadline, unavailable/replay handling and synchronous seam compatibility | Owner + future event-source designer | UNRESOLVED / none supplied | NOT READY for live activation; no transport selected by this contract |
| H8 Separate completion authority | Future executor evidence, process-tree termination proof, native reporter identities, receipt/content/mention binding and lost-response reconciliation | Owner + future executor/reporting designers | UNRESOLVED / none supplied | NOT READY for execution/reporting; owner request or policy facts cannot stand in for a receipt |
| H9 Operational decision | Exact status-only subject/job scope, dependency advisory assessment, independent review, human risk decision and separately authorized activation/rollback plan | Owner + independent Reviewer | UNRESOLVED / none supplied | NOT READY; docs merge grants no capability and starts no runtime |

H1–H6 are the selected preparation focus. H7–H9 record prerequisites for later
phases; their presence in the table does not authorize their implementation. Even
if H1–H6 later pass, this document alone cannot declare live processing ready.

### Identity compatibility stop rule

A2 compares each ledger file's UID with the configured `uid` and rejects group/other
permission bits. Protected ancestors must be root/configured-UID owned and not
writable by group/other (the documented sticky `/tmp` allowance is for fixtures).
GID/group membership alone does not satisfy the file UID check. A distinct reader
UID plus group-read access is therefore not an accepted workaround. Choosing the
existing administrative UID would trust code sharing that UID; that expanded trust
must be explicit. A separate projection/access design would require new review and
a new scope, not an unapproved second ledger or relaxed file checks. Actual UID,
GID and access choices remain **UNRESOLVED / NOT READY**.

### Writer and storage stop rules

A2 provides a reader, not the actual host administrative writer or installer.
The A3 disposable writer does not establish production fsync, serialization or
recovery guarantees. The two-file double read can reject observed changes; it cannot
prove a transaction across agents/jobs or prevent hidden ABA. The writer contract
must address partial-pair updates explicitly without claiming reader guarantees
that do not exist. Unknown writer provenance remains **UNRESOLVED / NOT READY**.

Keep the existing journal and authority separation. The namespace is bound to its
trusted source/registry/workspace configuration; route each job/workspace to its
unique namespace. Preserve pending intents and positive historical receipts through
restart and any later source change. The journal is bounded to 128 requests and
1 MiB; capacity, archival/migration and investigation of stale locks/atomic temporary
files need their own approved procedures. Do not delete state, clear locks, reset a
nonce database, switch namespaces or use a fake provider to escape ambiguity.
Actual storage paths, filesystem, ownership, capacity policy and recovery procedure
remain **UNRESOLVED / NOT READY**.

## Future trust and data-flow boundaries

This table describes intended boundaries, not installed wiring.

| Boundary | Required proof / separation | Failure or attack to reject |
| --- | --- | --- |
| Public raw event → A1 | Recompute event ID and signature; exact owner/routing/payload/source/descriptor scope | Forged ID/signature, changed context, duplicate/oversized input, display-name or chat authority |
| Verified owner → A2 current policy | Owner requester differs conceptually from execution subject/role; current authoritative enabled agent/job and explicit status-only capability | Stale copied facts, wrong subject/owner/member/task/repo/ref/SHA, missing/revoked/expired capability |
| Reviewed install → loaded policy/registry | Full immutable artifact/dependency/configuration provenance and host-selected mapping | Writable install/dependency substitution, untrusted environment/configuration or request-selected provider |
| Policy + descriptor → journal intent | Fresh outside-lock and under-lock authorization; durable private intent before disclosure | Scope substitution, observed concurrent revocation, replay or alternate-namespace bypass |
| Executor/report authority → journal receipt | Separate positive evidence bound to the exact intent; next effect still needs fresh admission | Intent/signature treated as execution, timeout treated as termination, absent report treated as delivery |

`resolveEvent` and `currentJob` are synchronous injected functions. A live event
transport has not been selected. Do not put synchronous network calls, Promise
wrappers or self-refreshing stale caches under the journal lock. Any bounded
prefetch/storage/freshness design needs separate review. Public-key verification
proves authorship/integrity, not current policy, installed code integrity or work
completion. Same-reader-UID or host-admin compromise remains outside these checks.

## Future host acceptance matrix — unavailable, not executed

All rows below are **UNRESOLVED / NOT READY** as host evidence. They are requirements
for a later separately authorized host exercise using synthetic data first, not
instructions to read or mutate operational ledgers, inject faults into production,
reboot hosts, send native reports or run privileged checks now.

| Case | Positive acceptance evidence required | Fail-closed negative acceptance and expected result | Evidence owner / current status |
| --- | --- | --- | --- |
| Installed set | Full approved loaded artifacts/locks/registry/source binding verified under protected paths | Artifact/dependency/config/sourceDigest/registry substitution → no admission / zero new intent | Installation custodian / UNRESOLVED, NOT READY |
| Reader access | Actual UID/private modes/canonical ancestry match unchanged A2 checks; no agent/LLM access | Wrong UID/mode/ancestor, symlink, hardlink, FIFO/device, missing file → sanitized denial / zero new intent | Installation + writer custodians / UNRESOLVED, NOT READY |
| Writer consistency | Named reviewed writer's validated private atomic replacement and fsync/serialization/recovery evidence | In-place or unstable write, mixed/partial update, unknown writer, malformed UTF-8/duplicate JSON/IDs, byte/record overrun → deny when invalidity/change is observed; no transaction/hidden-ABA guarantee | Writer custodian / UNRESOLVED, NOT READY |
| Current admission | Fresh matching raw event, current subject/job/capability and exact status descriptor can produce durable data intent without executing/reporting | Wrong owner/requester/subject/role/task/job/base/context/source/descriptor/operation; disabled/revoked/completed/expired authority; missing provider → denial / zero new intent | Owner + future admission reviewer / UNRESOLVED, NOT READY |
| Revocation/time | Fresh read clocks and expiry minima verified in epoch ms; prelock/locked/later-effect boundaries exercised | Observed revoke between checks, stale facts, clock error or observed budget overrun → denial; revoke after final read or stalled syscall remains residual | Storage custodian + owner / UNRESOLVED, NOT READY |
| Durable journal | Same namespace and receipt history survive restart; unique routing, lock contention, capacity and durable intent-before-effect verified | ENOSPC/write/rename/fsync failure, crash/death, stale lock/temp → no usable fresh effect or conservatively pending unknown; no automatic cleanup/reset | Storage custodian / UNRESOLVED, NOT READY |
| Receipt/replay | Reopened pending effect remains unknown; complete replay emits no new effect; matching historical positive receipt can reconcile after expiry/revocation | Request signature/policy facts, timeout/unproven descendants or absent delivery evidence cannot clear pending; any next intent still needs current authorization | Future executor/reporting evidence custodians / UNRESOLVED, NOT READY |
| Non-disclosure | Authorized normalized DTO/intent/receipt/error output contains only bounded public fields | Synthetic token/hash/private-path/raw-error canaries must not escape; raw evidence stays protected | Owner + independent Reviewer / UNRESOLVED, NOT READY |

A3's offline conformance is reusable baseline evidence only. Root/Docker/Compose,
actual filesystem/mount/boot/restart/power-loss, installed UID/access, administrative
writer, live event/current-policy and native reporter acceptance are unavailable in
this preparation scope. No fixture run is labeled a live PASS.

## Residual limitations and owner inputs

The owner must supply the H1–H6 inventory and name its custodians using sanitized
references, then decide whether to accept current reader semantics or require a
stronger design. The observed 100ms checks happen between synchronous calls and
after evaluation; they cannot interrupt a blocked syscall or guarantee hard
wall-clock completion. Two-file consistency is not a transaction, a durable
generation store or protection against last-read revocation, perfectly hidden ABA
or full-host storage rollback. Private filesystem permissions do not protect against
compromised host administration or code sharing the trusted reader UID.

Existing Gateway dependency advisories require separate operational assessment;
A4 performs no dependency audit/upgrade and claims no advisory-free state. A1/A2/A3
approval does not establish AGE #5 authority/workspace migration, restricted
executor process-tree/CPU/memory/PID/disk/output/timeout enforcement, privileged
service isolation or native Buzz/Kaneo completion evidence. These remain distinct
future gates. No new identities, installed paths, writer commands or event APIs are
inferred from this document.

## Preparation review and handoff

Documentation acceptance means every required fact is either supported by a
verifiable owner-approved reference or explicitly UNRESOLVED with a NOT READY gate.
It does not require filling unknown facts with guesses. Developer checks all source
citations/links, Markdown structure, complete three-file diff and whitespace.
Independent Reviewer must inspect the exact PR head, compare claims with the pinned
sources and distinguish documentation correctness from operational evidence.
No new executable tests or host acceptance runs are part of A4.

Any later implementation needs a fresh narrowly scoped owner-authorized Developer
job, exact repository/base/head/expiry, isolated checkout and separate Reviewer
assignment. Existing completed A3 jobs are not host-admission authorization.
Owner/admin setup may require protected ownership or mount work, but actual
operations and whether elevated access is needed remain UNRESOLVED until inventory
is approved. No speculative privileged command is offered. Independent review and
human risk acceptance do not themselves activate a capability.

## Rollout, rollback and exclusions

There is no runtime rollout for this preparation PR. Future installation/activation
must be separately authorized, stay disabled until relevant evidence and risk
decisions pass, and have a reviewed rollback plan. A future trusted authority must
disable/revoke any newly enabled admission before changing installed code; preserve
journal source bindings, intents, receipts and pending `outcome_unknown` state.
Do not recover by switching namespace, resetting state or using fixture authority.
That is a rollback requirement, not an operational procedure supplied here.

A4 source rollback reverts only this new document and the two documentation links.
It does not change deployed code, live jobs/capabilities, storage or receipts.

Excluded: source code/tests/dependencies or Gateway changes; installer/writer tools;
live resolver/provider/capability activation; endpoint/socket/HTTP/MCP/systemd service;
runner, arbitrary shell/path/env/mount/argv or validate/delegated execution; root or
Docker access; AGE #5 provisioning/migration; dedicated reporter credentials/native
receipt implementation; C-prime #16; job-scope/runtime/container/credential changes;
Ready transition, approval, merge, deploy or operational rollback execution.

## A5 offline evidence-index lint

The pure [evidence linter](scripts/host-operator-evidence.mjs) checks a compact,
explicitly supplied sanitized metadata index against the merged A4 contract. It
opens no referenced evidence, reads no host files, fetches no URLs, executes no
processes and stores no state. The stdin entrypoint reads only its supplied bytes;
importing the module consumes no stdin and produces no output. It is not a collector,
attestation verifier, authorization ledger, `currentJob` provider or journal input.
All H1–H9 rows above remain **UNRESOLVED / NOT READY**.

`lintEvidenceIndex(raw, asOf)` accepts serialized JSON as a string or ordinary Buffer
and an explicit nonnegative safe-integer epoch-ms cutoff. Already-parsed objects,
class instances, accessors, symbol-bearing/extended Buffers and caller verdicts are
not accepted. The API returns a fixed bounded summary rather than throwing raw
errors. The caller cutoff and index `asOf` must match; no ambient clock or automatic
evidence timestamp refresh is used. Whitespace counts toward the byte limit.

### Exact metadata schema and bounds

The root has exactly `version`, `contract`, `asOf`, `references`, `gates`.
`version` is 1. `contract` has exactly the following literal fields (also exported
as frozen `CONTRACT`); these identify the **merged A4 baseline**, not an installed
artifact or the evolving A5 document:

| Field | Required literal |
| --- | --- |
| id | `host-operator-host-acceptance-a4` |
| repository | `darimuri/agent-orchestration` |
| sourceSha | `60d7f6e857c6139e4b776cf5296720f00c5ebc81` |
| sourceTree | `500522c773e21c941244fc298fd4a2d28e55222a` |
| contractBlob | `50cc24f45d9aef2f2422417d737b28c8202e6767` |
| gatewaySha | `59fca5e863c99dd44b7d8d0ad762e00f03402517` |
| gatewayTree | `b1e1430793bcd26b02df9a77aa49a5b5ce16a24b` |

`gates` contains exactly one `{id,facts}` object for each H1–H9. Each has exactly
three `{id,status,references}` facts from the fixed mapping below, in any order.
These identifiers partition the existing A4 row requirements; they introduce no
new live acceptance policy or host values. Each fact status is `UNRESOLVED` with an
empty reference list, or `REFERENCES_SUPPLIED` with 1–4 unique opaque reference IDs.
No other status, fact, gate or field is accepted.

| A4 row | Required fact identifiers | Scope of the existing requirement |
| --- | --- | --- |
| H1 | `installed_set`, `install_boundary`, `source_binding` | Loaded artifacts/dependencies/configuration; protected install; registry/sourceDigest meaning |
| H2 | `reader_identity`, `private_access`, `agent_exclusion` | Actual UID/GID compatibility; file/ancestor controls; absence of agent/LLM access |
| H3 | `ledger_custody`, `subject_scope`, `owner_mapping` | Authoritative ledger custody; current subject/job/capability; pinned owner/requester/callback/target/allowlist |
| H4 | `writer_source`, `atomic_update`, `pair_recovery` | Actual writer source; validated temp/fsync/rename/parent fsync; serialization/partial-pair recovery |
| H5 | `namespace_storage`, `capacity_durability`, `restart_recovery` | Unique protected journal routing/storage; capacity/fault/durability; restart/stale-lock investigation |
| H6 | `clock_latency`, `stall_acceptance`, `revocation_acceptance` | Trusted clocks/read measurements; uninterruptible syscall risk; final-read/ABA/whole-host rollback decision |
| H7 | `raw_event_source`, `event_bounds`, `event_failure_replay` | Exact-ID raw signed source; size/deadline/synchronous seam; unavailable/replay/freshness handling |
| H8 | `termination_authority`, `reporter_identity`, `receipt_reconciliation` | Executor/process-tree proof; distinct native reporter identity; exact receipt/content/mention/lost-response evidence |
| H9 | `status_scope`, `advisory_assessment`, `activation_decision` | Exact status-only scope; advisory assessment; independent review/human risk/activation/rollback decisions |

`references` is a list of at most 108 unique definitions, each with exactly these
fields. Every definition must be used by a fact; a pointer may be shared between
facts because one protected document may cover multiple claims. Duplicate
reference definitions/pointers, conflicting custodian/revision/time metadata,
undefined pointers and unused definitions reject.

| Reference field | Allowed metadata, not independently verified evidence |
| --- | --- |
| id | Sanitized opaque label matching `[a-z][a-z0-9_-]{0,31}` |
| custodian | Named custodian's sanitized label using the same alphabet; not authentication, a new account, or an assigned host identity |
| revision | Lowercase 40-hex source revision or 64-hex artifact/evidence revision; otherwise `null` |
| recordedAt | Nonnegative safe-integer epoch ms, no later than the explicit cutoff |
| reviewBy | Owner-defined validity-policy review deadline, safe-integer epoch ms no earlier than recordedAt; `null` if policy is unknown |

Applicable revision metadata is required for `installed_set`, `source_binding`,
`writer_source` and `advisory_assessment`. A missing revision there yields
`revision_missing`; it does not invent an installed revision. A null `reviewBy`
yields `review_policy_missing`; `reviewBy` at/before the cutoff yields
`stale_reference`. No universal host-evidence TTL is selected. An invalid/reversed
interval or future recordedAt is rejected. All revisions/custodians/deadlines are
untrusted claims; a syntactically valid forged revision is never proof of current
source, actual custody, install integrity or human acceptance.

Input limits are fixed: 65,536 UTF-8 bytes, nesting depth 8 (root depth 0), decoded
strings at most 128 UTF-8 bytes, at most 32 keys/object and 108 elements/array before
schema-specific limits. Reject malformed UTF-8, BOM, lone surrogates, malformed JSON,
escaped duplicate keys and all unknown/extra fields. Live fact bodies, paths, URLs,
commands, env/mount/argv, attachments, token hashes, `verified`/`ready` flags and
caller-selected limits have no schema slot. References are never dereferenced.
Only synthetic sanitized metadata belongs in test fixtures; do not paste raw
private evidence into this index or assume the linter can sanitize arbitrary text.

### Output and offline invocation

The only operational `decision` is `NOT_READY`; `verification` is always
`INDEPENDENTLY_UNVERIFIED`, including invalid input. Output is at most 4096 bytes:
fixed version/contract identity, `structure`, fixed global `codes`, and fixed H1–H9
IDs/decisions with deduplicated sorted diagnostic codes. It never echoes a reference,
custodian, revision, timestamp, raw field, exception message or evidence content.

| Structural result | Meaning | CLI exit |
| --- | --- | --- |
| INVALID | Bad schema, source pin, JSON/encoding, bounds, cutoff or conflicting metadata; no gate claims processed | 2 |
| INCOMPLETE | At least one gate has `missing_references`, `review_policy_missing`, `revision_missing` or `stale_reference` | 1 |
| COMPLETE | All structural reference requirements supplied; still independently unverified and operational NOT_READY | 3 |

Global valid-input code is `independently_unverified`. Invalid-input codes are fixed:
`invalid_input`, `invalid_encoding`, `invalid_json`, `duplicate_key`, `bounds`,
`schema`, `invalid_cutoff`, `contract_mismatch`, `cutoff_mismatch`, `gate_set`,
`fact_set`, `fact_status`, `fact_conflict`, `reference_schema`, `reference_time`,
`duplicate_reference`, `reference_conflict`, `unknown_reference`, `unused_reference`,
`output_bound`. Invalid input returns an empty gate list. No CLI result exits 0 or
emits PASS/READY/activation. COMPLETE describes index structure only.

Pipe the explicitly prepared metadata JSON into the stdin-only entrypoint and
supply the chosen reproducible review cutoff. For syntax illustration only, the
following cutoff is synthetic, not a live host fact or freshness recommendation:

```text
node agents/scripts/host-operator-evidence.mjs --as-of 1800000000000
```

There is no file-path argument, collector, output-file option or evidence opener.
Run [the linter tests](scripts/host-operator-evidence.test.mjs) and the repository's
full feasible Node suite for code verification; ordinary runs that skip A3 integration
must report those skips. Synthetic all-unresolved, incremental and forged-complete
fixtures verify preparation semantics, not H1–H9 host acceptance. This code never
feeds `journal.next`, supplies a receipt or overrides `currentJob`.

Named custodians and an authorized independent reviewer must still verify every
protected evidence reference, applicable revision, validity policy and actual host
fact. The owner must separately accept risks and authorize any later operation.
No input can waive H7–H9 through H1–H6 structural completeness. Removing the A5
module/tests and these documentation additions restores the A4 manual inventory;
retain all existing UNRESOLVED rows, journals, receipts and pending outcomes.
No live data collection, dependency change, installer, provider, ledger, executor,
reporting, systemd/runtime/container/credential/job or activation change is included.
