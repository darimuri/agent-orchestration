# AGE30 source-only host acceptance prerequisite

This preparation facility (PR86 plus the four-file v2 dossier update) prepares
evidence and **always refuses operational admission**.
It does not qualify a host, implement the privileged fixture factory, install a
service, or supply an OGC2 capability. AGE28 remains blocked. All twelve merged
AGE29 files and the three native/validator host fixtures remain byte-for-byte
unchanged. The production facility source base is the human-approved
merge `8bbc3a9d052d428e67eebd3b7cf56c43ffe4490a`, tree
`8c5c76161e3e2580c463f644bff7f893a47bbb54`.

Authority: Kaneo AGE30 `hzj0bwjvs34u8jt97rj7jk5k`, plan
`cp6zifggarbfcomf8nudf2kp`, source handoff `ovgzsbka2vnhaajdfqtxdwuy`.
This is a source-only prerequisite PR, not the complete planned host harness.
The following concrete blocker prevents safely implementing an admitting launcher:
there is no independently justified preventive CPU/lifetime bound for the merged
mechanism. Filling capsule proof fields with arbitrary hashes would conceal that
blocker. The owner restricted the root phase to a reviewed future interface and
runbook. An operational launcher and its tests need another explicit source review
and authorization; even root cannot activate the entry stub in this slice.

## Implemented interfaces and limits

Run these as the ordinary build user from a reviewed source checkout:

```bash
node agents/scripts/offline-git-host-acceptance.mjs inspect
node agents/scripts/offline-git-host-acceptance.mjs probe
node agents/scripts/offline-git-host-acceptance.mjs build-source
node --test agents/scripts/offline-git-host-acceptance.test.mjs
node --test agents/docker/*.test.mjs agents/scripts/*.test.mjs
bash agents/scripts/test-resource-config.sh
```

Inspection/probe/build CLI exit2 means UNKNOWN, even when preparation succeeds;
exit0 is never host PASS. Root and non-Linux invocation are refused. Probe is
currently an alias for read-only nonroot inspection. There is no qualify command,
run-id option, executable/path/argv option, environment override or sudo call.
Exported JS functions are preparation helpers, never production admission APIs.
No normal test runs the entry/driver or makes a mount, cgroup, UID change or root
request. Tests delete only their exclusively created disposable test files;
source-build directories and partial build output are retained.

Inspection records current-process kernel/architecture, current UID/GID maps,
namespace IDs, controller listing, fixed tool identities/versions, Git HEAD/tree/
clean state and nineteen exact source file hashes (twelve AGE29 plus seven
preparation files, including qualification-dossier.mjs).
These are unqualified container observations when run in this agent container.
Controller availability is not delegation; namespace existence is not isolation;
no ext4 durability/seccomp/UID authority is inferred. No environment, credential,
unrelated mount inventory or other job's data is collected. Bounded regular-file
reads reject symlinks/special files/oversize and metadata changes; they are not the
production held-source custody primitive or a claim of mutation-proof observation.
Review must independently pin exact clean HEAD/tree and all artifact identities.

`build-source` creates one private exclusive `/tmp/age30-source-*` directory,
uses the unchanged production build function and fixed `/usr/bin/cc` flags, then
builds the entry and driver with hardened and ASan/UBSan variants. It records ELF
metadata, sources, production build inventory and fixed Git/Node identities.
Build artifacts are qualified:false, admission:false, runtime.completeClosure:false.
The native artifacts are compiled, **not executed**. There is no compiler download,
installation or root build. Missing tools are mandatory test failures, not skips.
This build is not a flattened runtime, complete Git/Node ELF/library inventory,
reproducible installation or successful sanitizer execution. Those missing checks
must be supplied before a future root run; never elevate `ldd` or compiler tools.

`host-entry.c` has a no-argument, root-only future interface and unconditionally
exits70 before any descriptor processing or effects. It creates no capsule,
namespace, loop device, filesystem, cgroup or process. This is an explicit refusal
stub, not an implemented launcher or a passing root-admission fixture.

`host-driver.c` is a separately hashed native fixture identity. It has no argument
or profile selector and refuses standalone invocation unless UID10002 and inherited
SEQPACKET/capsule shape match. Shape checks are not authorization. Its finite
fixed sequence probes AF_INET/AF_INET6/AF_UNIX socket denial and SCM_RIGHTS sendmsg
denial on the private fixture socket. Only EPERM/EACCES count as denial observations;
a successful forbidden syscall is failure. No resource bomb, generic command or
host-secret read is implemented. This driver alone is never Node compatibility or
qualification evidence. The future launcher must select its separate fixture
closure explicitly and observe failures externally. Resource exhaustion, canaries,
recvmsg and descendant profiles remain UNKNOWN, not silently counted as passed.

`host-validator.mjs` is the fixed **real Node** fixture path. The future flattened
closure places it at `/validator/entry.mjs` and copies unchanged production
client/protocol modules to `/validator/client.mjs` and `/validator/protocol.mjs`.
Their bytes and imports must be included in the closure inventory. Node receives
only FD3 private protocol, FD4 exact496-byte OGC2/v2 capsule, FD5 sealed bundle;
root launcher/worker are responsible for authentic/sealed descriptor custody.
It has no caller module selector and starts only under UID10002 without arguments.
It accepts only a bounded self-contained v2 SHA1 bundle containing the fixed
`refs/heads/candidate` commit/tree/blob fixture. It validates the pack trailer,
runs INIT/index-pack/verify-pack/fsck, compares original raw commit and blob batch
responses and tree bytes/OIDs, then SETTLE on the in-worker channel. External
OPEN/ADOPT are never forwarded. This is fixture logic, not AGE28 semantics.
The JS tests construct a genuine three-object pack and check it with real Git;
this does not execute real Node inside the production eight-PID envelope. Runtime
compatibility under those limits remains a required future gate.

## Legacy v1 conditional CPU dossier feasibility, never admission

The legacy v1 form of the `dossier` command reads at most16KiB JSON (two-second input deadline) from stdin as a nonroot user. It has
one exact version1 schema, rejects unsafe/negative numbers and wrong source/config,
and uses BigInt arithmetic. Fields:

- version=1, source=the base merge above, kernel=bounded release identifier,
  arch=x64 or arm64.
- quotaUs=20000, periodUs=100000, burstUs=0, parallelism=1..8,
  quotaSlackUs>=0.
- maxRunnableUs>=40000000, terminationBoundUs>=2000000, trustedCpuUs>0,
  uncertaintyUs>0.
- lifetimeContractSha256 and independentReviewSha256: nonzero SHA256 identifiers.

The conditional conservative candidate is:

```text
periods = ceil((maxRunnableUs + terminationBoundUs) / 100000) + 1
workerUpperUs = periods * 20000 + parallelism * quotaSlackUs
aggregateUpperUs = workerUpperUs + trustedCpuUs + uncertaintyUs
arithmeticWithinCeiling = aggregateUpperUs <= 10000000
```

This formula is an accounting proposal contingent on independently proved
assumptions, not a theorem about the current kernel. In particular the lifetime
bound must limit RUNNABLE time even if owner/controller/guardian are starved or
killed. cpu.max is a rate; per-CPU slack, quota carry, parallelism and termination
latency must have host-specific preventive upper bounds. Trusted reserve includes
setup, hashing, all controller/guardian/outer-owner CPU, output and settlement.
Those processes are outside the worker counter. A final measured counter, an8s
polling guard,40s watchdog or observed quick kill cannot prove prevention.

Even a mathematically feasible dossier with nonzero review hashes returns
assumptionsVerified:false, qualified:false, admission:false, status:UNKNOWN.
The source cannot verify independent review or unbounded scheduling assumptions.
No mechanism in these files transforms caller claims into a trusted capsule. If
that bound cannot be justified, request a separately reviewed production mechanism
correction; never widen the10s ceiling, quota, PID cap or margin in this harness.

## Future owner-only interface and effects (NOT runnable commands)

No root command is ready or authorized by this PR. The planned no-argument native
entry must eventually be driven by a separate reviewed owner-only phase dispatcher:
B1 nonadmitting intended-host capability probe, then B2 production-entry qualification
only after independently accepted CPU and lifetime dossiers. Current CLI refuses
all privileged phase/run-id inputs. Do not run source tests with sudo, invoke the
production supervisor manually, or reuse synthetic OGW_TEST capsules.

Future fixed run identifiers are `age30-8bbc3a9d-r1` (B1) and
`age30-8bbc3a9d-r2` (B2), each single use. Reserved paths:

| Resource | Future effect confined to fresh disposable fixture |
| --- | --- |
| Run root | `/var/lib/age30-qualification/runs/<fixed-run-id>` |
| Children | runtime/, storage.img, namespace-root/, artifacts/, evidence/ |
| External retained evidence | `/var/lib/age30-qualification/evidence/<fixed-run-id>` |
| Fresh delegated scope | `age30-qualification-<fixed-run-id>`, distinct empty per-case leaves |
| Storage | Exclusive owned regular storage.img, <=256MiB ext4, <=65536 inodes |

The future owner must verify identities before any operation and refuse missing
support, symlinks, preexisting paths/run IDs, stale locks, delegation or mounts.
No ancestor cgroup policy changes, existing-service migration/kill, arbitrary
formatting device/path, fallback filesystem, resize or stale-lock reuse. Proposed
production fixed root exists **only** inside the fixture's private outer mount/root
namespace, backed by the fresh image. Never create/chown/mount the actual host path
`/var/lib/github-app-agent-gateway/offline-import-v1`. Root-owned ancestors, UID1000
0700 custody leaves, UID10002 worker and denied agent10001 are required; control
gets an actually allocated1MiB evidence.reserve outside worker access. Disposable
mechanism qualification cannot certify an unprovisioned production mount identity.

Future FD3–12 layout is exactly the unchanged production contract: UID1000 connected
SEQPACKET peer, empty dedicated cgroup, storage, immutable runtime, sole root owner
lifeline reader, sealed496-byte OGC2/v2 capsule, held Git/worker/Node/validator.
Collision-safe remapping and an allowlist of inherited descriptors are required;
no host secrets/sockets/proc enter the runtime. Runtime is flattened read-only,
no symlinks, no old root, fixed /empty, /dev/null and mount points. Git/Node/loaders/
all libraries/validator/imported modules/protocol/build/config hashes must be pinned.
No OGW_TEST or syscall shim in production artifacts. Every driver closure has a
separate identity from the real Node validator closure.

Outer owner retains independent held-cgroup kill and pidfd/reap authority even if
guardian dies; sole lifeline writer is not inherited by children. Bound every
session and the entire finite sequential run, including external evidence capacity
and trusted CPU. Positive populated0, descendant reap and writer revocation must
precede success. A missing cgroup is UNKNOWN, never empty. Never signal a recycled
numeric PID after reap. On cancellation/fault retain image, staging, locks and raw
phase evidence. Identity-proven whole-group kill/reap/private unmount is separate
from evidence deletion. No auto cleanup/retry/repair/lock stealing or recursive
cleanup command. Unsettled resources require owner attention and cannot be reused.

## Independent evidence matrix and decision rules

All cells below are **UNKNOWN / NOT RUN** by this source PR. Each future cell must
bind case count/skips/raw-log hashes, exact source merge/tree/harness review/build
flags/binary/ELF/runtime identities, OGC2/v2 + OGW1/v1 + inventories/v2, intended
kernel/architecture/systemd/controllers/seccomp/ext4, UID maps and held namespace/
mount/dev/inode identities, counter snapshots, proof hashes and monotonic phase
records. Use dummy fixture canaries only, never credentials. Preserve logs outside
the exhausted storage; source assertions or synthetic cgroup files are not evidence.

| Required actual-host cell | Required observation |
| --- | --- |
| Admission negatives | Bad capsule/proof/peer/FD/root/runtime identity refused before execution |
| Real Node/Git | Fixed raw SHA1 bundle import/read/settlement under unchanged8PID limit |
| Network and secrets | Socket/network/SCM_RIGHTS/escape denied, fixture canary unreachable, external observer |
| Resources | Every inclusive ceiling and +1 case, actual counters and preventive aggregate CPU proof |
| Lifetime | Fork/daemon, parent/controller/guardian/owner loss, starvation, kill/reap and writer revocation |
| Custody | Source mutation, ancestor/FD/mount substitution, global exclusion, real no-replace races |
| Storage | Real block/inode exhaustion, short IO, fsync/rename failures, retained bounded evidence |
| Crash/restart | Every durability boundary, UNKNOWN retained after lost acknowledgement, no repair/replay |

Actual process kill is not power-loss proof. Kernel/storage fault injection needs
its own reviewed disposable mechanism and authority; this PR supplies none. PASS
requires independent Reviewer evaluation of every required real cell, no required
skips/mocks, justified preventive bound and exact identities. UNKNOWN is missing
proof/support/identity/evidence; REQUEST_CHANGES is an observed escape, false
receipt or ceiling breach. No exit code, checksum, self-review digest or checklist
alone establishes PASS. Any changed closure/kernel/config/UID/mount invalidates
affected qualification. The eventual AGE28 validator requires new closure review.
Rollback means disable admission and invalidate affected identities while retaining
evidence, not automatic deletion or fallback to an older worker.

## v2 canonical evidence and context contract

The next source slice starts at preparation merge
`f41325db78c87545f454212ad16187c7fbff76c8`, tree
`89832821a4e764192d53bdcc0d4eb9b2ac74d4c3`. This is **not** the production facility
identity. Production BASE remains AGE29 merge8bbc3a9d/tree8c5c7616 above. Only four
files change: new `offline-git-worker/qualification-dossier.mjs`, this document,
and the host acceptance JS/test. No native, production admission, dependency or
build primitive changes are included. Planner decision `a6z5jmhqz3sa7xobf0cq1fiv`
and owner handoff `d8ubjmrhaafadmimwng432a2` define this boundary.

The existing `dossier` stdin command accepts legacy v1 unchanged, or canonical v2.
All results exit2/UNKNOWN with admission:false, qualified:false and
assumptionsVerified:false. The same16KiB byte limit and two-second stdin deadline
apply to both. Nothing fetches evidence, follows a supplied path/link, executes a
caller predicate or emits a capsule. The pure module uses only bounded in-memory
values, SHA256 and JSON; it launches no process or file IO. Valid v2 CLI input is
followed by the existing fixed read-only current-process inspection; malformed v2
is rejected before inspection. `qualify`, run-id and generic command options still
refuse. The mandatory native build remains a source acceptance test, not a skip.

Canonical encoding is UTF8 without BOM, whitespace or trailing newline. Object
keys sort by ASCII code unit; arrays retain order. Numbers are nonnegative safe
integers written in ordinary decimal (no exponent, negative zero, fractions,
Infinity or aliases). Strings use JSON.stringify's shortest escaping and must
have well-formed Unicode, <=512 UTF8 bytes. Field names are ASCII identifiers.
Maximum nesting12 and2048 values; arrays<=32 and objects<=32 fields, further
restricted by schema. Decoder re-encodes and compares bytes, rejecting duplicate
keys even when their values agree, alternate escapes, invalid UTF8, truncation or
trailing data. These restrictions are a local documented canonical format, not a
claim of implementing a general external canonical-JSON standard.

The literal deterministic all-missing template contains no invented safe numbers:

```json
{"accounting":{"maxRunnableUs":null,"parallelism":null,"quotaSlackUs":null,"terminationBoundUs":null,"trustedCpuUs":null,"uncertaintyUs":null},"claimed":null,"evidence":[],"expected":null,"version":2}
```

The code fence above describes the bytes; a newline after the JSON is not part of
the v2 input. `probe` includes this template plus canObserve/cannotObserve and
missingProofInputs. It records current source bytes/HEAD/tree, kernel release and
architecture, bounded current UID/GID maps and current namespace/cgroup identifiers.
It cannot observe intended-host authority, exact kernel build/config, preventive
quota/slack/carry behavior, finite starvation/death lifetime, trusted aggregate CPU
reserve, escape/migration enforcement or durability. Kernel build/config remain
null. There is no broad /proc, environment, account or unrelated mount enumeration.
No privileged probe, cgroup write, stress/workload or root factory is added.

Exact top-level keys are version=2, expected, claimed, accounting, evidence.
`expected` and `claimed` are independently supplied expectations and external
claims; neither is a trusted observation. Either may be null, meaning missing.
Each nonnull context has exactly production, preparation, probe, host, policy.
Each subcontext may be null; nullable leaf values represent unavailable context.
Unknown keys, source paths, enums, unsafe numbers or malformed digests are denied.

| Context | Exact contents |
| --- | --- |
| production | commit/tree40 lowercase hex; twelve path/sha256 records in the fixed PRODUCTION inventory order. The module pins both merge/tree and all twelve source digests. |
| preparation | separate commit/tree, clean boolean and seven path/sha256 records in PREPARATION_FILES order, including this new module. Never silently replace production BASE with current HEAD. |
| probe | schema `age30.nonadmitting-inspection`, version2, SHA256 of the literal descriptor `age30.nonadmitting-inspection/v2:current-process-only;no-enforcement-proof` plus LF. Source file hashes separately bind implementation. |
| host | scope, kernelRelease, kernelBuildSha256, kernelConfigSha256, arch, uidMapSha256, gidMapSha256, namespaces, cgroupSha256. Release<=128 ASCII identifier bytes; arch x64/arm64; namespace keys ipc/mnt/net/pid/user/uts with `<kind>:[decimal-id]` strings. |
| policy | exact POLICY keys/values below; mismatched fixed limits are contradictions, not negotiable options. |

SHA256 is64 lowercase nonzero hex; null means missing, not zero. File inventory
paths are compiled identifiers only, not read requests. Namespace and map/cgroup
hashes identify current-process observations; they do not establish host or mount
custody authority. Scope is CURRENT_PROCESS_UNQUALIFIED or INTENDED_HOST_CLAIM.
The observer always emits CURRENT_PROCESS_UNQUALIFIED. Any attempted intended-host
promotion is CONTRADICTED, including a caller supplying a matching alleged host
observation to the pure API. Same release/build/config hashes, repeated contexts
and a clean tree do not authenticate host provenance or freshness.

POLICY binds quotaUs20000/periodUs100000/burstUs0, pids8, wallMs30000/tailMs2000/
ownerMs40000, guardUs8000000/ceilingUs10000000, memoryBytes536870912/swapBytes0,
scratchBytes268435456/inodes65536, machineBytes268435456/diagnosticBytes1048576,
readCount20000/frameCount65536, objectBytes8388608/bundleBytes33554432,
controlBytes16384/frameBytes65536. It copies the frozen policy identity for reporting;
it never writes or changes any limit. Values are compared against compiled constants.

`accounting` is null or exactly six nullable integer terms: parallelism,
quotaSlackUs, maxRunnableUs, terminationBoundUs, trustedCpuUs, uncertaintyUs.
Known values use the unchanged v1 candidate formula and minima/ranges. Missing
terms yield arithmeticWithinCeiling:UNKNOWN; values below required minima are
blockers. Feasible totals and threshold equality never prove a bound. Inclusive
10,000,000us is arithmeticWithinCeiling:true; +1 is a ceiling contradiction. A
single microsecond crossing a quota-period boundary rounds to a whole extra period.
The independent conditional baseline is worker8430000/aggregate9030000us, not a
kernel measurement. Safe-integer inputs are converted to BigInt before summing or
multiplying, so extreme aggregates do not silently wrap/round.

`evidence` has at most16 fixed-purpose records, each at most512 canonical UTF8
bytes, within the total16KiB envelope. Each has exactly:

- obligation: kernelQuotaBound, finiteRunnableLifetime, noEscapeMigration,
  trustedCpuBound, uncertaintyReserve, intendedHostScope or independentContract.
- expectedContextSha256: SHA256 of canonical expected context bytes.
- evidenceSha256: claimed content identity, never authenticated proof.
- evidenceId:1..256 ASCII letters/digits/underscore/dot/colon/hyphen, no URL or path.
- provenance: SOURCE_CLAIM, NONROOT_OBSERVATION, OWNER_OBSERVATION or
  INDEPENDENT_REVIEW_REFERENCE. These are **caller labels**, not verified actors.

Repeated obligation/provenance/evidenceId triples reject; different bounded
references for the same obligation are allowed. No reference is dereferenced.
The context hash binds the claim's stated subject; it cannot prove completeness,
truth, independence, freshness or a reviewer signature. Forged, stale and self-review
hashes cannot supply authority. `provenanceVerified:false` and `freshness:UNVERIFIED`
are unconditional, including for fully populated/repeated inputs.

The report separates conditional arithmetic, identityMatches (true/false/UNKNOWN),
missing paths, explicit blockers and seven obligation rows. Identity comparison
includes expected vs claimed/current observation plus production/probe/policy pins;
a missing context is UNKNOWN, mismatch or dirty preparation is a blocker. A stale
evidence context digest is also a binding contradiction. identityMatches:true
means matching supplied byte identities only. It is never qualification.

Rows are MISSING when relevant context, arithmetic terms or references are absent;
CLAIM_ONLY for source/nonroot labels; REQUIRES_INDEPENDENT_REVIEW for owner/review
references; CONTRADICTED for a binding, fixed-policy or accounting contradiction.
No row becomes PROVEN. Every accounting term is returned with proven:false. The
finite handoff result is one of SOURCE_CONTRACT_READY_FOR_REVIEW (packaging only),
MISSING_PRIVILEGED_OBSERVATION or PREVENTIVE_BOUND_UNSUPPORTED. This creates no
retry/poll loop or authority to collect privileged evidence. Even completely
populated feasible forged envelopes end UNKNOWN/nonadmitting.

## Upper-bound assumption review deliverable

The following map states what would need a finite justification. None is established
by this source PR. “Measure later” cannot replace a preventive argument.

| Candidate term | Actual assumption / present justification |
| --- | --- |
| ceil((maxRunnableUs + terminationBoundUs)/100000) quota periods plus1 | Bound every interval the worker can remain runnable, including initial and terminal period phase.40s owner and2s tail are policy, not a scheduler-guaranteed upper bound. No finite arbitrary-starvation/death guarantee is established. |
| periods *20000 | Exact intended-kernel cgroup quota behavior, hierarchy, replenishment/carry and no migration/escape. Config text or one cpu.stat sample cannot prove it; kernel build/config and actual effective topology remain missing. |
| parallelism * quotaSlackUs | Kernel-specific per-CPU quota slack/carry and maximum concurrent runnable workers/threads. Eight PIDs are not automatically an eight-CPU scheduling theorem. No supported finite slack bound exists here. |
| trustedCpuUs | Setup/input/runtime hashing, controller, guardian, outer owner, machine/diagnostic output and settlement CPU outside worker cpu.stat. Those processes lack a proved aggregate preventive mechanism. A chosen positive reserve is only a claim. |
| uncertaintyUs | Explicit remaining measurement/phase/termination error reserve. No justified finite uncertainty bound is supplied. Never silently zero an unproved term. |
| noEscapeMigration | Namespaces/seccomp/cgroup custody and independent owner enforcement even on guardian death; missing actual host proof, not established by matching source digests. |
| independently reviewed contract and host scope | Independent provenance/freshness and exact intended-host/build/UID/namespace identities. Hashes and current-container observations are insufficient. |

The concrete unsupported production assumptions are finite runnable lifetime under
arbitrary owner/controller/guardian starvation or death, and bounded trusted CPU
outside worker cpu.stat. Without an independently defensible mechanism for those,
the next step is a separately scoped production-mechanism review/correction, not a
launcher, larger budget or more optimistic default. Actual quota/slack/topology
observations may falsify a proposed argument but cannot prove arbitrary scheduling
latency bounded. A privileged nonadmitting capability probe, if needed to establish
an otherwise inaccessible observation, requires its own exact source/effect/limits/
retention review and separate owner authorization first. This source slice gives
none. The root refusal stub is not a probe substitute.

All earlier UNKNOWN host gates, retained-evidence rules and AGE28 blockage remain.
Future real Node8PID closure, runtime pinning, owner-death kill/reap, custody/storage/
crash and isolation qualification remain separate. Native builds here are mandatory
source evidence only; unavailable compiler failure must be reported honestly, and
an owner compiler-equipped report must be attributed separately from local tests/CI.

## Source-only empty-cgroup observer (separate four-file slice)

`tests/offline-git-worker/host-cgroup-observe.c` is a standalone future Linux,
no-argument observer. It is not installed or connected to the CLI, host entry,
dossier, capsule, launcher or production build. The existing 19-file inspection
inventory and all production sources remain unchanged. Its exit is always 2;
every report and build inventory is UNKNOWN, admission:false, qualified:false,
assumptionsVerified:false. observationsComplete means only that the finite empty
configuration sequence finished. It is not host qualification.

Future effects are reserved, not authorized by this document. Real/effective
UID/GID must all be zero, arguments are refused, inherited descriptors above 2
are closed and inherited environment authority is cleared. Required openat2,
statx mount identity and evidence allocation/sync behavior have no fallback.
Ancestors must be root-owned and not writable by agents, group or world. Named
and held device/inode/mount identities are compared around effects/readback.

The following parents must ALREADY exist with trusted custody:

- `/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1`: actual cgroup v2,
  domain, empty, no descendants, cpu/memory/pids available and already enabled.
- `/var/lib/age30-qualification/evidence`: trusted evidence storage.

The observer exclusively creates evidence directory
`age30-8bbc3a9d-r1-cgroup-observe-v1` (0700), and only `start.json`,
`observations.json`, `result.json` (exclusive 0600 regular single-link files).
Each file is bounded to 16384 bytes; aggregate is at most 65536. All three receive
16KiB KEEP_SIZE allocation reservations before the start record; observations
have a reserved closing margin and terminal output has independent capacity.
Failure to reserve or sync denies further cgroup effects. Each report is written
at most once. Short writes, absent/partial terminal records, allocation or fsync
uncertainty remain UNKNOWN, with no durability claim. Complete records include
phase/error/errno and held identities; errno zero can accompany a semantic refusal.

Only after exclusive evidence reservation and synced start does it create the
single child `cgroup-observe-v1` beneath the fixed cgroup parent. Only that fresh
empty child receives these literal writes, once, in this order:

| Control | Literal bytes |
| --- | --- |
| cpu.max | `20000 100000\n` |
| cpu.max.burst | `0\n` |
| memory.max | `536870912\n` |
| memory.swap.max | `0\n` |
| memory.oom.group | `1\n` |
| pids.max | `8\n` |

Here `\n` denotes one newline byte. No parent limits, ownership or
subtree_control are changed. There is no process insertion, workload, signal,
kill/freeze/procs/threads write, namespace, mount, runtime or storage image.
The observer remains outside the empty leaf. Unexpected population stops later
writes, without attempting removal or killing its occupant.

Reads are limited to parent type/controllers/subtree_control/events/procs;
child type/events/procs, the six controls and cpu.stat/memory.current/
memory.events/pids.current; own UID/GID maps, namespace IDs, kernel release and
architecture. Each fixed read is bounded to 4096 bytes. No broad process, mount,
account, credential or environment scan occurs. There is no polling or retry;
the cooperative ten-second deadline only refuses subsequent steps. It is not a
hard scheduling or lifetime guarantee.

Retained states include: evidence-directory-only; some reserved empty files;
partial or synced start without child; child created before open/initial reads;
any prefix of the six controls; readback mismatch, identity change or unexpected
population after a write; observations or result short write/fsync failure; and
process interruption at any point. Every created artifact stays in place on
success, refusal, interruption and uncertainty. No delete, repair, adoption,
resume, retry or stale-path reuse is provided. Concurrent exclusive attempts can
win at most once. A second invocation refuses retained paths. Owner remediation
and eventual cleanup are separate authorized work.

Ordinary-user source verification uses:

```sh
node --test agents/scripts/offline-git-host-cgroup-observe.test.mjs
node --test agents/docker/*.test.mjs agents/scripts/*.test.mjs
```

The new JS test compiles the production observer but NEVER executes it. Only the
separate test binary and its ASan/UBSan variant execute, as an ordinary user, in
exclusive `/tmp/age30-cgroup-source-*` fixtures. Root/cgroup identities and control
semantics are simulated; real openat2 and ordinary-file exclusivity are exercised.
The independent golden trace checks the six literals and effect order. Fixtures
cover prerequisite/path/custody/mount/controller/domain/population errors,
unsupported primitives, read/evidence bound and +1, short IO, each counted
creation/read/write/report/allocation/fsync fault, interruption after start,
retention, no reuse and concurrent attempts. Production invocation guard logic
is tested through a pure predicate, never by launching its privileged entry.
Missing fixed compiler, linker, readelf or sanitizer support is FAILURE, never skip.
For the memory.max fixtures, a missing regular file permits exactly the literal
cpu.max and cpu.max.burst writes before its open fails. A FIFO or symlink is
rejected by directory validation during initial reads, before any control write.
Separate literal traces, retained path types/original memory value, CPU readback
and terminal error phases assert this distinction independently of write counts.

All build output is retained, including failures. Separate `build.json` binds
base, exact source head/tree, working diff digest, the four source SHA256 values,
compiler/linker versions, compiler/linker/readelf/Node digests rechecked after the
fixture run, full fixed flags/commands, artifact digests and simulated
trace digest. Command logs retain statuses and diagnostics. Its complete field
means source fixtures only. For review, use clean exact published head, compare
all four hashes and the inventory against the independently reviewed commit,
then independently hash retained build.json/logs/binaries. This inventory does
not extend the frozen probe inventory or certify a runnable/trusted installation.

Before any future root effect: independent exact-source review, human merge,
ordinary-user build verification, trusted reviewed executable custody and explicit
owner authorization naming source/build/binary digests, intended disposable host,
fixed effects and retained paths are required. Missing delegated topology or
trusted artifacts is a RUN BLOCKER, not permission to provision, elevate, install,
change ancestors or select another writable path. No root command is supplied.

Even genuine empty-leaf readback cannot prove quota/slack/carry/parallelism bounds,
finite runnable lifetime under controller/owner starvation/death, escape/migration
prevention, aggregate trusted CPU or uncertainty reserve. All seven dossier
obligations remain unproved. Namespace/seccomp/network/secrets, memory/PID
stress enforcement, real Node8PID/Git closure, storage/custody/crash behavior,
launcher and production mount identity remain unqualified. AGE28 remains blocked.
A later admitting mechanism needs independent preventive CPU/lifetime justification
and separately reviewed source authority; this observation cannot auto-promote it.

## Separate setup/custody V1 source slice (not execution authority)

Frozen Planner contract `fp9y3v230ral17pji0jdhifv` and owner readiness
`nb7hb8j3cpsi6lluds0rqa43` bind this five-file slice to
`cc71fb96f0be40b681821c5061675285a6f66244`, tree
`3caab46e535de0cf5ab25774dea8c7a45e1d9817`. Production AGE29, the observer,
its tests/runner, refusal entry and the existing 19-file probe inventory remain
byte-identical. This separate source/build inventory does not extend that inventory.
The observer errno diagnostic follow-up is outside this slice.

Ordinary-user preparation has exactly one command, with no input paths, profiles,
arguments, environment overrides or limits:

```sh
node agents/scripts/offline-git-host-cgroup-setup.mjs prepare
```

It requires a clean reviewed commit descending from the pinned base, with exactly
the five permitted paths changed. Clean source is a reproducibility condition;
an independent source review and human merge still authenticate the commit.
Preparation creates an exclusive mode-0700 `/tmp/age30-cgroup-setup-source-*`
directory and retains every outcome. It compiles the unchanged observer with the
existing hardened flags, inspects its x86_64 ELF interpreter/dependencies, and
embeds its bytes into a private generated header. It then compiles the native
setup payload. Neither binary is executed. Observer size is at most 256KiB,
payload at most 1MiB; bounds are not automatically increased. ASan/UBSan is a
separate mandatory source fixture build; sanitizer bytes are never installed.

`build.json` records base/current commit/tree, all tracked source hashes (including
all linked/embedded unchanged inputs), tool and Python imported-module identities,
compiler/linker/readelf/Node versions, full invocations, generated header hash,
ELF inspection and both binary hashes. Sources, tools, trusted runtime and Python
module custody are rechecked after compilation. All receipts remain UNKNOWN,
admission:false, qualified:false, assumptionsVerified:false. complete only means
source preparation completed. Exit2 never means host setup succeeded.

The only permitted ELF interpreter is `/lib64/ld-linux-x86-64.so.2`; the only
DT_NEEDED entry is libc.so.6, with no RPATH/RUNPATH. Only the known x86_64 loader
and libc system aliases resolve into trusted root-owned nonwritable custody;
canonical paths and hashes are recorded. Unknown closure, writable ancestry,
unsupported architecture or absent tools refuse. No ldd, downloader, package
installation, privileged compiler or runtime factory is provided. Trusted system
`/usr/bin/python3`, its interpreter/stdlib/imported native modules and ancestry
are prerequisites for the later owner entry. The ordinary-user inventory checks
these; independently confirm the exact runtime custody before authorization.

`owner-entry.txt` is INERT REVIEW TEXT, not a trusted script and not to be executed
with sudo. The renderer contains a literal isolated `/usr/bin/python3 -I -c`
verifier and a placeholder for stdin redirection from one approved regular file.
After independent exact-source review, human merge, ordinary-user build and
independent digest verification, a separate owner authorization must name the
literal setup SHA256/size, runtime pins, host, fixed effects and retained paths.
The literal digest and the payload are approved separately. A mutable neighboring
manifest cannot supply the root command's expected pin; changing the pin requires
new owner authorization. No runnable root command or execution consent is supplied
by this document or by preparation.

The verifier checks isolation, root identity, fixed loader/libc hashes and trusted
ancestry, regular stdin at offset zero, pinned size/digest, bounded size+1 reads
and before/after metadata continuity. It copies only matching bytes to a memfd,
compares readback, applies WRITE/GROW/SHRINK/SEAL seals, checks sealing/fd-exec
support, closes unrelated descriptors and execs the FD with fixed no-argument argv
and an empty environment. No untrusted ELF pathname is reopened, no root temporary
executable is created and no caller command, shell or user-owned Python module
is selected. Root Python and stdlib must already be trusted before Python starts;
this is not a bootstrap route for an untrusted interpreter. Missing primitives
refuse before filesystem/cgroup setup effects.

The native entry requires Linux x86_64 real/effective UID/GID0, no arguments,
cleared environment, closed inherited descriptors>=3 and umask0077. It never
spawns, execs or runs the observer, moves processes, changes UID, mounts,
creates namespaces, contacts services/network or installs a generic command API.
Required openat2/statx held/name device/inode/mount checks have no fallback.
Existing `/`, `/var`, `/var/lib`, `/sys`, `/sys/fs`, `/sys/fs/cgroup` custody must
be root-owned and nonwritable by group/world, with stable identities.

All new names must initially be absent, including both fixed parents. Any
preexisting, substituted, special, linked or apparently matching path refuses;
there is no adoption, chown, overwrite, retry, repair or cleanup path. Setup
exclusively creates only these filesystem paths:

| Path under `/var/lib/age30-qualification` | Mode / purpose |
| --- | --- |
| top directory itself, `evidence`, `bin`, `setup-v1` | 0700; evidence initially empty |
| `setup-v1/start.json`, `inventory.json`, `result.json` | exclusive 0600 regular single-link reports |
| `bin/cgroup-observe-v1` | initially exclusive nonexecuting 0600; embedded byte comparison then 0500 |

Each report is at most16KiB, aggregate at most64KiB, with separate16KiB KEEP_SIZE
reservations including terminal capacity before the durable start. Partial top
creation may precede journal availability: such retained state is UNKNOWN.
Embedded observer copy uses bounded full write/readback comparison, exact custody
checks, final mode0500, file and directory fsync. Its receipt records the embedded
hash/size and held identities before any cgroup creation. It is never executed.

The only created cgroup is the direct child
`/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1`. Root must already expose
and enable cpu/memory/pids. Setup never writes root subtree_control or changes
ancestor quotas, service units or hierarchy. The owner must separately authorize
this precise disposable direct-child topology; a host requiring another hierarchy
needs revised source scope, not an improvised service/delegation.

After durable custody/start, the new parent must be genuine cgroup2, root-owned,
domain, empty and without descendants, with cpu/memory/pids available. Its ONLY
control write is one literal `+cpu +memory +pids\n` to its own subtree_control.
Exact set readback, emptiness and identity checks follow. No observer child/run
is created, no procs/threads/freeze/kill/disable write occurs, and no occupant is
moved or killed. Root process/child lists are not enumerated. Cgroup readbacks
are explicitly RUNTIME_ONLY; fsync of receipts does not make cgroup configuration
durable. Fixed reads are bounded to4096B, and the finite sequence has no retry or
poll loop. A cooperative ten-second refusal deadline is not a hard lifetime proof.

First failing syscall captures errno immediately; semantic failures explicitly
use NO_ERRNO/0. Later reporting does not replace the first error. Subsequent setup
effects stop; one reserved terminal receipt may be attempted. All created state,
including partial/unsynced reports, partial observer copies, enabled controller
prefixes and interrupted directory-only state, remains retained. Missing,
partial or unsynced result is UNKNOWN even if a partial record looks complete.
Second invocation refuses; concurrency can reserve the top at most once. Native
exit2 is used for both refusal and setup completion. Independently inspect valid
reports/custody before interpreting setupComplete, which never means host PASS.

Source checks, as ordinary user only:

```sh
node --test agents/scripts/offline-git-host-cgroup-setup.test.mjs
node --test agents/docker/*.test.mjs agents/scripts/*.test.mjs
bash agents/scripts/test-resource-config.sh
```

The separate native fixture replaces IO only at compile time. It uses private
ordinary-file fixtures and real openat2/exclusivity, SIMULATED root/cgroup
identities/controls, an independent literal effect oracle, counted IO faults,
copy/mode/reservation/sync/report/revalidation failures, short/bounded IO,
substitution/custody/controller/domain/population failures, first-error reporting,
start interruption, retained state, second invocation and two-process races.
The Python NONROOT test form handles fixed harmless data and checks digest/bounds,
metadata mutation, held-file pathname replacement and memfd sealing; it never
executes setup or the owner root entry. Missing compiler/Python/sanitizer is a
failed mandatory gate, never skipped or promoted to PASS. Build logs/inventories
are retained under the private scratch directory. Full-package failures must be
separated into new failures and exact baseline/environment limitations.

A Draft requires exact-head compiler/owner validation and independent Reviewer
source PASS before any later Ready request. Human merge and owner setup execution
remain separate. The installed observer may only be invoked by a further separate
owner authorization; setup neither grants nor runs it. Root-owned receipts and
future observer evidence require their own reviewed read/export contract; no
chmod/chown/upload workaround is provided. All seven dossier obligations and
intended-host isolation/resource/custody/storage/crash qualification remain
UNKNOWN. AGE28 stays blocked. No deployment or task/job completion follows.

## Root cgroup interface compatibility correction (post PR92)

The fixed held /sys/fs/cgroup node (s->cg) is validated as cgroup2 with
root custody and repeated held/name device, inode and mount identity checks.
Linux documents cgroup.type and cgroup.events as non-root interfaces:
https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html . Setup does
not open either interface on that exact held root. It still requires cpu,
memory and pids available and enabled, allowing additional root controllers.
This distinction does not depend on ENOENT or a caller-selected flag/path.
Root processes, threads and children are never read or enumerated or modified.

The new direct child still requires exact domain type, empty procs, exact
unpopulated/unfrozen events and no descendants before enabling and at readback.
Missing type/events, threaded/malformed type, occupied/frozen state, descendants,
and unexpected child controller state refuse. No generic missing-file fallback
was added. Existing effect ordering, the single fixed child control write,
first-error capture, retained prefixes, no retry and no cleanup remain in force.

The ordinary-user fixture omits both non-root-only files at root and models
unrelated root occupants/children. It forbids production setup opens of root
type/events/procs/threads, root writes and root enumeration, while retaining the
separate bounded-read helper test. Extra enabled root controllers are a positive
case. Child missing-file and invalid-state cases assert exact phase/error/errno,
unchanged literal effect prefixes, retention and no later control effects.
Counted fault positions come from the corrected successful trace; hardened,
ASan+UBSan, interruption and concurrency coverage remain mandatory. These are
simulated source tests, never intended-host qualification.

After correction, run the unchanged nonroot prepare on the clean exact reviewed
head and again after human merge. Independently review the new setup payload and
owner-entry digest/size, source/tool/runtime inventory and unchanged observer
identity. Previous payload or owner-entry pins cannot authorize corrected bytes.
No root command is authorized here. Source review, human merge, intended-host
preflight, separate owner execution approval and reviewed root evidence export
remain required. All seven obligations remain UNKNOWN and AGE28 stays blocked.

## Separate setup evidence reader SOURCE slice

The evidence reader is a distinct source-only artifact based on setup evidence
revision `34b7768a70d64141be52b36d3fbe729b8a02c55c`, tree
`18ac126ce52b8da030f3f25b7fc6866b4c447f3d`. Its four new files and this runbook
are the complete five-path allowance. Existing setup, observer and builders are
unchanged. This source work does not authorize any privileged run.

Ordinary-user source checks and preparation:

```sh
node --test agents/scripts/offline-git-host-cgroup-evidence.test.mjs
node --test agents/docker/*.test.mjs agents/scripts/*.test.mjs
node agents/scripts/offline-git-host-cgroup-evidence.mjs prepare
bash agents/scripts/test-resource-config.sh
```

Only fixed `prepare` and `collect` commands exist. Both refuse root and always
exit2/UNKNOWN, including complete preparation or collection. The production
reader is compiled and inspected, never executed by tests/preparation. Separate
compile-time IO fixtures run as ordinary user in hardened and ASan+UBSan forms;
missing compiler/Python/sanitizer is a mandatory failure, never a skip.
Preparation requires a clean reviewed descendant and exactly these five changed
paths. Private exclusive0700 scratch retains invocations, source/tool identities,
Python import/runtime inventory, ELF, fixture results, reader and inert-entry
size/SHA256, and false admission flags, including failures. Source/tool/runtime
identity checks surround compilation. Neither builder CLI nor setup/observer runs.

The reader's only prospective source paths are anchored ancestors and:

- `/var/lib/age30-qualification/setup-v1/{start,inventory,result}.json`
- `/var/lib/age30-qualification/bin/cgroup-observe-v1`
- `/sys/fs/cgroup/{cgroup.controllers,cgroup.subtree_control}`
- `/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1/` followed only by
  `cgroup.type`, `cgroup.controllers`, `cgroup.subtree_control`, `cgroup.procs`,
  `cgroup.events`, and one bounded directory observation of that parent itself.

There is no caller path/limit/profile, recursive archive, future observer leaf,
root type/events/procs/threads read, root enumeration or external command. Fixed
openat2 no-symlink/no-magiclink/beneath resolution, explicit crossing rules, statx
mount IDs and held/name custody checks have no fallback. Ancestors are root-owned
and nonwritable; fixture directories0700, single-link regular receipts0600 and
observer0500 are required. Ordinary files/directories use O_NOATIME; unsupported
primitives refuse. Device/mount, identity, size or timestamp instability stops
subsequent source IO. Missing fixed names are recorded without creating them;
other fixed names may still be checked. Empty/partial/malformed receipt bytes
remain raw evidence. Reader code does not interpret receipt claims as authority.

Receipt reads are bounded to16KiB, observer256KiB, cgroup files4096B, each with one
overflow/terminal check. Fixed-parent directory observation is4096B plus a terminal
check; descendants are labeled unexpected and never followed. Encoded output is
capped at512KiB, constructed before output, with at most128 writes of at most4096B.
A short write, EINTR or EPIPE stops without retry or further source reads; the
collector retains incomplete bytes. Native stdout must be a writable anonymous
pipe owned by a nonroot user. This checks inherited pipe provenance, not the
identity or continued behavior of the consumer process. Owner authorization and
capture-process provenance remain external evidence. No source writes, fsync,
permission changes, execution, process creation, service/network contact, root
output files, cleanup or repair occur.

Format version1 includes status UNKNOWN, admission/qualified/assumptionsVerified
false, atomic:false, cgroupDurability:RUNTIME_ONLY, collectionComplete and a fixed
ordered object list with raw base64, observed length and before/after metadata.
Missing/unsafe/partial/unread objects are distinct; unexpected directory entries
are observations. A complete collection can contain missing or malformed receipts
and occupied/threaded/frozen cgroup bytes. It is never setupComplete, host PASS,
freshness, past fsync/order or durable configuration proof. Mutable cgroup contents
are not an atomic snapshot even when metadata remains unchanged.

The nonroot `collect` command consumes reader JSON only from stdin. It cannot
launch a reader, accepts no source/output pathname, and never invokes sudo or
uploads. It rejects duplicate decoded JSON keys, trailing input, invalid UTF-8,
noncanonical base64, schema/metadata/flag errors and bounds violations. It retains
a bounded raw prefix (at most512KiB+one overflow byte) and an explicit incomplete
manifest on malformed/interrupted/oversize input. On validated input it retains
decoded bytes with SHA256, receipt syntax observations and collection state in
fresh exclusive0700 nonroot scratch; files0600, no overwrite/reuse. Reviewer tools
must independently hash decoded bytes. In particular, compare the installed
observer to the separately pinned setup artifact size34528 and SHA256
`959e27df34cbe45068350c5d506cebc2cb33892333754dac09b9c52f24bf39bf`.
Reader/collector success never performs this setup acceptance automatically.

The reader-specific inert Python entry is separate from setup's entry. Literal
payload/runtime pins, isolated trusted system Python/import custody, bounded
regular stdin, metadata continuity and verified sealed memfd precede fixed
`age30-evidence-read-v1` argv and an empty environment. The expected digest never
comes from a neighboring manifest. No actual root command or execution request is
provided here. Independent exact-head review, human merge, exact-merge reader
preparation and independent new reader/entry/runtime pin review must precede any
future owner authorization naming intended host, exact source allowlist and
stdout-only nonroot capture. Setup authorization remains a separate decision.

The existing setup preparer deliberately rejects this expanded checkout: its
five-path scope is relative to its own older base. Do not relax that gate or
silently regenerate setup bytes. Keep original exact34b7768 setup artifacts and
reader/exporter inventories separate; use the original clean pinned projection
for any separately authorized setup regeneration, or obtain a revised source
scope. Earlier setup entry/payload pins do not authorize the reader. Future
observer-run evidence export needs a separately reviewed extension. All seven
qualification obligations remain UNKNOWN, AGE30 incomplete and AGE28 blocked.

### Reader directory-padding correction (PR94 follow-up)

Before each bounded getdents64 call, the reader initializes its directory buffers
to zero. Linux directory records contain alignment padding that the kernel need
not write; retaining raw returned records must not export previous stack bytes.
The separate fixture now writes only record fields and name/NUL, preserving
caller padding. A poisoned-buffer check verifies the shim does not hide this
boundary, and an independent decoder checks zero padding in actual exported
parent.entries on successful collection, counted IO failures after the copy,
terminal-directory failure and maximum-directory-bound cases. The literal fixed
open/read oracle and all existing bounds/authority remain unchanged. These native
assertions still require compiler-equipped ordinary-user hardened and sanitizer
execution; missing tools are failures. No privileged reproduction is authorized.
