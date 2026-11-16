# AGE30 source-only host acceptance prerequisite

This six-file slice prepares evidence and **always refuses operational admission**.
It does not qualify a host, implement the privileged fixture factory, install a
service, or supply an OGC2 capability. AGE28 remains blocked. All twelve merged
AGE29 files remain byte-for-byte unchanged. Source base is the human-approved
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
clean state and eighteen exact source file hashes (twelve AGE29 plus six AGE30).
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

## Conditional CPU dossier feasibility, never admission

The `dossier` command reads at most16KiB JSON (two-second input deadline) from stdin as a nonroot user. It has
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
