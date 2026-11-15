# AGE29 offline Git worker — source facility, NOT QUALIFIED

This facility is separate from Host Operator/A17. It supplies no service,
installer, production configuration, approval verifier, generic executor, semantic
bundle/diff/object validator, Gateway integration or deployment. AGE30 must qualify
the exact human-reviewed merge/build/configuration on a separately authorized host.
An uncompiled or untested source draft is not source PASS.

The twelve new files in this slice are the protocol/client, native protocol,
supervisor, worker and custody headers/implementation, offline build script, Node
test file, two native fixtures and this document. All preexisting files are frozen.

## Trust and admission

A separately authorized root launcher supplies descriptors 3–12 to the supervisor,
which takes **no arguments**. There is no public listener, socket path, setuid,
sudo, Docker socket or arbitrary service-property interface. Never expose this
launcher or its capsule factory to agents. Agent UID10001 cannot launch it.

| FD | Host-selected authority |
| --- | --- |
| 3 | Already connected SOCK_SEQPACKET; peer UID1000, authorized host client |
| 4 | Empty dedicated cgroup-v2 domain, never an existing agent/service group |
| 5 | Fixed custody root directory |
| 6 | Dedicated immutable read-only minimal runtime root |
| 7 | Root-owned outer launcher's lifeline pipe; EOF/data/error cancels |
| 8 | Root-owned sealed memfd containing the exact 496-byte admission capsule |
| 9–12 | Held Git, worker, Node and validator files in that runtime, respectively |

The capsule is **trusted launcher data, not proof produced by this source**. It
must have F_SEAL_WRITE/SHRINK/GROW/SEAL, magic OGC2/version2 and network-order fields:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | OGC2 then uint32 version2 |
| 8 | 192 | Six 32-byte nonzero bindings: nonce, intent, artifact, policy, capability, context |
| 200 | 160 | SHA256 Git/worker/Node/validator/runtime inventory |
| 360 | 72 | Three dev/inode/mount-ID triples: storage, cgroup, runtime |
| 432 | 64 | Qualified CPU-bound dossier and independently owned lifetime contract digests |

Context is the trusted repository/job/agent/caller tuple digest. The host retains
the full tuple/PublicationIntent/authorization and verifies all bindings. A random
nonce/opaque inbox handle or matching digest is not approval. The capsule issuer
must verify qualification evidence and current identities; merely supplying
nonzero digests does not create qualification. No default capsule is provided.

Runtime files must be root-owned single-link regular files, with no special or
group/other-write bits. The runtime is a dedicated flattened file closure (no
symlinks), containing /usr/bin/git, /usr/bin/node,
/usr/libexec/ogw-worker, /validator/entry.mjs, loader/libraries, empty /empty,
/work, /input/bundle and /oldroot mountpoints and an ordinary empty /dev/null for
Git config reads. It contains no host /proc, secrets, journal, other jobs or socket.
The supervisor maps real host /dev/null to broker standard FDs before pivoting.
The native runtime-inventory hash starts with ASCII
`offline-git-runtime/v2\n`, then the unambiguous v2 tree grammar: `[` + uint64 child count + sorted entries
+ `]`. Each entry is uint64 basename-byte length + unsigned basename bytes +
`D` followed by a complete recursive tree, or `F` + uint64 file length + SHA256
file bytes. Every directory, including the root and empty directories, has its
own count and end marker. All uint64 values use network order. Maximum4096 entries/depth16/512MiB
aggregate, any file256MiB. The build manifest records ELF loader/library hashes;
it is not itself a runtime inventory or qualified installation manifest.

The fixed validator entry must exist, match the pinned held inode/digest, and be
part of the admitted closure. There is no production test-mode flag or caller
module/callback. AGE29 implements no validator semantics. AGE28 may later supply
its module through this fixed entry, within its own authorized scope; changing
that runtime closure invalidates capability identity and requires affected AGE30
requalification. A separately hashed native/test driver may exercise containment
in AGE30 but must never be labeled production-validator qualification.

## Isolation, resources and lifetime

One import uses one protected cgroup, private network/mount/PID/IPC/UTS namespaces,
private propagation and a pivoted runtime with old root detached. Worker UID/GID
10002 has no supplementary groups/capabilities, has no-new-privileges, and runs
fixed architecture-checked seccomp denial of networking/socket creation/FD
transfer and namespace/mount/ptrace/escape surfaces. The broker makes its private
validator socket before applying seccomp; Git inherits pipes, never that socket.
The native PID1 broker starts only the fixed Node/validator and fixed Git FD.
All semantic parsing/expansion must occur inside that same cgroup and namespaces.

The root supervisor and its independent lifetime guardian remain outside the
hostile cgroup. Guardian observes controller death and launcher lifeline, kills
the same held group, and acts as subreaper. The outer trusted launcher must also
retain independent whole-group kill authority if guardian itself dies. This
source does not install or authorize that launcher. Missing support denies.

| Resource | Inclusive contract |
| --- | --- |
| Worker CPU rate | cpu.max=20000 100000; cpu.max.burst=0 |
| Cumulative worker CPU guard | usage_usec>=8000000; sampled before/after phases and <=10ms supervision loop |
| Aggregate CPU ceiling | 10000000us including controller/setup/output/settlement reserve |
| Work wall | 30000ms monotonic from before input/admission work |
| Kill/reap tail / outer owner | 2000ms / 40000ms from session start |
| Worker memory / swap | 536870912 bytes / zero; memory.oom.group=1 |
| Worker PIDs | 8 including Node threads, broker and Git children |
| Machine output / diagnostics | 268435456 / 1048576 bytes cumulative |
| Raw object | 8388608 bytes plus at most256 framing bytes |
| Object/tree reads / output frames | 20000 / 65536 cumulative |
| Persistent writable filesystem | <=268435456 bytes and <=65536 inodes, finite ext4 |

**CPU qualification is unresolved, not established by final counter checks.** A
polling watchdog, the 8s guard or final <=10s counter is not a proof of preventing
overrun. AGE30 needs a kernel-specific upper bound including per-CPU quota slack,
setup/hash work, parallelism, scheduler starvation, the guardian/controller
reserve, output processing and the entire kill tail. This implementation's worker
counter does not account the controller/guardian; their bounded contribution must
be established independently in the lifetime dossier. Refuse operational admission
without that dossier; reduce quota/margin or return for explicit mechanism review
if the sum cannot be proven <=10s. Do not widen the ceiling or claim host PASS.
The eight-PID limit may deny an ordinary Node build that creates too many threads;
AGE30 must choose/qualify a compatible fixed Node closure, never raise the limit.

## Protocol and validator placement

OGW1 messages are one packet per frame on inherited SOCK_SEQPACKET. Header208:
magic4, uint16 version1, uint16 opcode, uint32 request sequence, uint32 payload
length, then the six 32-byte bindings. All integers are network order. Control
<=16KiB, DATA packets<=64KiB including header. Reject unknown/duplicate/reordered
requests, extra bytes, wrong bindings or payload lengths, overflow and truncation.
DATA packets and terminal END echo the current request sequence, stay cumulative
and preserve binary bytes. EOF/error poisons the channel; requests are never retried.
Clients require a launcher-assigned socket timeout; there is no timer bypass option.

Host API `createOfflineGitClient({channelFd,binding})` exposes only
open/step/settle/adopt/observe. Privileged channel supports OPEN (32-byte host-issued
inbox handle), then after validator exit SETTLE, then ADOPT (exact native inventory
digest). OPEN's response arrives only after worker settlement and contains the
native inventory digest. No Git operations are accepted from the external host
while the in-session validator owns execution. The validator obtains FD3 protocol,
FD4 capsule read-only, FD5 sealed input read-only, and uses step/settle with the
same bindings on that **distinct** channel. The trusted host and in-worker client
are separate capabilities, not a forwarded command stream. OBSERVE is reserved
and currently refused (UNKNOWN); there is no restart-success or repair API.

Validator operation sequence is INIT -> INDEX_PACK -> VERIFY_PACK -> FSCK ->
bounded OBJECT/TREE reads -> SETTLE. Invalid/repeated stage poisons the session.
INDEX_PACK has two uint64 values (offset/length within the sealed whole bundle);
OBJECT/TREE have exactly20 raw OID bytes, converted to lowercase hex internally.
No paths, revision expressions, refspec, argv, environment, cwd, limits or executable
selection are accepted. Machine output is raw size-framed data. OBJECT returns
the fixed Git batch response (type/length/raw bytes); TREE requests type tree.

Every Git argv starts with `/usr/bin/git --no-pager --git-dir=/work/repo
-c core.hooksPath=/empty -c gc.auto=0 -c maintenance.auto=false`, followed only by:

| Stage | Fixed suffix |
| --- | --- |
| INIT | init --bare --object-format=sha1 --template=/empty --quiet /work/repo |
| INDEX_PACK | index-pack --stdin --strict --max-input-size=33554432 |
| VERIFY_PACK | verify-pack -v /work/repo/objects/pack/pack-HASH.idx |
| FSCK | fsck --strict --full --no-reflogs --no-dangling |
| OBJECT | cat-file --batch (stdin is host-encoded40-hex OID plus LF) |
| TREE | cat-file tree HOST_ENCODED_OID |

Pack HASH comes only from exact `pack<TAB>40hex<LF>` index-pack output. No fetch,
checkout, unbundle, thin repair, ref mutation, external diff or approval/grant effect.
Environment is compiled in worker.c: fixed locale/TZ/PATH, private HOME/TMP,
no system/global config/prompt/replacements/lazy-fetch/protocols/optional locks.

## Custody and failure semantics

The code constant root is
`/var/lib/github-app-agent-gateway/offline-import-v1`, with UID1000 mode0700
inbox/quarantine/candidates/control. Ancestors are root-owned and non-agent-writable.
The dedicated persistent ext4 volume covers ALL writable storage and inodes;
retained candidates consume capacity. No spill, quota widening, tmpfs durability
claim or cross-device copy fallback. Control contains a preallocated single-link
0600 UID1000 evidence.reserve file of exactly1MiB (allocated blocks verified),
unreachable by workers. It provides bounded preallocated phase-evidence space when
the filesystem is full. Durable create-exclusive session.lock covers all phases;
stale locks and staging block. Operator resolution requires separate authorization.

Native openat2 BENEATH/NO_SYMLINKS/NO_MAGICLINKS/NO_XDEV plus statx mount-ID and
dev/inode checks bind files to held directories. Nonblocking opens avoid FIFO
hangs before type checks. Input is regular0600/nlink1, copied into an exclusive
host-owned file with streaming SHA256, source pre/post stat, fsync/full destination readback and a second content hash
from the held source FD, bracketed by the original identity. Same-size source
mutation is rejected even when timestamp metadata is indistinguishable.
Only that held copy is used; worker sees it via read-only bind and readonly FD.
Worker can write only session/work, with no seal/control/candidate access.

Before adoption, positive same-cgroup populated0 and leader/descendant reap are
required, then worker mount/FD holders are gone. Custody changes owned output to
UID1000/0700 directories/0600 single-link files, inventories exact bytes and identity,
fsyncs files/nested directories and binds inventory to all six session digests.
This generic inventory attests bytes/custody only: AGE28's pinned validator and
trusted host must enforce the allowed semantic repository/receipt inventory.
Native renameat2(RENAME_NOREPLACE) adopts the whole directory on the same device
and mount, fsyncs BOTH parents, rereads the final inventory, and durably releases
the lock before the first successful response. Unsupported syscall/filesystem,
EXDEV or existing target has no fallback. SHA256 here does not verify Git SHA1
object semantics; that is AGE28 work.

Any malformed input, uncertain settlement/rename/fsync/I/O/cancellation/crash is
UNKNOWN with evidence retained. The current implementation deliberately maps all
native failures to exit70 rather than inferring safe retry. No automatic cleanup,
lock stealing, adoption, replay success, repair, journal consumption or overwrite.
Visible receipts after restart cannot prove a lost parent-fsync. Rollback disables
admission and invalidates qualification while preserving evidence; it does not
automatically remove storage or fall back to an older worker.

## Verification and remaining gates

Use an already provisioned unprivileged executable temporary directory:

```bash
node --test agents/scripts/offline-git-worker.test.mjs
node --test agents/docker/*.test.mjs agents/scripts/*.test.mjs
bash agents/scripts/test-resource-config.sh
```

The build uses only /usr/bin/cc and subordinate /usr/bin tools, hardened C17 flags,
source/runtime/compiler/linker/ELF inventories and fsync/readback. It installs
nothing and produces source-build artifacts with qualified:false. Compiler absence
is a mandatory test FAILURE, never a skipped PASS. Native FD/no-follow/no-replace
fixtures are real filesystem tests; wire/dispatch/state assertions are SYNTHETIC.
Sanitizers use the same source, compile-time test entry only. No production test
mode or injected syscall facade is enabled.

No actual namespace/cgroup/root smoke may be run by the Developer without separate
host authority. In this agent environment missing C compiler/headers prevents
native compilation; full source PASS therefore remains blocked until the same
exact source is built and independently reviewed in an authorized build fixture.
Additional fault/race/kernel containment coverage must be verified there; source
inspection/JavaScript tests do not substitute for those checks.

AGE30 must record exact human-approved merge, build/ELF/Git/validator/protocol/config
digests, kernel/architecture/cgroup/seccomp/filesystem and root UID/device/mount
mapping; externally observed network/socket/secret denial; aggregate boundary/+1
and CPU-bound proof; parent/controller/guardian death, daemon/double-fork kill/reap
and writer revocation; source/FD/mount substitution, no-replace races and ENOSPC/
short-write/fsync/rename/crash faults. A missing cgroup is UNKNOWN, not empty.
Process-kill tests alone are not power-loss proof. Changed closure/kernel/UID/mount
invalidates affected qualification. Initial test-driver facility qualification
does not qualify an absent production validator. AGE28 and operational use remain
blocked until the appropriate independent gates pass.

## R2 correction contract and source integration

R2 corrects the five findings at failed-review head
35d92bb693443bd1d731557c09104fe5a7bcadea. OGC2/version2 admission replaces OGC1;
old capsules are rejected. Both runtime and custody inventories use the explicit
v2 directory grammar above, under independent domains
`offline-git-runtime/v2\n` and `offline-git-custody/v2\n` (the latter
also prefixes all192 binding bytes). All old inventory/capability/qualification
hashes are invalidated, with no v1 compatibility fallback. OGW1 wire framing
itself stays version1; these inventory/capsule versions are distinct protocols.

Independent negative goldens for a/b containing byte x versus empty a/ plus
sibling b containing x:

| Tree | Raw v2 tree SHA256 | Runtime-domain SHA256 |
| --- | --- | --- |
| nested | c20ef1a80c71b6fe5b18cb517755317017f444f1ef67638f0f4dbe8d8c3088b5 | de31271d8e0b8878e4babea43c45c1e02550c6d1d0198b4272ce98e6b0dbf033 |
| sibling | fb75ef870ad78abaf00a8501cf0a90304a3560b5070ff420d363f76ff8d529e0 | 7ec9869cdec98d828c6b78326ccdef8a74d5ecc604a9a6d5ca4d6fe2125a05e1 |

The JS golden independently constructs literal bytes. Native fixtures call BOTH
production runtime closure and custody inventory code against actual disposable
trees and compare hardcoded hashes, including custody domain/bindings. Coarse
source metadata is masked only by a compile-time fixture seam; changed source
bytes must still reject by rehash. There is no production metadata masking.

The guardian now retains a controller pidfd and uses pidfd_send_signal, never a
numeric kill after reap. Already-reaped controllers are never signaled. JS/native
state now permits SETTLE only at stage4 and ADOPT only at stage5; adoption is
terminal, including SETTLE-after-ADOPT/repeated-SETTLE/repeated-ADOPT denial.

The existing two C fixtures now call the actual production dispatch_session,
execute, guard_controller and handoff_adopt functions. Their shared extraction
preserves root/qualification admission in the production entry; none of those
functions is a new external launcher/API. Fixture-only compile constants relocate
/work and /empty into a disposable CWD and use the test owner's UID. Those
constants cannot override production builds, and no operational test-mode flag
exists. The offline production build never defines OGW_TEST.

Source coverage present (execution requires a compiler):

- A real self-contained SHA1 bundle from the Node fixture goes through production
  INIT/index-pack/verify-pack/fsck/object/tree protocol stages and real held-FD Git
  execution. The fixture verifies original raw commit/OID after import.
- Actual broker/validator-peer processes cover valid settlement, replay/cross-binding
  rejection, validator EOF/death and broker kill/EOF without a success response.
- Actual guardian/pidfd paths cover normal/nonzero controller exit and loss of the
  outer lifeline. The R3 owner-loss fixture closes both inherited pipe ends in
  the forked non-owner controller, leaving the simulated launcher as the sole
  writer; that launcher then closes its writer. It requires monotonic completion
  in less than3000ms (the2000ms settlement budget plus1000ms fixture allowance),
  with a separate5s fail-fast alarm, so the40s outer timeout cannot pass this
  case. It observes exactly one controller reap with SIGKILL, the expected kill
  action, terminal pidfd readiness, ECHILD and post-reap pidfd ESRCH. The earlier
  R2 fixture retained a child writer and could pass after40s; its passing result
  is not evidence of owner-loss cancellation. No separate outer-timeout test is
  claimed by this case. Regular files explicitly model cgroup identity/populated/kill
  observations; these observations are SYNTHETIC, not actual cgroup enforcement.
- The production adoption handoff, not a reimplemented transaction, runs in a
  disposable child: successful receipt plus all eight fsync positions with EIO,
  exit before fsync, and exit after fsync (24 interrupted variants). Tests require
  no successful final acknowledgement, retained evidence/stage or destination,
  and no overwrite/replay success for a visible destination. These are process
  crash/source tests, not simulated power-loss or storage durability proof.

These tests do not bypass or qualify root capsule admission, namespaces/seccomp,
actual kernel resource controllers, the separately installed lifetime owner,
guardian death under that owner, or intended-host AGE30 acceptance. Those paths
still need the separately authorized compiler-equipped/disposable kernel fixture;
unavailable native checks remain failures. Neither source fixture labels nor a
future passing compiler run can be reported as AGE30 PASS.
