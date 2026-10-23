# Agent resource limits (K8S-TEST #3)

This is a reviewed configuration and trusted-host runbook, not authorization to
restart agents, migrate state, mount filesystems or change credentials. The owner
must approve rollout separately. Never run exhaustion against operational services,
volumes or workspaces.

## Defaults and evidence

| Service | CPU ceiling | Memory (processes + cache) | Memory + swap total | Persistent HOME backing image |
|---|---:|---:|---:|---:|
| dispatcher-planner | 1.0 | 2 GiB | 2 GiB (no swap) | 512 MiB |
| developer-a | 4.0 | 8 GiB | 8 GiB (no swap) | 2 GiB |
| reviewer-a | 2.0 | 4 GiB | 4 GiB (no swap) | 1 GiB |

`DISPATCHER_`, `DEVELOPER_`, `REVIEWER_` prefixes expose `CPUS`, `MEM_LIMIT` and
`STATE_BYTES` in `.env.example`. Compose uses service-level `cpus`, `mem_limit` and
`memswap_limit`; it does not depend on Swarm or `deploy.resources`. Swap total tracks
the same MEM_LIMIT variable, including overrides. CPU is a CFS time ceiling, not
exclusive cores or a reservation. Memory limits include descendants, not just the
listener. An OOM may kill a child or the listener; normal restart policy remains.

Owner read-only host evidence from 2026-10-23 (Buzz events
`48cc13e8e72b6408058ba20cf1d177fccc1f03f510aa9607d198201c438b270e` and
`fb36cf6452834e465716bae83a331765bc40778039fcfcfec6c96005958baf38`):
12 CPUs, 62 GiB RAM (~42 GiB available), 8 GiB swap, Engine 29.1.3,
Compose 2.40.3, cgroup v2/systemd, CPU/memory/swap/PID limits supported. HOME usage
was Dispatcher 228 MiB, Developer 207 MiB, Reviewer 315 MiB. Host `/home` and Docker
storage are ext4 without quota options; fallocate/losetup/mkfs.ext4 are installed.
This report is sizing evidence supplied by the owner, not a benchmark run by this
change. The aggregate agent ceiling is 7 CPUs / 14 GiB memory and 3.5 GiB state
backing files. Leave room for Gateway, Docker, the kernel and other host workloads;
Gateway has not been resized here. Measure real builds before changing defaults.

## Persistent state choice

HOME is a bind mount of a separate fixed-size, preallocated ext4 loopback image for
each role. The filesystem enforces data and inode capacity. Usable bytes are lower
than image size because of filesystem metadata. No existing state image is resized
or reformatted by the provisioner. Exhaustion returns ENOSPC; it does not spill into
an unlimited host directory. Images and their parent directory are root-owned and
private; agents see only their mounted filesystem, without loop devices or a Docker
socket. HOME is UID/GID 10001, mode 0700. Mounts use nosuid,nodev, while permitting
execution needed by provider caches. Credentials remain separate read-only mounts;
the entrypoint copies only the same writable runtime files as before.

A size-limited tmpfs is simpler, but loses all HOME data on stop/start, restart,
recreate or host reboot. That includes provider sessions/cache and the Dispatcher's
durable pending handoff intents. tmpfs is also charged against container memory and
can OOM before its size limit; allowing swap can persist tmpfs pages to disk. It is
therefore unsuitable for this reliability contract. Persistent HOME keeps journals,
sessions and cache across restarts, subject to ordinary crash recovery and storage
health. ext4 page cache is still charged to the memory cgroup and can be reclaimed;
state storage is a disk limit, not additional RAM. Full HOME can prevent startup or
receipt writes: preserve pending intents and reconcile authoritative effects before
retrying, never delete the journal to reclaim space.

Host project quotas on a dedicated ext4/XFS filesystem could preserve persistence
without loop devices, but the reported host filesystems do not enable quotas.
`storage_opt.size` depends on a compatible storage driver/backing filesystem and
does not quota a normal named volume. A dedicated fixed-size block device is also
valid, but would need separately reviewed provisioning. This implementation chooses
loopback files so it works without changing the host's filesystem quota policy.
There is no automatic fallback to an unbounded named volume or directory.

## Host prepare and preflight (separate approval required)

Prerequisites: trusted Linux host, Node 22, root mount/loop privileges, ext4 tools,
fallocate, findmnt, losetup, mount/umount, enough free disk for the aggregate images,
and the existing approved runtime root. Do not grant these privileges to agents.
The new tool never calls sudo itself, reads credentials, touches jobs, edits fstab,
or starts containers. Use reviewed code and a trusted host `.env` as the ordinary
host owner (never source arbitrary task-provided shell files):

```bash
cd agents
set -a
source ./.env
set +a
# Existing runtime provisioning must already have established AGENT_RUNTIME_ROOT.
sudo node scripts/state-storage.mjs prepare "$AGENT_RUNTIME_ROOT" \
  "${DISPATCHER_STATE_BYTES:-536870912}" \
  "${DEVELOPER_STATE_BYTES:-2147483648}" \
  "${REVIEWER_STATE_BYTES:-1073741824}"
sudo node scripts/state-storage.mjs check "$AGENT_RUNTIME_ROOT" \
  "${DISPATCHER_STATE_BYTES:-536870912}" \
  "${DEVELOPER_STATE_BYTES:-2147483648}" \
  "${REVIEWER_STATE_BYTES:-1073741824}"
sudo ./scripts/preflight.sh ./.env
bash ./scripts/test-resource-config.sh
```

The two invocations are idempotent at unchanged settings. `check` validates all
three images (regular, root:root/0600, exact length, preallocated), exact loop backing
files, zero offsets/size limits, rw ext4 nosuid/nodev mounts, filesystem capacity and
HOME ownership. A private exclusive provisioning lock prevents concurrent changes;
only this lock is transiently written by `check`. Symlink/noncanonical/protected
paths, different image sizes, wrong mounts and nonempty unmounted targets fail.
Only an exclusively created `.img.creating` file can be formatted, then fsynced and
renamed to `.img`. Partial creation or an orphan lock requires host inspection;
never remove/reformat unknown existing data to retry. A power loss between creating
and initializing a new filesystem can require explicit ownership repair after host
verification. No recursive chown is performed by this tool.

The mount paths are `${AGENT_RUNTIME_ROOT}/state-storage/<service>`, backed by
`<service>.img` beside them. Underlying unmounted target directories are root-owned
mode 000. Compose `create_host_path: false` rejects missing paths. The image
entrypoint checks ext4 filesystem capacity before copying credentials; an ordinary
unbounded host directory or tmpfs fails. This check complements host preflight;
it does not replace verification of the loop backing file or Docker cgroups.

After host reboot, run prepare/check **before** creating agents. Mount persistence
across reboot requires owner-managed boot ordering (for example a reviewed systemd
oneshot running prepare before the Compose service); this tool does not install a
boot service. Docker's automatic restart must not precede state mounts. A container
that bound an unmounted target must be recreated after the host mount is restored;
mount propagation is private. Missing/unbounded HOME fails closed rather than
silently accepting ephemeral or unlimited storage.

## Migration and rollback

The old named volumes are intentionally not deleted. Changing mount type requires
an owner-approved maintenance window; never copy a live journal while a handoff or
provider refresh is writing. Before rollout:

1. Record previous source SHA, immutable image IDs, resolved non-secret limits and
   each old HOME volume name using targeted inspect formats (not full inspect/env).
   Quiesce work, record pending intents, and stop only approved affected agents.
2. Back up each old HOME on the trusted host, preserving ownership, modes, hidden
   files and timestamps; treat the backup as private credential-bearing material.
   Keep the old volumes intact. Measure allocated usage and inode counts, including
   journal/session/cache data; choose larger STATE_BYTES **before first prepare**
   if the new filesystem cannot hold the data with headroom.
3. Prepare/check the three bounded filesystems. Copy each stopped persona's complete
   HOME from its old volume into its matching mount using a trusted-host tool such
   as `sudo rsync -aHAX --numeric-ids OLD_HOME/ NEW_HOME/`. Use actual inspected paths,
   never a guessed Docker root path. Do not copy into an unmounted directory, delete
   originals or print credential files. Verify journal file hashes privately and
   ownership/modes, then run preflight again.
4. Build reviewed images under distinct test tags; both Dockerfiles add the HOME
   check, while AGE #3 pins/ACP bundled resolution and Gateway settings stay intact.
   Run the isolated tests below before the separately approved recreation. Verify
   provider auth reload, native MCP, Buzz and journal continuation after restart.

If rollback is required, stop/quiesce affected agents first. Preserve the new
filesystems and copy any newer journal/session state back to the retained old HOME
or a private backup after reconciling pending effects. Never blindly resume an old
journal snapshot: it could resend completed effects. Restore previous Compose and
recorded immutable images only after that reconciliation. Version rollback retains
the AGE #3 procedure. To release mounts when no container uses them:

```bash
sudo node scripts/state-storage.mjs unmount "$AGENT_RUNTIME_ROOT" \
  "${DISPATCHER_STATE_BYTES:-536870912}" \
  "${DEVELOPER_STATE_BYTES:-2147483648}" \
  "${REVIEWER_STATE_BYTES:-1073741824}"
```

Unmount verifies the same backing files/mounts and does not delete images, backups,
volumes or credentials. No automated resize, migration, rollback or fsck repair is
provided. Size changes reject existing images; plan a stopped backup/migration to a
new reviewed filesystem rather than editing STATE_BYTES on an existing runtime.

## Verification and monitoring

Offline, from repository root:

```bash
git rev-parse HEAD
node --test agents/docker/*.test.mjs agents/scripts/*.test.mjs
bash github-apps/test-create-apps.sh
bash agents/scripts/test-resource-config.sh
```

The config test uses an empty environment and `.env` file, checks real Compose JSON
for defaults and overrides, and rejects zero CPU/unlimited swap or missing state
bounds. It does not start services. Optional `COMPOSE_BIN` selects a standalone
Compose executable. On the trusted test host also run the existing full build/smoke,
gateway provisioning and ownership/preflight suite, with distinct test image tags
as in the AGE #3 runbook. `test-provision-runtime.sh` now uses three disposable
64 MiB loopback filesystems so its preflight exercises the new requirement.

```bash
# Run only in a clean reviewed checkout with no operational .env; use a test .env.
source_sha=$(git rev-parse HEAD)
./agents/scripts/build-and-smoke.sh \
  "local/buzz-agent-claude:k8s3-test-${source_sha}" \
  "local/buzz-agent-codex:k8s3-test-${source_sha}"
bash agents/scripts/test-provision-runtime.sh
sudo bash agents/scripts/test-resource-limits.sh \
  "local/buzz-agent-codex:k8s3-test-${source_sha}"
```

The resource script uses a random separate Compose project and private mktemp root,
three new 64 MiB ext4 images, no network, no real credentials/workspaces and restart
policy `no`. Only fixture code is mounted read-only. Two workers check CPU throttling
at 0.25 CPU; the memory probe touches allocations under 256 MiB until Docker reports
exit 137 **and** OOMKilled. The state probe writes to ENOSPC below 64 MiB, deletes
only its filler file, verifies a durable marker across container restart and
filesystem unmount/remount, and checks cgroup v2 memory/swap values. Tests wait at
most 45 seconds per container. Traps tear down only this project, then verified
fixture mounts; cleanup failures preserve the fixture directory for host inspection
and fail the run. No system-wide prune or detach-all is used. SIGKILL/power loss can
leave fixtures: inspect their recorded unique root/project before manual cleanup.
Do not apply test limits or exhaustion workloads to operational containers.

On an approved deployment, monitor without dumping environment/credentials:

```bash
cd agents
ids=$(docker compose ps -q dispatcher-planner developer-a reviewer-a)
docker stats --no-stream $ids
docker inspect --format '{{.Name}} CPU={{.HostConfig.NanoCpus}} Memory={{.HostConfig.Memory}} MemorySwap={{.HostConfig.MemorySwap}} OOM={{.State.OOMKilled}} Restarts={{.RestartCount}}' $ids
docker inspect --format '{{.Name}} {{json .HostConfig.Tmpfs}} {{range .Mounts}}{{if eq .Destination "/home/agent"}}HOME={{.Type}}:{{.Source}} RW={{.RW}}{{end}}{{end}}' $ids
# Expected CPU NanoCpus: 1000000000 / 4000000000 / 2000000000;
# memory == MemorySwap: 2147483648 / 8589934592 / 4294967296.
docker compose exec -T developer-a sh -c \
  'cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/memory.events; df -h /home/agent; df -i /home/agent'
# Repeat for the other two roles; swap.max must be 0.
```

Use host `state-storage.mjs check` and `findmnt --mountpoint` to validate backing
mounts, not Docker stats alone. Record reviewed head SHA, image IDs, effective
cgroups, mount checks and disposable test results. `docker stats` may subtract
cache; it is not proof of the kernel hard limit. An ENOSPC or increased OOM/restart
counter needs investigation; do not automatically delete sessions/journals or raise
limits. Verify host free disk, memory and inode headroom as well.

## Remaining shared-host / unattended gate

This bounds agent process memory/CPU and every HOME, while keeping the existing
bounded `/tmp`, default `/dev/shm`, PID and log limits. The Developer's writable
`/workspace` bind mount is separate from HOME and is **not** given a disk quota by
this change. Builds there can still fill host disk. Gateway sizing, network egress
controls and host-wide I/O budgets are also separate. Before shared-host/unattended
use, quota the writable workspace separately, validate the real kernel/daemon and
boot ordering, independently review migration/recovery, and complete live restart
and journal continuation acceptance. Static tests alone do not establish enforcement.

## References

- [Docker Compose service limits](https://docs.docker.com/reference/compose-file/services/)
- [Docker memory/swap and CPU constraints](https://docs.docker.com/engine/containers/resource_constraints/)
- [Docker tmpfs persistence and memory accounting](https://docs.docker.com/engine/storage/tmpfs/)
- [util-linux mount loop support](https://man7.org/linux/man-pages/man8/mount.8.html)
- [util-linux losetup safety and backing-file inspection](https://man7.org/linux/man-pages/man8/losetup.8.html)
- [e2fsprogs mke2fs filesystem sizing](https://man7.org/linux/man-pages/man8/mke2fs.8.html)
