# Repository extraction — Kaneo #12

Source: `darimuri/k8s-test` main at
`619f99df92aa7fb707635013b900b6bca444bd9f`.
Target base: `darimuri/agent-orchestration` main at
`9a7658010a3068642d67e4ac4848416d8f404347`.
Task: `xbb7u0bj8sc1p30ewc6709yb` ([source issue #19](https://github.com/darimuri/k8s-test/issues/19)).
Jobs: `kaneo12-agent-orchestration-developer` and `kaneo12-k8s-test-developer`.

## File correspondence

`MIGRATION_FILES.json` lists all 47 tracked source files, their Git blob IDs and
modes, destination paths, destination SHA-256 hashes and whether content changed.
The mapping removes only the `agent-orchestration/` prefix. It includes the
tracked `.env.example`, never a real `.env`, credentials, runtime state, workspace
clones or source repository history. The initial target README is replaced by
the migrated overview. This document and the mapping are new migration artifacts.

Runtime images, version pins, Compose project name, service names, named volumes,
mount destinations and environment variable names are unchanged. Relative
`agents/` build contexts and prompt mounts retain their layout. The two host
provisioning scripts now resolve the repository root one level above `agents/`,
so path protection applies to the extracted checkout. Documentation entry paths
and GitHub App homepage URLs refer to the new repository. Cluster setup commands
that use `k8s-test/source.sh` and the existing GitHub App verification target
remain explicit external dependencies in `darimuri/k8s-test`.

## Validation before cutover

Run from the extracted checkout, recording its exact commit and command outcomes:

```bash
git rev-parse HEAD
node --test agents/docker/*.test.mjs
bash github-apps/test-create-apps.sh
bash agents/scripts/build-and-smoke.sh
bash agents/scripts/test-provision-runtime.sh
```

The build-and-smoke script runs both image builds, the proxy suite, entrypoint
smoke tests and Gateway provisioning tests. Docker is required. The isolated
runtime provisioning suite uses temporary fixtures and requires host sudo for
UID/mode checks. It must run under the authorized host role, not by granting an
agent more permissions. The host role must also run preflight against its existing
runtime environment and validate Buzz, Kaneo and assigned Gateway access. Never
include credential values in logs. No live provisioning or restart is part of
this extraction patch.

## Follow-up cutover and rollback

Do not remove the source implementation until the extracted revision passes all
checks and receives independent review. Then propose a separate `k8s-test` PR
that records the reviewed full target commit SHA, updates runtime source paths to
that pinned checkout and removes the original tracked implementation. Resolve
references against that source PR's actual base, including external host launch
commands; do not track moving `main` for operation.

The host role must preserve its existing environment file outside Git and retain
credential/state locations and the Compose project name `buzz-development-team`.
It must check resolved Compose paths before any separately authorized operation.
No copying, resetting or recreating named volumes is required by this migration.

Before cutover, rollback means abandoning the extraction proposal: the original
source remains untouched. After an authorized cutover, revert the source cutover
commit and have the host role restore the previous pinned checkout/Compose file
path and existing environment. Keep the same state and credential mounts; never
use `down -v`. Any operational restart remains a separate host responsibility.
