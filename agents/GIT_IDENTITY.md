# Persona Git author identity

Git identity is now required before agent startup. Existing deployments without a
mounted managed `gitconfig` will fail closed, even if their persistent HOME contains
an older identity. This is an intentional migration requirement; do not roll out
these images until the approved mapping has been provisioned and preflight passes.

## Input and installation

Set `AGENT_GIT_IDENTITY_MANIFEST` in the external runtime environment to an absolute
path outside the checkout. Use `git-identities.example.json` as the **schema only**:
its `*.example.test` identities are test fixtures, not approved production identities.
An operator must supply approved names and emails for `dispatcher-planner`,
`developer-a`, and `reviewer-a`. Do not infer App bot IDs, use a host's global Git
configuration, or commit/log personal email addresses. This code does not decide
whether an address belongs to an approved bot; that remains an operator input check.

The manifest contains exactly three `{agentId, name, email}` records under
`identities`. Missing/extra personas or fields, empty/trimmed values, control/format
characters, angle brackets, and duplicate names or emails (case-insensitive) fail.
Values are never included in validation diagnostics. Quote/backslash characters
are escaped when rendering Git configuration.

From the repository root, the host operator validates input and performs normal
provisioning with the existing external environment file:

```bash
node agents/docker/git-identity.mjs validate /absolute/path/git-identities.json
bash agents/scripts/provision-runtime.sh /absolute/path/runtime.env
sudo bash agents/scripts/preflight.sh /absolute/path/runtime.env
```

Normal provisioning retains its canonical/disjoint path checks, common flock and
sudo boundary. The mapping is validated before provisioning mutations. Under the
lock, all three existing Git files are checked for conflicts before layout/token
changes. Each persona receives a directory owned by `10001:10001` with mode `0700`
and a `gitconfig` owned by `10001:10001` with mode `0600`. Each file is staged next
to its destination and renamed atomically. Repeating the same mapping produces
identical content. This is per-file atomicity, not a three-file transaction: on an
I/O failure, keep agents stopped, correct the fault and rerun the same manifest.

The identity-only helper can also install or check a mapping without generating
Gateway tokens (arguments must be canonical, disjoint directories, in persona order):

```bash
sudo node agents/docker/git-identity.mjs install /absolute/path/git-identities.json \
  /absolute/runtime/dispatcher-planner/credentials \
  /absolute/runtime/developer-a/credentials \
  /absolute/runtime/reviewer-a/credentials
sudo node agents/docker/git-identity.mjs check /absolute/path/git-identities.json \
  /absolute/runtime/dispatcher-planner/credentials \
  /absolute/runtime/developer-a/credentials \
  /absolute/runtime/reviewer-a/credentials
```

Use this low-level helper only under the same host provisioning lock and with
quiesced agents; the production entrypoint for host setup remains
`provision-runtime.sh`. It does not provide a hostile-writer filesystem sandbox.
Symlinks in any component, hardlinked/nonregular Git files, and conflicting existing
content are rejected. Do not run concurrent provisioning or allow writers to swap
paths while the host is installing files.

## Existing installations, update and rollback

1. Obtain approval for the maintenance window and mapping. Preserve the previous
   image, manifest and each credential-side `gitconfig` with its ownership/mode in
   restricted operator storage; never paste their contents into logs or chat.
2. Stop the affected agents using the existing approved host procedure. Do not
   recreate credentials, Gateway identities or persistent state. Existing custom
   Git files (including include/signing/helper configuration) cause a conflict;
   retain them for explicit operator reconciliation, rather than overwriting them.
   Move a conflicting file to the restricted backup only after approval. The
   generated file intentionally contains only the persona marker and
   `user.name`, `user.email`, `user.useConfigOnly=true`.
3. Provision the approved mapping and run preflight. For existing installations
   where only identity is changing, use the identity-only helper under the common
   lock instead of rerunning unrelated token provisioning. A changed mapping is
   also a conflict and follows the same backup/reconciliation steps.
4. Separately authorize image rollout/container recreation. At every startup the
   entrypoint verifies the mounted file's persona, exact generated format,
   UID/GID/mode and directory, then atomically replaces `${HOME}/.gitconfig` before
   reading other credentials. No stale HOME fallback is allowed. The credential
   bind remains read-only. Running processes are not hot-reloaded: restart through
   the approved host procedure to apply a new mapping. Preserve the state volumes.
5. Verify the actual mounted persona and effective Git identity privately inside
   each container, including a local fixture commit and recreation. Capture only
   pass/fail evidence, container/image IDs and commit IDs in public records.
6. If validation fails, keep the affected agents stopped. Restore the saved
   credential-side mapping and previous image using the existing rollback plan,
   preserving state mounts; restart and verify identities/connections. Never
   delete volumes or reissue credentials as an identity rollback.

The entrypoint replaces the complete HOME Git file. Previously manual signing or
other global settings therefore need explicit operator review before migration;
this change neither introduces signing nor decides a new signing policy. Optional
`git-credentials` handling still adds its existing credential helper after identity
validation. The mounted source must remain in the generated format.

`useConfigOnly=true` prevents Git from guessing an identity. It does **not** prevent
explicit overrides via repository config, environment variables, `git -c`, includes
from other config scopes, or later user edits. An identity is author metadata, not
an authorization or impersonation boundary; Gateway jobs still control GitHub
access. Check effective values in the actual repository before a live commit.

## Local and host verification

No production credentials or actual persona addresses are needed for fixtures.
The Node suite runs as UID/GID 10001 (the agent image); it tests real Git commits,
repeated startup with persistent HOME, missing/shared/invalid identities, conflict
preservation, modes, symlinks and hardlinks. Run all local Node package tests:

```bash
node --test agents/docker/*.test.mjs
bash github-apps/test-create-apps.sh
```

On a trusted test host with Node 22, jq, Git, sudo and Docker, from the reviewed
checkout with no live `agents/.env` (build/smoke source that file if present):

```bash
git rev-parse HEAD
bash agents/scripts/test-provision-runtime.sh
bash agents/scripts/build-and-smoke.sh
```

The first script uses isolated temporary fixture paths and sudo for ownership/GID
checks; run as the normal host user. The second builds both images, runs the Node
identity suite as UID 10001, checks all three distinct container identities with
local commits, and runs existing proxy/Gateway smoke tests. It needs network access
for image/package builds but never starts the production Compose project. Running
`node --test agents/docker/*.test.mjs` directly on a host with another UID will fail
ownership checks; use the image suite there. These image and privileged checks must
be reported as pending if Docker/sudo are unavailable, never as passed.

## GitHub attribution acceptance remains separate

Local Git commits use the effective persona name/email for author and committer.
Gateway branch commits are created by the Gateway's GitHub App/API flow and do not
read the container's `.gitconfig`; API defaults may identify the App actor instead.
Verify both author/committer metadata and GitHub's displayed account on actual
approved commits before accepting live attribution. Do not guess a bot noreply ID.
The code/fixture PR does not complete AGE #2's operational acceptance: approved
production mapping, container recreation/persistence and actual GitHub attribution
remain explicit host/reviewer follow-ups. Signing decisions are outside this change.
