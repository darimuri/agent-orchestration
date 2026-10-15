# Kaneo #12 host validation

[한국어](HOST_VALIDATION.md)

Owner: dormael. Run against the exact extraction commit reported in Kaneo/Buzz,
not a moving branch. These steps produce evidence; they do not authorize cutover.
The original `k8s-test` runtime remains authoritative until validation and review.

## 1. Revision and prerequisites

On the trusted Linux host, use the prepared extraction worktree (the agent sees
`/workspace/darimuri/agent-orchestration-task12`; the host mount path may differ).
If validation uses another trusted checkout, its HEAD and tree must match the
reported extraction commit. Do not validate the empty target main branch.

The previously reported proxy 8/8 result was verified at
`693dbb36298d7f832c09546b2c64b7ba5756a79c`. The subsequent documentation
translation commit creates a new HEAD. Set `expected_sha` below to the **reported
final SHA of the checkout actually being validated**, and record that SHA in the
logs. Do not present the earlier test result as a rerun at the new HEAD. A
documentation-only change does not complete host validation.

```bash
cd /absolute/host/path/to/agent-orchestration-task12
expected_sha=REPLACE_WITH_REPORTED_EXTRACTION_COMMIT
[ "$(git rev-parse HEAD)" = "$expected_sha" ] || exit 1
[ -z "$(git status --porcelain)" ] || exit 1
for cmd in bash git node gh jq openssl python3 curl docker sudo flock realpath; do
  command -v "$cmd" >/dev/null || exit 1
done
docker info >/dev/null
docker compose version
sudo -v
```

Use Node 22 (the runtime image baseline), GNU coreutils and a Docker daemon the
host user may access. Image builds need network access to the existing pinned
base images and npm packages. No production credentials are needed for the App
mock suite or container smoke tests. The runtime provisioning fixture test uses
sudo to manage temporary UID 10001/1000 files, local fixture clones and cleanup;
run it as the normal host user, not as root. Do not install host tools or mount a
Docker socket into the agent as part of this procedure.

## 2. Isolated package tests and images

Ensure this validation checkout has no real `agents/.env`: build scripts source
that file automatically. Keep the existing runtime environment external and use
it only for the later preflight. Run from the repository root in a fresh shell
without AGENT_* build overrides so the checked-in defaults are tested.

```bash
[ ! -e agents/.env ] || exit 1
umask 077
validation_logs="$(mktemp -d /tmp/kaneo12-validation.XXXXXX)"
set -o pipefail
git rev-parse HEAD > "$validation_logs/revision.txt"
git status --porcelain > "$validation_logs/worktree.txt"
run_check() {
  local label="$1"; shift
  "$@" 2>&1 | tee "$validation_logs/$label.log"
  local rc=${PIPESTATUS[0]}
  printf '%s exit=%s\n' "$label" "$rc" | tee -a "$validation_logs/results.txt"
  return "$rc"
}
run_check proxy node --test agents/docker/kaneo-mcp-safe-proxy.test.mjs
run_check apps bash github-apps/test-create-apps.sh
run_check runtime bash agents/scripts/test-provision-runtime.sh
run_check images bash agents/scripts/build-and-smoke.sh
```

Run all four commands and retain each exit code, including failures. Expected:
proxy suite 8/8; `GitHub App bootstrap tests passed.`; `Runtime provisioning tests
passed.`; both image builds, proxy tests, `Container entrypoint smoke tests passed.`
and `Gateway agent provisioning tests passed.` in the images log, all exit 0.
The image script includes the complete Gateway provisioning suite. Tests that
cannot run are pending, not passed. Builds change local image tags/cache; run them
on a validation host or ensure no operational automation consumes those tags.
No `compose up`, restart, real provisioning or volume deletion belongs here.

## 3. Existing host configuration: read-only validation

Set an absolute path to the host's existing trusted environment file outside Git.
Its configured credential paths stay on the host. Do not paste its contents.

```bash
runtime_env=/absolute/host/path/to/existing-runtime.env
run_check preflight sudo bash agents/scripts/preflight.sh "$runtime_env"
run_check compose docker compose --env-file "$runtime_env" \
  -f agents/compose.yaml config --quiet
```

Expected exit 0 and `Preflight passed. No credential values were read or printed.`
The preflight performs presence, ownership, mode and configuration consistency
checks; it does not provision or restart services. `config --quiet` validates
without printing interpolated secrets. On failure, report the specific check;
do not repair permissions or change live configuration without separate approval.

## 4. Buzz / Kaneo / Gateway connection evidence

For already-running agents only, use the existing authenticated sessions. A
read-only Buzz CLI check inside the existing developer service can be run with:

```bash
run_check buzz docker compose --env-file "$runtime_env" \
  -f agents/compose.yaml exec -T developer-a sh -eu -c '
  export BUZZ_PRIVATE_KEY="$(cat /run/agent/credentials/buzz-private-key)"
  if [ -r /run/agent/credentials/buzz-auth-tag ]; then
    export BUZZ_AUTH_TAG="$(cat /run/agent/credentials/buzz-auth-tag)"
  fi
  if [ -r /run/agent/credentials/buzz-api-token ]; then
    export BUZZ_API_TOKEN="$(cat /run/agent/credentials/buzz-api-token)"
  fi
  exec buzz channels get --channel "$1"
' sh e04d48c5-f100-4e75-9362-aaac11094227
```

Expected: successful channel response. If no existing service is available, mark
this check pending; do not start one. Ask Developer A in the same Buzz thread to
run these native MCP calls and report only identity/repository/task status:

The exec shell loads authentication from the existing mounted files because it does
not inherit exports made by the running entrypoint. Do not use shell tracing or
print these variables. This command only reads credentials through the runtime
authentication flow and does not modify them.

```text
mcp__kaneo__get_task({"taskId":"xbb7u0bj8sc1p30ewc6709yb"})
mcp__github_gateway__github_gateway_identity({})
mcp__github_gateway__github_get_repository({"jobId":"kaneo12-agent-orchestration-developer"})
mcp__github_gateway__github_get_repository({"jobId":"kaneo12-k8s-test-developer"})
```

Expected: task #12 assigned to developer-a, gateway identity developer-a/developer,
and repositories darimuri/agent-orchestration and darimuri/k8s-test. Use only these
active jobs (expiry 2026-10-18T06:05:06Z), not old smoke assignments. Record Buzz
event IDs and the exact running image ID separately. Checks against existing
containers prove current connectivity, not that the newly built image has been
deployed. End-to-end checks of a new runtime require a separately approved isolated
validation instance or operational change; keep that acceptance item pending.

## 5. Evidence and release boundary

Record extraction commit SHA, host/runtime image IDs, command exit codes, private
log locations and remaining failures in Kaneo #12. Review logs for secrets before
sharing. Do not upload environment files, tokens, auth tags or credential outputs.
The developer will link evidence in the draft PR and request independent review.
Only after validation and review may a separate source PR pin the target revision
and remove the old implementation. Merge, deployment and operational restarts
remain outside this task's current authorization. See [MIGRATION.md](MIGRATION.md) for rollback.
