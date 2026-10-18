# Buzz/Kaneo development-team containers

This directory builds and runs the three bootstrap members proposed for the
Buzz/Kaneo development workflow:

| Service | Runtime | Default model | Workspace |
|---|---|---|---|
| `dispatcher-planner` | Claude Agent ACP | `claude-sonnet-5` | read-only |
| `developer-a` | Codex ACP | `gpt-5.3-codex` | read-write |
| `reviewer-a` | Claude Agent ACP | `claude-opus-5` | read-only |

The images contain `buzz-acp`, `buzz`, Kaneo MCP, the ACP adapter, and the
underlying Claude Code or Codex CLI. The Compose stack also runs the private
`github-app-agent-gateway` service. Startup does not install packages. Buzz
binaries come from the official multi-architecture `buzz-sprig` image pinned by
tag and manifest-list digest; they are not compiled separately in every image.

Prompts and credentials are deliberately absent from the image. Compose mounts
`prompts/` and one credential directory per agent read-only. The entrypoint copies
only provider runtime state that must be writable into the agent's private `/home/agent`
volume.

The default host runtime root is `${HOME}/buzz-agents`. Override `AGENT_RUNTIME_ROOT`
when the Docker host should store agent data elsewhere. Every managed runtime path must
be a canonical strict descendant of that root. GitHub App credentials use the separate
`GITHUB_GATEWAY_CREDENTIALS_BASE_DIR` boundary. Provisioning rejects protected,
symlinked, overlapping, and repository-checkout paths before any recursive ownership
or mode change.

## Automated host provisioning

On a new Docker host, copy and edit the environment file, then run the idempotent
provisioner as the host user. It invokes `sudo` only for files owned by the container
UIDs.

```bash
cp .env.example .env
$EDITOR .env
# First configure the required external AGENT_GIT_IDENTITY_MANIFEST (see GIT_IDENTITY.md).
./scripts/provision-runtime.sh
```

The script creates organization workspace roots, prepares credential directories,
initializes safe empty Gateway runtime files, and issues the Dispatcher, Developer, and Reviewer
Gateway bearer tokens. Existing workspace roots, runtime JSON, and bearer tokens are
preserved on repeated runs.

Before changing any runtime file, the provisioner requires `GITHUB_GATEWAY_IMAGE` in
`.env` to match the compatible image pinned by `.env.example`. Build that image and
update an older local `.env` first; this prevents a new role record from being written
for a Gateway version that cannot parse it.

It never creates or copies Buzz, Kaneo, Claude, Codex, or GitHub App private
credentials. It reports each missing file at the end. `jobs.json` also remains empty
until a trusted job assignment is added explicitly.

Add only the repositories required by active jobs. The trusted host creates a separate
full clone for every agent under `/workspace/<owner>/<repository>`:

```bash
./scripts/provision-agent-repository.sh darimuri/k8s-test
./scripts/provision-agent-repository.sh darimuri/github-app-agent-gateway main
```

The repository owner must match `AGENT_WORKSPACE_ORGANIZATION`. The Git URL is rendered
from `AGENT_WORKSPACE_GIT_URL_TEMPLATE`, so another GitHub organization or Git host can
be selected without changing the scripts.

Run its isolated portability and idempotency test with:

```bash
./scripts/test-provision-runtime.sh
```

## 1. Prepare organization workspaces

Each agent mounts a separate organization workspace root. Repository clones are added
under `<owner>/<repository>` and are never shared between agents. Do not mount linked
Git worktrees unless their common Git directories are also mounted at the exact paths
recorded in their `.git` files.

```bash
./scripts/provision-runtime.sh
./scripts/provision-agent-repository.sh darimuri/<repository>
```

The resulting host layout is:

```text
${HOME}/buzz-agents/<agent>/workspace/darimuri/<repository>
```

Only the Developer organization workspace root is mounted read-write. Dispatcher and
Reviewer receive separate clones through read-only mounts.

Image는 UID/GID `10001`로 실행된다. Linux bind mount는 numeric ownership을 그대로
유지하므로 clone한 뒤 해당 identity가 접근할 수 있도록 소유권을 변경한다.

```bash
sudo chown -R 10001:10001 "${HOME}/buzz-agents"/*/workspace
```

## 2. Prepare credential directories

Create a different directory for each identity with mode `0700`. Files should be
mode `0600`. Never place these directories inside a Git checkout.

Directory에 credential을 배치한 뒤 container identity로 소유권을 이전한다. 이후
credential을 rotation하는 trusted host keeper도 같은 수준의 권한을 사용해야 한다.

```bash
source ./.env

sudo chown -R 10001:10001 \
  "${DISPATCHER_CREDENTIALS_DIR}" \
  "${DEVELOPER_CREDENTIALS_DIR}" \
  "${REVIEWER_CREDENTIALS_DIR}"
sudo chmod 0700 \
  "${DISPATCHER_CREDENTIALS_DIR}" \
  "${DEVELOPER_CREDENTIALS_DIR}" \
  "${REVIEWER_CREDENTIALS_DIR}"
sudo find \
  "${DISPATCHER_CREDENTIALS_DIR}" \
  "${DEVELOPER_CREDENTIALS_DIR}" \
  "${REVIEWER_CREDENTIALS_DIR}" \
  -type f -exec chmod 0600 {} +
```

Required for every agent:

```text
buzz-private-key          Nostr nsec or hex private key for this one Buzz member
buzz-auth-tag             NIP-OA owner attestation for this one Buzz identity
kaneo-credentials.json    this agent's Kaneo MCP device credential cache
```

All three agents additionally require:

```text
github-gateway-agent-token    agent bearer token issued by github-app-agent-gateway
```

Claude agents require one of:

```text
claude-oauth-token        output provisioned by the trusted host credential keeper
anthropic-api-key         API key fallback
```

The Codex agent requires one of:

```text
codex-auth.json           file-based Codex login cache
openai-api-key            API key fallback
```

Optional files:

```text
buzz-api-token            relay API token when enforced
gh-token                  GitHub CLI token
gitconfig                 REQUIRED generated persona identity; see GIT_IDENTITY.md
git-credentials           Git credential-store file for a disposable PoC only
git-ssh-key               SSH private key
known_hosts               SSH known-hosts file
```

GitHub writes use the gateway MCP and GitHub App installation tokens retained inside
the gateway. The agent bearer token identifies the agent and role but is not a raw
GitHub credential. Do not add `git-credentials` or a general-purpose `GH_TOKEN` for
these workflows.

### Prepare the GitHub gateway

Clone and build the separate private repository with the tag referenced by `.env`:

```bash
git clone https://github.com/darimuri/github-app-agent-gateway.git \
  /srv/github-app-agent-gateway
git -C /srv/github-app-agent-gateway checkout --detach \
  196c5a384875e9f5434536342e5277ca6e73ec68
docker build -t local/github-app-agent-gateway:196c5a3 \
  /srv/github-app-agent-gateway
```

The image tag is the short form of the checked-out commit. Update the full commit and
image tag together when rolling the gateway forward.

`GITHUB_GATEWAY_ALLOWED_OWNERS=darimuri` restricts every job and installation-token
request to repositories owned by the `darimuri` organization. The gateway rejects a
different owner before calling GitHub. It also requests each installation token for
the job repository and operation permissions only, even though the Apps are installed
for all organization repositories.

Create a host runtime directory owned by the gateway container's UID `1000`. Copy the
example files from that repository, then replace the sample jobs with trusted job
assignments. `jobs.json` is the authorization boundary for repository, base SHA, PR,
head SHA, role, status and expiry.

```bash
sudo install -d -m 0700 -o 1000 -g 1000 "${HOME}/buzz-agents/github-gateway"
sudo install -m 0600 -o 1000 -g 1000 \
  /srv/github-app-agent-gateway/config/apps.example.json \
  "${HOME}/buzz-agents/github-gateway/apps.json"
sudo install -m 0600 -o 1000 -g 1000 \
  /srv/github-app-agent-gateway/config/agents.example.json \
  "${HOME}/buzz-agents/github-gateway/agents.json"
sudo install -m 0600 -o 1000 -g 1000 \
  /srv/github-app-agent-gateway/config/jobs.example.json \
  "${HOME}/buzz-agents/github-gateway/jobs.json"
```

Issue or rotate the Dispatcher, Developer, and Reviewer gateway bearer tokens without printing the
token values:

```bash
sudo node ./scripts/provision-gateway-agent.mjs \
  dispatcher-planner control \
  "${DISPATCHER_CREDENTIALS_DIR}" "${GITHUB_GATEWAY_RUNTIME_DIR}"
sudo node ./scripts/provision-gateway-agent.mjs \
  developer-a developer \
  "${DEVELOPER_CREDENTIALS_DIR}" "${GITHUB_GATEWAY_RUNTIME_DIR}"
sudo node ./scripts/provision-gateway-agent.mjs \
  reviewer-a reviewer \
  "${REVIEWER_CREDENTIALS_DIR}" "${GITHUB_GATEWAY_RUNTIME_DIR}"
```

The script writes each raw bearer token only to that agent's mode `0600` credential
directory and stores only its SHA-256 hash in `agents.json`. The default lifetime is
30 days; set `GATEWAY_AGENT_TOKEN_TTL_DAYS` when a different rotation window is needed.
It serializes all updates to the shared `agents.json` with
`GITHUB_GATEWAY_RUNTIME_DIR/.provision-gateway-agent.lock`; the host must provide
`flock`.

The upstream `codex-acp` adapter supports ChatGPT and API-key authentication, but the
current Buzz documentation recommends an API-key fallback because ChatGPT WebSocket
login can fail in some deployments. Keep `openai-api-key` available until the Phase 0
subscription-auth smoke test proves `codex-auth.json` works reliably in this image.

## 3. Configure and validate

```bash
cd agents
cp .env.example .env
$EDITOR .env
./scripts/provision-buzz-agent-identity.sh
sudo ./scripts/preflight.sh
docker compose config --quiet
```

The Buzz identity provisioner keeps each existing agent key, installs its NIP-OA
owner attestation, and publishes the agent profile plus the owner's signed
`kind:30177` `respond_to=owner-only` policy. Its helper image is built from the exact
Buzz source commit configured by `BUZZ_NIP_OA_SOURCE_COMMIT`. Verify the relay state
without publishing again with:

```bash
./scripts/provision-buzz-agent-identity.sh --verify-only
```

Preflight는 UID 10001 소유의 mode 0600 file 내용을 읽지 않고 검사하기 위해 root 권한이
필요하다. Credential 값을 출력하지 않고 file 존재 여부, numeric ownership, mode와
workspace 접근 권한을 확인한다.

## 4. Build and start

```bash
docker compose build
docker compose up -d
docker compose logs -f dispatcher-planner developer-a reviewer-a
```

`github-gateway` has no published host port. All three agents reach it as
`http://github-gateway:8787/mcp` on the private Compose network.

## Native MCP configuration

`ENABLE_KANEO_MCP=false` disables Buzz ACP's legacy single-command shortcut. At each
container start, `mcp/servers.json` is converted into the provider's native user
configuration:

| Runtime | Generated file | Servers |
|---|---|---|
| Dispatcher / Claude | `~/.claude.json` | Kaneo, GitHub gateway |
| Developer / Codex | `~/.codex/config.toml` | Kaneo, GitHub gateway |
| Reviewer / Claude | `~/.claude.json` | Kaneo, GitHub gateway |

Codex uses `bearer_token_env_var = "GITHUB_GATEWAY_AGENT_TOKEN"`. Claude stores the
literal header template `Bearer ${GITHUB_GATEWAY_AGENT_TOKEN}`. Neither generated file
contains the token value. Kaneo continues to read its private credential cache from
`~/.config/kaneo-mcp/credentials.json`.

All agent Kaneo registrations run through `kaneo-mcp-safe-proxy`. The proxy removes
`whoami` from `tools/list` and rejects a direct `tools/call` before it reaches
`@kaneo/mcp`. It does not log MCP payloads or forward upstream stderr, so the raw
`session.token` returned by `@kaneo/mcp` `0.1.11` cannot enter the model context or
container logs through this tool. This is a tool-output control, not credential
isolation: the Kaneo process still needs its own credential cache, so keep each
agent's credential directory private and independently revocable.

The generated formats follow the official
[Codex MCP configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
and [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

Inspect the generated registration after the containers start:

```bash
docker compose exec developer-a codex mcp list --json
docker compose exec reviewer-a claude mcp list
```

After changing the common MCP definition, endpoint or token, recreate the affected
container and send `!rotate` so the next ACP session reloads its native MCP catalog.

For a local build plus credential-free entrypoint smoke test:

```bash
./scripts/build-and-smoke.sh
```

This also runs the gateway provisioning checks for invalid TTL input, repeated
rotation, token-install rollback, and parallel Dispatcher/Developer/Reviewer provisioning.

Each image is version-pinned through `.env`. Update the pinned Buzz sprig image and
npm versions intentionally, rebuild, and run the smoke checks below before rollout.

## 5. Smoke checks

Inspect installed binaries without starting the listeners:

```bash
docker compose run --rm --no-deps --entrypoint bash dispatcher-planner -lc \
  'buzz --help >/dev/null && buzz-acp --help >/dev/null && claude --version && claude-agent-acp --version && command -v kaneo-mcp-safe-proxy >/dev/null'

docker compose run --rm --no-deps --entrypoint bash developer-a -lc \
  'buzz --help >/dev/null && buzz-acp --help >/dev/null && codex --version && codex-acp --version && command -v kaneo-mcp-safe-proxy >/dev/null'

./scripts/smoke.sh \
  "local/buzz-agent-claude:${AGENT_CLAUDE_CODE_VERSION:-2.1.278}" \
  "local/buzz-agent-codex:${AGENT_CODEX_VERSION:-0.154.0}"
```

두 개의 선택적 위치 인자는 검증할 Claude와 Codex image reference다. 생략하면 움직이는
`latest` tag가 아니라 위에 명시한 고정 기본 version을 사용한다.

After each Buzz identity is registered and added to the target channel, mention each
agent separately and confirm exactly one response. Verify that:

- Dispatcher and Reviewer cannot write their mounted repositories.
- Developer can write only its own clone and cannot push the default branch.
- each agent sees a different Buzz and Kaneo identity;
- the Developer cannot publish the Reviewer's required check;
- provider, Buzz, and Git credential content does not appear in Docker logs, Buzz,
  Kaneo, Git, or the workspace;
- Kaneo MCP tool 목록에 `whoami`가 없고 이름을 직접 지정한 호출도 security policy
  error로 거부되며, Docker log와 tool result에 raw session token이 나타나지 않는다.

Give all three agents an active gateway job, rotate their ACP sessions, then ask each
agent in one turn to:

1. list a known Kaneo project or task without calling `whoami`;
2. call `github_gateway_identity`;
3. call `github_get_repository` with its assigned `jobId`.
4. list and read a known GitHub Issue with the same `jobId`.

For an Issue write smoke test, let each role create a temporary issue or comment, update
it, close it, and reopen it. GitHub must show the corresponding Control, Developer, or
Reviewer App actor, and the gateway log must identify the same agent, job, repository,
and operation. Delete operations are intentionally unavailable.

The same session must show successful Kaneo and GitHub gateway tool calls. If only one
server appears, check that `BUZZ_ACP_MCP_COMMAND` is absent, inspect the generated file
above, verify the agent token has not expired in `agents.json`, and inspect
`docker compose logs github-gateway` for a sanitized authorization error.

## 6. 에이전트 대화 컨텍스트 초기화

Buzz membership과 container lifecycle은 LLM 대화 context와 별개다. ACP session은
`buzz-acp`가 소유하므로 owner는 container, Buzz key, profile, channel membership을
교체하지 않고 Claude/Codex 대화만 새로 시작할 수 있다.

### 수동 session rotation

신뢰할 수 있는 owner shell에서 대상 agent를 별도 mention으로 지정해 `!rotate`를
전송한다.

```bash
buzz messages send \
  --channel <CHANNEL_UUID> \
  --mention <AGENT_PUBLIC_KEY> \
  --content '!rotate'
```

발신자는 `BUZZ_ACP_AGENT_OWNER`와 일치해야 한다. 본문은 공백을 제외하고 정확히
`!rotate`여야 한다. `@Developer A !rotate`처럼 agent 이름을 본문에 직접 넣은 메시지는
같은 control command가 아니다. agent container가 private key를 이미 갖고 있다는
이유로 agent identity를 사용해 이 명령을 실행하지 않는다. 신뢰할 수 있는 human owner
identity를 사용한다.

진행 중인 turn이 없으면 `buzz-acp`가 cached ACP session을 즉시 무효화한다. turn이
진행 중이면 해당 turn을 취소하고 task가 반환될 때 session을 무효화한다. 다음으로
수락된 mention이 새 provider session을 생성한다. 현재 release는 실행 결과를 harness
log에만 기록할 수 있으므로 필요하면 다음처럼 확인한다.

```bash
docker compose logs -f developer-a \
  | rg '!rotate received|rotating session|invalidated idle session'
```

기본 `channel` 정책에서는 agent가 channel 전체에서 provider session 하나를 공유하며,
rotation은 그 channel 범위 session을 초기화한다. 대화를 canonical thread별로 분리하려면
`x-agent-common.environment`에 다음 값을 설정하고 service를 다시 생성한다.

```yaml
BUZZ_ACP_SESSION_POLICY: thread
```

이후 rotation할 때 thread root를 지정한다.

```bash
buzz messages send \
  --channel <CHANNEL_UUID> \
  --reply-to <THREAD_ROOT_EVENT_ID> \
  --mention <AGENT_PUBLIC_KEY> \
  --content '!rotate'
```

두 정책 모두 direct message는 conversation 범위를 유지한다. Rotation은 mention된 agent
하나만 대상으로 한다. multi-agent channel에 공통 작업 경계가 필요하면 각 member를
개별적으로 rotation한다.

### Rotation 후에도 유지되는 상태

`!rotate`는 provider conversation session을 초기화하며 agent의 모든 상태를 지우지는
않는다.

| 상태 | `!rotate` 이후 |
|---|---|
| Claude/Codex ACP 대화와 tool-call transcript | 새 session 생성 |
| Buzz message와 서명된 audit history | 유지 |
| Workspace file, Git 상태와 일부만 반영된 변경 | 유지 |
| `/home/agent` named volume과 provider runtime state | 유지 |
| `buzz-acp`가 주입하는 최근 thread/DM message | 설정된 개수까지 다시 주입 |
| NIP-AE agent core memory | memory가 활성화돼 있으면 다시 주입 |

기본 context 조회 한도는 12개 message다. 의도적으로 완전히 비어 있는 provider prompt가
필요하면 history 조회와 core-memory 주입을 끌 수 있지만, 유용한 연속성도 함께 사라진다.

```yaml
BUZZ_ACP_CONTEXT_MESSAGE_LIMIT: "0"
BUZZ_ACP_NO_MEMORY: "true"
```

일반적인 context window 복구가 아니라 엄격한 초기화가 목적일 때만 이 값을 사용한다.
환경변수 변경은 container 재생성이 필요하지만 수동 `!rotate`에는 필요하지 않다.

### 자동 rotation과 안전한 handoff

오래 실행하는 listener는 정해진 turn 수가 지난 뒤 자동으로 rotation할 수 있다.

```yaml
BUZZ_ACP_MAX_TURNS_PER_SESSION: "20"
```

upstream 기본값 `0`은 turn 수 기반 rotation을 비활성화한다. 너무 낮은 값을 사용하면
진행 중인 개발 workflow가 나뉠 수 있으므로 예상 task 길이를 실측한 뒤 정한다.

계획된 rotation은 다음 순서로 수행한다.

1. Agent에게 현재 상태를 workspace에 간결한 handoff로 기록하거나 Buzz에 게시하게 한다.
2. 현재 turn이 끝날 때까지 기다린다.
3. Owner 권한으로 해당 agent에 `!rotate`를 전송한다.
4. 새 turn에서 handoff 위치와 현재 acceptance criteria를 함께 전달한다.
5. 진행 중인 turn을 강제로 rotation했다면 이미 작성된 filesystem 변경은 rollback되지
   않으므로 `git status`와 미완성 file을 확인한다.

Container를 재시작하거나 교체해도 in-memory ACP session은 사라진다. 그러나 이는 범위가
큰 복구 방식이며 재연결 후 처리되지 않은 mention이 replay될 수 있다. 통제된 context
경계에는 `!rotate`를 사용하고, process 또는 runtime 복구에는 container restart를
사용한다.

## 개인 PoC에서 수락한 제한

현재 Compose는 개인 단일 사용자·단일 node PoC 전용이다. 이 절의 예외는
[ARCHITECTURE.md](../ARCHITECTURE.md)의 production/shared-host 보안 목표를 완화하지
않는다. 다중 사용자, 비신뢰 workload, 공유 host 또는 상시 무인 운영으로 확대하기
전에 아래 후속 issue를 완료하고 이 예외를 제거해야 한다.

### Resource hard limit 부재

현재 Compose는 PID, `/tmp` tmpfs와 Docker log 크기만 제한한다. CPU, process memory와
`/home/agent` named volume에는 hard limit 또는 quota가 없으므로 runaway build/test가
host 자원을 고갈시킬 수 있다.

- 다른 중요 workload와 host를 공유하지 않는다.
- 무인 상태에서 비신뢰 build/test를 실행하지 않고 host resource를 직접 감시한다.
- 공유 host 또는 production 전환 전에
  [issue #5](https://github.com/darimuri/k8s-test/issues/5)의 CPU/memory limit과 state
  storage quota를 적용한다.

## Security boundaries

- The container runs as UID/GID `10001`, drops Linux capabilities, enables
  `no-new-privileges`, uses a read-only root filesystem, and receives no Docker socket.
- `bypass-permissions` is required because the ACP listener is non-interactive. Safety
  therefore comes from the container, workspace mount mode, short-lived credentials,
  forge rules, and role prompt—not from an approval dialog.
- Compose networking is not an egress allowlist. Add host firewall or container-network
  policy before giving agents high-value credentials.
- A mounted credential is still visible to the process that uses it. Use a different
  Buzz/Kaneo/Git identity for every agent and revoke one identity without affecting the
  others.
- Prompt files are operational policy but not an authorization boundary. Enforce
  author/reviewer separation and merge/deploy gates in GitHub and the orchestrator.

## Source references

- Buzz ACP runtime and environment variables:
  <https://github.com/block/buzz/blob/main/crates/buzz-acp/README.md>
- Codex authentication and `CODEX_HOME/auth.json`:
  <https://developers.openai.com/es-419/docs/auth>
- Claude Code installation and authentication:
  <https://docs.anthropic.com/en/docs/claude-code/getting-started>
- Kaneo MCP setup: `../KANEO-MCP-SETUP.md`
- Subscription credential design: `../SUBSCRIPTION-OAUTH-SANDBOX.md`

## Required Git identity migration

See [GIT_IDENTITY.md](GIT_IDENTITY.md) before provisioning or upgrading images.
Each persona now requires an approved external manifest and managed Git config;
missing or conflicting identities fail closed. Production attribution and rollout
require separate verification. The example mapping contains test identities only.

## Dispatcher assignment handoff

[DISPATCHER_HANDOFF.md](DISPATCHER_HANDOFF.md) defines the trusted assignment input,
owner-only Kaneo role setup, native MCP/Buzz execution and crash reconciliation.
The Dispatcher uses `scripts/dispatcher-handoff.mjs` to persist each write intent
before executing it and records success receipts afterward. A pending intent blocks
automatic retransmission. Its private journal lives in the persistent agent home;
no additional service, runtime setting, credential or permission change is needed
for the helper itself. Live role application remains a separate owner action.

Run the local suites with:

```bash
node --test agents/docker/*.test.mjs agents/scripts/*.test.mjs
bash github-apps/test-create-apps.sh
```

These commands assume the repository root. The full Docker smoke suite also includes
the handoff fixtures; see the handoff guide for prerequisites and limitations.
