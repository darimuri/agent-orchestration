# 기술 조사 및 스택 검토

조사일: 2026-09-12, GitHub/GHES 보완: 2026-09-13 (Asia/Seoul)

## 1. 요구사항 해석

목표는 단순한 챗봇 묶음이 아니라 다음 성질을 가진 자동화 시스템이다.

1. 개발, 리뷰, QA, 릴리스처럼 서로 다른 역할과 페르소나가 있다.
2. 모델 제공자나 서비스 계정이 하나 이상일 수 있다.
3. 에이전트는 여러 PC에 분산되고 각 실행은 격리된다.
4. 평소에는 대기하다가 Buzz, Kaneo 또는 GitHub Issue/PR 이벤트로 동작한다.
5. 실행이 중복되거나 유실되어도 복구할 수 있어야 한다.
6. 개발자가 자기 변경을 승인하거나 릴리스 권한까지 갖지 못해야 한다.
7. 사람이 현황과 근거를 Buzz와 Kaneo에서 추적할 수 있어야 한다.

이 요구사항에서 가장 어려운 부분은 LLM 호출이 아니라 분산 작업의 소유권,
idempotency, 권한 분리, 신뢰할 수 있는 승인이다.

## 2. 현재 저장소에서 재사용 가능한 구성

| 구성 | 현재 저장소 상태 | 권장 용도 | 주의점 |
|---|---|---|---|
| Buzz | `buzz/`, local fork chart `0.1.8-k8s-test.2`, app `0.1.0` | 협업 이벤트와 에이전트 대화 | 최신 agent/persona/remote-agent 기능과 배포 이미지의 호환성을 반드시 실측 |
| Kaneo | `kaneo/`, Helm chart를 upstream clone에서 설치 | 작업 및 상태 원장 | clone이 commit/tag에 고정되지 않고 값에 평문 dummy DB 암호가 있음 |
| GitHub/GHES | 저장소 외부 서비스 | issue/Git/PR/리뷰/Actions/release 원장 | GHES version/license별 capability 차이 확인 필요 |
| Gitea | `gitea/`와 act-runner manifest 존재 | 선택적 fallback forge | 초기 구현 범위에서 제외 |
| LiteLLM | `litellm/`, Python proxy 배포 구성 | 모델 gateway와 agent별 virtual key | 현재 구성에는 key-management DB 도입 여부 확인 필요 |
| Zot | `zot/` | agent/worker/CI 이미지 registry | 저장소에 보이는 정적 htpasswd 값은 별도 보안 정비 대상 |
| VictoriaMetrics | `vm/`, `vmks/` | metrics와 alerting | orchestration 전용 지표/대시보드는 없음 |
| Coder | `coder/` | 사람용 개발 환경 후보 | 1차 agent worker에는 불필요, 격리 경계를 더 복잡하게 함 |

기존 서비스는 좋은 출발점이지만 single-node microk8s이므로 이 구성 자체가 단일
장애 지점이다. 홈랩 MVP로는 허용할 수 있으나 HA나 재해 복구가 달성됐다고 표현하면
안 된다.

### 구현 전 보안 차단 항목

현재 Git 파일만 기준으로 보면 다음 설정은 도구 권한을 가진 agent를 연결하기 전에
반드시 정비해야 한다. 실제 cluster에서 다른 override를 사용했는지는 Phase 0에서
확인한다.

- `buzz/values.yaml`의 `ownerPubkey`가 placeholder이고 `requireRelayMembership`가
  `false`다. 실제 owner key와 membership enforcement를 설정해야 한다.
- `kaneo/values.yaml`의 DB password와 `authSecret`가 고정 dummy 값이다. 기존 session과
  DB 영향을 확인한 뒤 Secret 기반 값으로 교체/회전해야 한다.
- Kaneo chart/upstream image와 Buzz relay/agent image를 tag뿐 아니라 digest까지
  고정해야 한다.
- GitHub.com self-hosted runner 또는 GHES runner를 agent worker와 분리하고, persistent
  runner가 untrusted PR을 실행하지 않도록 해야 한다.
- LiteLLM master key는 agent에 배포하지 않고 key-management DB와 per-instance virtual
  key를 준비해야 한다.

## 3. Buzz 기능 검토

Buzz의 현재 upstream은 사람과 에이전트가 같은 Nostr 기반 이벤트 로그를 사용하는
협업 공간을 표방한다. 공식 README는 다음 기능을 현재 동작하는 것으로 구분한다.

- `buzz-cli`: agent-first JSON 입출력 CLI
- `buzz-acp`: Goose, Codex, Claude Code 같은 ACP agent harness
- `buzz-agent`와 `buzz-dev-mcp`: LLM agent와 shell/file tool 경계
- message, reaction, schedule, webhook trigger를 가진 YAML workflow
- NIP-34 기반 Git event
- agent별 key와 channel membership, audit trail

근거: [Buzz README @ 조사 commit](https://github.com/block/buzz/blob/78618804ec86a014524ad7d1fb55928e8f5c3edf/README.md),
[buzz-acp README](https://github.com/block/buzz/blob/78618804ec86a014524ad7d1fb55928e8f5c3edf/crates/buzz-acp/README.md).

### 3.1 에이전트 실행

`buzz-acp`는 relay에서 접근 가능한 channel을 발견하고 mention을 구독한다. agent가
죽으면 재시작하고 relay 연결이 끊기면 reconnect/replay를 시도하지만, upstream 문서도
완전한 전달을 보장하지는 않는다고 명시한다. 한 프로세스에서 1~32개 subprocess를
운영할 수 있고 channel 하나는 동시에 두 subprocess가 처리하지 않지만, 서로 다른
PC/launcher 사이의 전역 singleton까지 제공하는 것은 아니다.

따라서 동일 Nostr private key를 여러 PC에서 무심코 실행하는 방식은 피한다. 논리적
역할이 같아도 실제 agent instance마다 key와 instance ID를 다르게 두고, 중앙 lease가
하나의 job을 한 instance에만 배정해야 한다.

### 3.2 Persona pack

upstream persona pack 명세는 persona별 prompt, model/provider, channel subscription,
trigger, skill, MCP server 구성을 표현할 수 있다. 그러나 현재 명세에는 구현 경계가
명시돼 있다.

- persona prompt는 아직 ACP의 진짜 system message가 아니라 매 turn의 `[System]`
  prefix로 전달된다.
- lifecycle hook은 parse/validate되지만 실행은 향후 기능이다.
- MCP env의 `${VAR_NAME}` 보간은 harness에서 아직 구현되지 않았다.
- Desktop snapshot과 persona-pack zip은 현재 서로 교환 가능한 형식이 아니다.

따라서 1차 구현은 persona pack의 선언 형식은 활용하되, secret injection과 실행 전후
정리는 worker가 담당하도록 한다. 근거:
[Persona Pack Specification](https://github.com/block/buzz/blob/78618804ec86a014524ad7d1fb55928e8f5c3edf/crates/buzz-persona/PERSONA_PACK_SPEC.md).

### 3.3 Remote agent

Buzz의 remote-agent 공식 문서는 아직 `draft`다. Kubernetes provider는 bare Pod와
`sprig` image를 사용하고 relay presence를 유일한 실행 상태 신호로 삼는다. 문서는
provider와 substrate가 agent의 Nostr private key를 받는 것을 명시적인 신뢰 결정으로
취급하며, 다른 launcher 범위까지 전역 singleton을 보장하지 않는다.

이 모델은 Buzz 대화 agent를 원격 실행하는 데 유용하지만, 개발/테스트/release job의
durable queue와 cross-system reconciliation을 대체하지 않는다. 초기 구현에서는
상시 Buzz listener와 실제 작업 container를 분리한다. 근거:
[Remote Agents specification](https://github.com/block/buzz/blob/78618804ec86a014524ad7d1fb55928e8f5c3edf/docs/remote-agents.md),
[Remote Agents vision](https://github.com/block/buzz/blob/78618804ec86a014524ad7d1fb55928e8f5c3edf/VISION_REMOTE_AGENTS.md).

### 3.4 Workflow 한계

현재 workflow schema는 message, reaction, diff, schedule, webhook trigger와 message,
DM, topic, reaction, external webhook, approval, delay action을 정의한다. 다만 공식
README는 workflow approval gate를 “being wired up”으로 분류한다. 그러므로 release
승인은 초기 단계에서 Buzz workflow action 하나에 맡기지 않는다. GitHub ruleset과
Actions environment의 human gate를 기본 권위로 두고 Kaneo/Buzz approval event는
추가 정책 신호와 가시화에 사용한다.

## 4. Kaneo 기능 검토

조사한 upstream commit의 Helm chart는 `2.24.0`이지만, 이는 현재 클러스터에 설치된
버전을 뜻하지 않는다. 로컬 `install.sh`는 최초 clone 이후 tag나 commit을 명시하지
않으므로 실제 버전은 별도 확인해야 한다.

### 4.1 API와 MCP

Kaneo는 REST/OpenAPI와 두 종류의 MCP 연결을 제공한다.

- 모든 instance의 `/api/mcp` streamable HTTP endpoint
- Node.js 기반 `@kaneo/mcp` stdio package
- task 조회/생성/수정/이동, comment, label, relation, time entry tool
- API key 또는 browser/device/OAuth 기반 인증

agent가 대화적으로 task를 읽고 갱신할 때 MCP가 편리하다. 반면 오케스트레이터는
재시도, 응답 코드, idempotency를 직접 관리할 수 있도록 REST API를 사용한다.

근거: [Kaneo MCP documentation](https://github.com/usekaneo/kaneo/blob/93cb4712367e5cbb7ac6f9c5ec20e6a037c227bc/apps/docs/core/integrations/mcp.mdx),
[Kaneo API introduction](https://kaneo.app/docs/api-reference/introduction).

### 4.2 Outgoing webhook

Kaneo generic webhook은 다음 task event를 JSON POST로 전송한다.

- `task.created`
- `task.status_changed`
- `task.priority_changed`
- `task.title_changed`
- `task.description_changed`
- `task.comment_created`

HMAC-SHA256 `X-Kaneo-Signature`를 지원하지만 서명 입력은 raw body뿐이고 별도 signed
timestamp/header는 없다. 수신기는 raw body 서명을 constant-time 비교하고, body hash
중복 제거, 짧은 허용 시간, private network 또는 mTLS 같은 replay 방어를 추가해야
한다. private destination은 SSRF 방어 때문에 기본 차단되므로 내부 service URL을
쓰려면 `KANEO_ALLOW_PRIVATE_WEBHOOK_DESTINATIONS=true`와 NetworkPolicy를 함께 적용해야
한다.

현재 구현은 전송 실패 상태를 integration health에 기록하지만 별도의 durable retry
queue를 두지 않고 한 번의 HTTP 요청을 수행한다. 따라서 webhook을 유일한 dispatch
수단으로 쓰면 안 된다. 오케스트레이터는 짧은 주기로 `Ready`/진행 중 task를 REST로
재조회해 놓친 event와 상태 불일치를 보정해야 한다.

근거: [Outgoing webhooks](https://github.com/usekaneo/kaneo/blob/93cb4712367e5cbb7ac6f9c5ec20e6a037c227bc/apps/docs/core/integrations/outgoing-webhooks.mdx),
[generic webhook client source](https://github.com/usekaneo/kaneo/blob/93cb4712367e5cbb7ac6f9c5ec20e6a037c227bc/apps/api/src/plugins/generic-webhook/client.ts),
[Environment setup](https://github.com/usekaneo/kaneo/blob/93cb4712367e5cbb7ac6f9c5ec20e6a037c227bc/ENVIRONMENT_SETUP.md).

### 4.3 권한과 계정

Kaneo upstream은 viewer/member/admin/owner와 workspace별 editable role을 제공한다.
API key는 사용자와 연결되고 만료, permission scope, rate limit 필드를 가진다. 따라서
agent마다 별도 Kaneo 사용자와 API key를 만들고 다음처럼 최소 권한을 적용할 수 있다.

- planner/reviewer/QA: viewer 또는 필요한 comment/update만 가진 custom role
- developer: task read/update/comment, project/workspace 관리 권한 없음
- release agent: task read/comment만, release 승인은 할 수 없음
- orchestrator: task read/update/comment와 assignee만, workspace 관리/삭제 없음

근거: [Kaneo authentication](https://github.com/usekaneo/kaneo/blob/93cb4712367e5cbb7ac6f9c5ec20e6a037c227bc/apps/docs/api-reference/authentication.mdx),
[Kaneo permissions source](https://github.com/usekaneo/kaneo/blob/93cb4712367e5cbb7ac6f9c5ec20e6a037c227bc/packages/permissions/src/index.ts).

## 5. GitHub/GHES 기능 검토

### 5.1 GitHub App 인증

GitHub.com과 GHES 모두 server-to-server 자동화에는 GitHub App이 가장 적합하다. App은
설치 대상을 repository로 제한하고 세분화된 permission을 선언할 수 있다. App private
key로 발급하는 installation access token은 1시간 후 만료되며, 발급할 때 repository와
permission을 App의 최대 권한보다 더 좁힐 수 있다.

권장 App 경계는 다음과 같다.

| App | 최대 권한 예시 | 하지 못해야 할 일 |
|---|---|---|
| `agent-control` | metadata/contents/pulls/actions/checks/deployments read, issues write | code push, PR review/merge, environment approve |
| `agent-developer` | native mode: contents/pulls write, Free-private: contents read | checks write, rules/admin, deployment |
| `agent-reviewer` | contents/pulls/actions read, checks write | contents write, PR review/merge, deployment |
| `forge-publisher` | contents/pulls write | LLM 실행, review/check, deployment |
| `merge-broker` | contents/pulls read/write | LLM 실행, rules/admin, deployment |

주의: GitHub의 `pull_requests: write`는 PR 생성뿐 아니라 review와 merge 관련 API도
포함한다. developer App의 API permission만으로 자기 승인을 차단할 수 있다는 뜻이
아니다. developer App이 직접 PR을 생성해 PR author가 되게 하고, tool allowlist,
ruleset bypass 금지, required reviewer Check, `require_last_push_approval`, 필요 시
CODEOWNERS human review를 함께 강제한다. GitHub는 PR author의 자기 승인을 허용하지
않지만 이 한 규칙만을 보안 경계로 삼지 않는다.

Free private repository에서는 branch protection이 없으므로 이 권한도 충분히 안전하지
않다. 해당 mode에서는 developer App을 read-only로 낮추고 비-LLM publisher/merge
broker만 write token을 사용한다.

App private key는 중앙 credential broker만 보유한다. worker/agent에는 job 대상 repository와
권한으로 축소한 installation token만 전달한다. 여러 agent instance가 같은 App을
사용하면 GitHub audit의 actor는 같은 App으로 보이므로 `external_id`, branch 이름,
commit trailer, PR comment에 내부 `agent_instance_id`와 `job_id`를 함께 기록한다.

사람처럼 별도 assignee/mention/UI actor가 꼭 필요한 persona만 machine user와
fine-grained PAT를 예외로 검토한다. classic PAT와 공유 SSH key는 기본안에서 제외한다.

| 인증 후보 | 최소 권한/만료 | 귀속 | 운영 부담 | 판단 |
|---|---:|---:|---:|---|
| **trust domain별 GitHub App** | 5 | 3.5 | 3.8 | 기본. short-lived token과 repo scope |
| machine user + fine-grained PAT | 4 | 5 | 2.5 | 독립 UI actor가 필수인 persona만 예외 |
| 공유 classic PAT/SSH key | 1 | 1 | 3 | 사용하지 않음 |

근거: [GitHub App 개요](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-creating-github-apps),
[GHES App installation 인증](https://docs.github.com/en/enterprise-server@3.22/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation),
[GitHub App permission 표](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps).

### 5.2 Webhook과 API

GitHub App webhook은 `X-GitHub-Delivery` GUID를 제공하므로 event idempotency key로
사용할 수 있다. 수신기는 raw body와 `X-Hub-Signature-256`을 constant-time 비교하고
durable 저장 후에만 2xx를 반환한다. 최소 구독 후보는 `issues`, `issue_comment`,
`pull_request`, `pull_request_review`, `push`, `check_run`, `check_suite`, `workflow_job`,
`workflow_run`, `deployment`, `deployment_status`, `release`다. 실제 permission과 event는
Phase 0에서 최소 집합으로 줄인다.

오케스트레이터는 GitHub Issue의 allowlist된 label 또는 명시적 slash command도 intake로
받을 수 있다. 그러나 issue text를 곧바로 실행하지 않고 Kaneo task에 연결한 뒤 risk,
repository, acceptance criteria와 actor policy를 확인한다.

Kaneo에도 GitHub integration이 있으므로 task/issue 양방향 생성 주체를 둘로 만들면
loop와 중복이 생길 수 있다. 초기에는 오케스트레이터만 GitHub Issue와 Kaneo task의
연결을 소유하고 Kaneo의 자동 issue 생성은 끈다. 나중에 built-in integration을 쓰려면
기존 external link를 먼저 조회하고 한쪽만 create 권한을 갖는 단방향 계약을 정한다.

근거: [GitHub App webhooks](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/using-webhooks-with-github-apps),
[webhook signature 검증](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries),
[delivery headers](https://docs.github.com/en/webhooks/webhook-events-and-payloads).

### 5.3 자동 리뷰, merge, release gate

자동 reviewer의 판정은 사람의 PR approval을 흉내 내기보다 현재 head SHA에 연결된
Check Run `agent-review/<policy-version>`으로 게시한다. Checks write는 reviewer App에만
주고 developer App에는 주지 않는다. repository ruleset 또는 branch protection에서
이 check와 CI check를 required로 만든다. 고위험 변경은 CODEOWNERS 또는 사람 approval도
별도로 요구하며, 가장 최근 push를 다른 사람이 승인하도록 설정한다.

native 기능이 있는 production release는 GitHub Actions `environment: production`을
사용한다. required reviewer, prevent self-review, protected branch/tag, environment
secret의 승인 후 공개를 기본 gate로 삼는다. Free private repository에서는 environment를
쓸 수 없으므로 Actions는 artifact 생성까지만 수행하고 외부 deploy broker가
digest-bound human approval을 검증한다. custom deployment protection rule은 조사한
GHES 문서에서 preview로 표시되므로 초기 필수 경로에는 넣지 않는다.

근거: [GHES Checks API](https://docs.github.com/en/enterprise-server@3.22/rest/checks/runs),
[GitHub ruleset 규칙](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets),
[GitHub protected branch 규칙](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches),
[PR author 자기 승인 제한](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/reviewing-proposed-changes-in-a-pull-request),
[GHES deployment environments](https://docs.github.com/en/enterprise-server@3.22/actions/reference/workflows-and-actions/deployments-and-environments).

### 5.4 GitHub.com과 GHES 차이

integration은 host profile을 가진다.

```yaml
github_host:
  kind: github_com | ghes
  web_url: https://github.example.com
  rest_url: https://github.example.com/api/v3
  graphql_url: https://github.example.com/api/graphql
  version: "<detected>"
  capabilities: {}
```

- GitHub.com에는 GitHub-hosted runner를 사용할 수 있다. untrusted PR은 hosted runner를
  우선하고 private network가 필요한 내부 job만 ephemeral self-hosted runner에 보낸다.
- GHES는 GitHub-hosted runner를 지원하지 않으므로 self-hosted runner가 필요하다.
- Kubernetes runner가 필요하면 ARC를 권장하되, single-node production workload와 같은
  cluster에 untrusted runner pod를 두지 않는다.
- GHES는 지원되는 feature release와 최신 security patch를 유지해야 한다. 2026-09-13
  기준 최신 네 feature release는 3.19~3.22다. 3.17/3.18은 게시된 종료일 전이지만
  EOL이 임박했으므로 새 연동 기준은 3.22 또는 당시 최신 지원 release로 잡고 실제
  목표 version으로 capability test를 실행한다.
- ruleset, environment, ARC, OIDC claim은 version/license에 따라 다를 수 있다. 특히
  GitHub.com의 immutable OIDC subject claim을 GHES에 그대로 가정하지 않는다.
- GitHub App은 GitHub.com과 각 GHES instance에 별도로 등록하고 key/installation ID도
  공유하지 않는다.
- GHES에서 enterprise-level App installation은 webhook을 받을 수 없으므로 event가
  필요한 App은 각 organization에 설치한다.
- GitHub.com용 App webhook은 microk8s ingress가 외부에서 접근 가능해야 한다. GHES가
  private network에 있다면 별도 public hop 없이 내부 orchestrator endpoint를 쓴다.
- GHES Actions는 기본적으로 GitHub.com/Marketplace action 접근이 제한된다. 허용된
  action을 commit SHA로 pin해 `actions-sync`로 mirror하거나, 정책을 갖춘 GitHub
  Connect 경로를 명시한다. offline runner는 tool cache도 미리 채운다.

근거: [GHES release 지원 표](https://docs.github.com/en/enterprise-server@3.22/admin/all-releases),
[GHES self-hosted runners](https://docs.github.com/en/enterprise-server@3.22/actions/how-tos/manage-runners/self-hosted-runners),
[Actions Runner Controller](https://docs.github.com/en/actions/concepts/runners/actions-runner-controller),
[OIDC 차이](https://docs.github.com/en/actions/reference/security/oidc),
[GHES action 동기화](https://docs.github.com/en/enterprise-server@3.22/admin/managing-github-actions-for-your-enterprise/managing-access-to-actions-from-githubcom/using-the-latest-version-of-the-official-bundled-actions).

### 5.5 Free Organization 지원 원칙

무료 Organization은 열화된 부가 대상이 아니라 정식 capability mode로 지원한다.
public repository에서는 repository별 native ruleset/branch/environment를 사용하고,
private repository에서는 publisher, merge, deploy broker가 부족한 강제 지점을 맡는다.
유료 기능이 생기면 broker를 제거하지 않고 GitHub native gate를 추가해 방어를
강화한다. 기능표, quota와 잔여 위험은
[GITHUB-FREE-ORG.md](GITHUB-FREE-ORG.md)에 고정한다.

## 6. 필요한 추가 구성

Buzz, Kaneo, GitHub/GHES 사이에 다음 책임을 가진 얇은 서비스가 필요하다.

1. webhook/Nostr/forge event를 공통 envelope로 정규화
2. event와 command의 중복 제거
3. Kaneo task를 실행 가능한 job으로 변환하는 정책 평가
4. capability가 맞는 worker에 TTL lease 발급
5. heartbeat, timeout, retry, dead-letter 처리
6. GitHub Actions/PR 결과와 Kaneo/Buzz 상태 reconciliation
7. 자기 승인 및 release 권한 정책 강제
8. webhook/relay event 유실을 보정하는 authoritative-source polling sweep

오케스트레이터는 LLM agent가 아니다. 결정적 상태 머신과 정책 코드로 구현하고,
자연어 판단은 별도 agent job으로 위임한다.

## 7. 기술 스택 비교

점수는 이 홈랩 요구사항에 대한 1~5 상대평가다. 가중치는 적합성 30%, 장애 안전성
25%, 운영 난이도 20%, 보안 경계 15%, 자원 비용 10%다. PoC 이전이므로 신뢰도는
중간이다.

### 7.1 오케스트레이션 방식

| 후보 | 적합성 | 장애 안전성 | 운영 | 보안 | 비용 | 가중 점수 | 판단 |
|---|---:|---:|---:|---:|---:|---:|---|
| **Go + 전용 PostgreSQL lease queue** | 4.5 | 4.2 | 4.3 | 4.0 | 4.3 | **4.29** | 권장. 작은 단일 binary와 명시적 상태 머신 |
| Temporal self-hosted | 4.7 | 4.8 | 2.0 | 4.0 | 2.2 | 3.78 | 복잡한 장기 workflow가 늘 때 재검토 |
| Argo Events + Workflows | 3.7 | 4.0 | 3.0 | 3.8 | 3.0 | 3.58 | cluster job에는 좋지만 여러 외부 PC lease가 어색함 |
| Buzz/Kaneo trigger 직접 연결 | 3.0 | 2.0 | 4.2 | 2.5 | 4.8 | 3.12 | 데모만 가능, 중복/복구/권한 정책이 분산됨 |

권장 queue는 별도 PostgreSQL schema/table과 `SELECT ... FOR UPDATE SKIP LOCKED`로
구현한다. PostgreSQL 공식 문서도 `SKIP LOCKED`를 일반 조회가 아니라 queue-like table의
consumer 경합 회피 용도로 명시한다: [PostgreSQL SELECT](https://www.postgresql.org/docs/current/sql-select.html).
Buzz나 Kaneo의 내부 DB를 직접 읽거나 같은 database를 공유하지 않는다.

### 7.2 Worker 실행 환경

| 후보 | 격리 | 여러 PC | 운영 | 판단 |
|---|---:|---:|---:|---|
| **rootless Podman + systemd/Quadlet worker** | 4.2 | 4.7 | 4.1 | 권장. PC가 outbound pull하고 job마다 container 생성 |
| 모든 PC를 microk8s node로 편입 | 4.0 | 3.5 | 2.8 | 동질 Linux node와 cluster 신뢰 경계가 필요할 때 |
| host process/systemd만 사용 | 1.8 | 4.5 | 4.3 | tool이 host HOME/credential을 보게 되어 비권장 |
| PC별 VM 안의 worker | 4.8 | 3.8 | 2.3 | 고위험 release/보안 job의 2차 방어선 후보 |

Podman Quadlet은 rootless user unit과 container secret 연결을 지원한다:
[Podman systemd/Quadlet documentation](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html).
macOS나 Windows worker는 Linux VM 안에서 같은 worker contract를 실행한다.

### 7.3 언어 및 protocol 선택

| 계층 | 선택 | 이유 |
|---|---|---|
| orchestrator/worker | **Go** | static binary, 작은 메모리, HTTP/lease/heartbeat 구현과 배포가 단순 |
| Buzz 연결 | 초기에는 `buzz-cli`/workflow webhook | Nostr event schema를 bridge에 중복 구현하지 않음 |
| Kaneo 연결 | REST/OpenAPI | 결정적 retry와 오류 처리가 MCP보다 명확 |
| agent의 Kaneo 접근 | official MCP | 자연어 agent tool 사용과 user permission 상속 |
| durable state | 별도 PostgreSQL | queue, outbox, lease, audit correlation을 한 트랜잭션으로 처리 |
| forge | GitHub App + REST/GraphQL/webhook adapter | GitHub.com/GHES 공통 contract, short-lived token |
| CI | GitHub Actions + hosted/ephemeral runner | SHA-bound check와 environment gate |
| image | GHCR/GHES Packages 또는 Zot | 환경별 registry 선택, image digest pinning |
| LLM gateway | LiteLLM virtual key | instance별 model allowlist, budget, rate limit, spend attribution |
| metrics | Prometheus format -> VictoriaMetrics | 기존 관측 스택 재사용 |

LiteLLM virtual key는 모델 접근, 예산, rate limit, 사용량 추적을 key/user/team 단위로
지원한다: [LiteLLM Virtual Keys](https://docs.litellm.ai/docs/proxy/virtual_keys).

## 8. Git/CI 및 runner 평가

GitHub.com에서는 untrusted code를 GitHub-hosted runner에서 먼저 실행하는 것이 운영 및
격리 부담이 가장 작다. self-hosted runner가 필요한 경우 persistent worker를 재사용하지
말고 job 하나만 처리하는 ephemeral/JIT runner 또는 ARC runner pod를 사용한다. GHES는
GitHub-hosted runner가 없으므로 이 격리가 필수다.

GitHub 공식 문서도 persistent self-hosted runner보다 ephemeral runner를 권장하고,
untrusted workflow가 self-hosted runner와 `GITHUB_TOKEN`/secret을 탈취할 위험을
경고한다. 개발 agent container와 Actions runner는 별도 계정, 별도 runtime, 별도
workspace를 사용한다. agent worker가 Actions runner 역할까지 겸하지 않는다.

| Runner 방식 | GitHub.com | GHES | 격리/운영 판단 |
|---|---|---|---|
| GitHub-hosted | 권장: untrusted PR | 미지원 | 관리 부담 최소 |
| ARC ephemeral scale set | private network/special hardware | 권장 후보 | Kubernetes 분리 cluster가 바람직 |
| custom JIT ephemeral VM/container | 가능 | 가능 | 여러 PC/특수 OS에 유연, 직접 lifecycle 운영 |
| persistent self-hosted | 제한적 trusted job만 | 제한적 trusted job만 | untrusted code에는 사용하지 않음 |

근거: [Self-hosted runner reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners),
[self-hosted runner 위험](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization),
[ARC 배포 보안 지침](https://docs.github.com/en/actions/how-tos/manage-runners/use-actions-runner-controller/deploy-runner-scale-sets).

## 9. 권장하지 않는 접근

- 같은 Nostr/Kaneo/GitHub credential을 여러 PC에 복사
- 모든 persona가 하나의 classic PAT, GitHub App private key 또는 LiteLLM master key 공유
- agent가 Kaneo task 본문만 보고 바로 production release 수행
- 개발 agent가 자신의 PR approve/merge
- webhook 수신 성공 전에 Kaneo 상태부터 변경
- Buzz/Kaneo 내부 PostgreSQL table을 직접 조회하거나 수정
- worker에 host Docker socket, host HOME, cluster-admin kubeconfig mount
- persistent self-hosted Actions runner에서 untrusted PR 실행
- developer와 reviewer가 bypass 가능한 하나의 GitHub App identity 공유
- Kaneo GitHub integration과 오케스트레이터가 같은 issue/task를 모두 생성하는 구성
- “exactly once”를 주장하는 설계. 내부 job은 at-least-once execution과 idempotent
  effect를 목표로 하고, 외부 event 유실은 주기적 reconciliation으로 보정한다.
- Buzz draft 기능이나 최신 `main`의 문서를 현재 배포 기능으로 간주

## 10. 미확정 사항

아래는 Phase 0에서 실측해야 한다.

1. 클러스터에 실제 설치된 Buzz image digest와 지원하는 CLI/ACP/workflow feature
2. 클러스터에 실제 설치된 Kaneo version, webhook, API key scope, MCP endpoint
3. 대상이 GitHub.com, GHES 또는 둘 다인지와 GHES exact version/license
4. 각 PC의 OS, CPU architecture, rootless Podman 가능 여부
5. GitHub.com hosted runner 사용 범위와 GHES self-hosted/ARC runner 배치 위치
6. release 대상이 container image, Kubernetes manifest, package 중 무엇인지
7. 사람이 반드시 승인해야 하는 risk level과 승인자 목록
8. LLM provider별 계정/요금/동시성 한도와 데이터 보존 정책
9. App별 최대 permission과 App actor 단위 audit가 충분한지, 일부 persona에 machine
   user가 필요한지
10. GHES의 GitHub Connect/action mirror/tool cache 정책과 runner outbound network
