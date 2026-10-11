# Subscription OAuth Sandbox Design

결정일: 2026-09-18 (Asia/Seoul)

여러 agent sandbox가 한 호스트의 Claude/Codex 구독 계정을 사용하되, host만 OAuth
credential을 갱신하고 sandbox는 읽기만 하는 초기 인증 설계다.

## 결정

초기 agent inference 경로는 Claude/Codex의 공식 구독 OAuth만 사용한다.

- LiteLLM은 초기 필수 경로에서 제외한다.
- host가 subscription credential의 유일한 writer다.
- 같은 subscription account를 쓰는 sandbox는 host credential을 read-only로 소비한다.
- Buzz keypair, persona, runtime state, cache, workspace는 agent instance별로 분리한다.
- credential 갱신 후 관련 agent를 drain하고 새 session으로 재시작한다.
- Claude와 Codex의 credential 형식과 refresh 동작을 동일하다고 가정하지 않는다.

이 설계는 같은 사용자가 소유한 노트북/데스크탑에서 자신의 agent를 실행하는 범위를
전제로 한다. 여러 사람이 한 개인 subscription credential을 공유하는 서비스로
확장하지 않는다. 각 provider의 plan, seat, 동시 사용과 automation 정책은 실제 계정
조건을 별도로 확인한다.

```text
Host credential authority
  ├─ Claude subscription profile
  │    ├─ read-only → Claude Developer sandbox
  │    └─ read-only → Claude Reviewer sandbox
  └─ Codex subscription profile
       ├─ read-only → Codex Developer sandbox
       └─ read-only → Codex Reviewer sandbox
```

## Identity와 state 경계

| 항목 | 공유 여부 | 소유 위치 |
|---|---:|---|
| Provider subscription account | 같은 account 사용 가능 | provider |
| Provider OAuth credential | 같은 host 안에서 read-only 공유 | host credential store |
| Buzz private key | 공유 금지 | agent별 secret |
| Buzz public identity | 공유 금지 | agent별 member/profile |
| Persona/system prompt | 공유 금지 | agent별 config |
| Runtime session/cache | 공유 금지 | agent별 writable volume |
| Workspace/worktree | 공유 금지 | agent/job별 writable volume |
| GitHub App token | 공유 금지 | execution별 short-lived secret |

Provider OAuth credential을 공유해도 Buzz에서는 다음처럼 별도 member로 보인다.

```text
Claude subscription A
  ├─ Dev Agent A     / npub-dev-a
  └─ Review Agent A  / npub-review-a

ChatGPT subscription A
  ├─ Dev Agent B     / npub-dev-b
  └─ QA Agent B      / npub-qa-b
```

## Host credential layout

credential은 workspace나 일반 사용자 홈 전체와 분리한다.

```text
/var/lib/agent-auth/
  claude-primary/
    oauth-token
    generation.json
  codex-primary/
    auth.json
    generation.json
```

`generation.json`은 secret를 포함하지 않고 다음 metadata만 가진다.

```json
{
  "profile_id": "claude-primary",
  "generation": 7,
  "updated_at": "2026-09-18T00:00:00Z",
  "expires_at": null,
  "provider": "claude"
}
```

권장 권한:

- host directory: `0700`
- credential file: `0600`
- container mount: read-only
- credential 경로는 workspace 밖에 배치
- image layer, Compose YAML, Git, log에 credential 값을 기록하지 않음

## Container mount model

각 sandbox는 shared credential directory와 독립 state/workspace를 mount한다.

```yaml
services:
  claude-developer-a:
    read_only: true
    volumes:
      - /var/lib/agent-auth/claude-primary:/run/provider-auth:ro
      - claude-developer-a-state:/var/lib/agent
      - claude-developer-a-workspace:/workspace

  claude-reviewer-a:
    read_only: true
    volumes:
      - /var/lib/agent-auth/claude-primary:/run/provider-auth:ro
      - claude-reviewer-a-state:/var/lib/agent
      - claude-reviewer-a-workspace:/workspace

volumes:
  claude-developer-a-state:
  claude-developer-a-workspace:
  claude-reviewer-a-state:
  claude-reviewer-a-workspace:
```

실제 runtime credential directory 전체를 공유하지 않는다. 공유 mount에는 OAuth
credential artifact만 두고, runtime config/session/cache는 agent별 volume에 둔다.

개별 credential file 하나를 직접 bind mount하기보다 directory를 mount한다. host가
atomic rename으로 파일을 교체했을 때 새 reader가 일관된 generation을 보게 하기
위함이다.

## Claude subscription OAuth

### 권장 형태

host에서 `claude setup-token`으로 생성한 subscription OAuth token을 보관하고 sandbox
entrypoint가 read-only 파일을 읽어 `CLAUDE_CODE_OAUTH_TOKEN`으로 전달한다.

```bash
export CLAUDE_CODE_OAUTH_TOKEN="$(< /run/provider-auth/oauth-token)"
exec buzz-acp
```

agent별로 다음은 분리한다.

- `CLAUDE_CONFIG_DIR`
- session와 cache
- debug log
- workspace
- Buzz keypair

`CLAUDE_CODE_OAUTH_TOKEN`은 Pro, Max, Team, Enterprise 구독으로 trusted script나
non-interactive workflow를 인증하기 위한 공식 경로다. bare mode에서는 이 token을
읽지 않으므로 초기 harness에서 bare mode를 사용하지 않는다.

### 대안

브라우저 `/login`이 만든 `.credentials.json`을 공유할 수도 있지만 refresh와 파일
갱신 동작이 runtime version에 의존한다. 초기 구현은 `setup-token`을 우선하고 login
cache 공유는 fallback으로만 검증한다.

## Codex ChatGPT subscription OAuth

host에서 공식 Codex login을 수행한다.

```bash
codex login --device-auth
codex login status
```

Codex는 로그인 정보를 `~/.codex/auth.json` 또는 OS credential store에 보관한다.
공식 문서는 headless machine으로 `auth.json`을 복사하는 경로를 제공하지만, 여러
process가 하나의 read-only cache를 장기간 공유하는 것을 concurrency contract로
보장하지는 않는다.

### 초기 PoC 형태

```text
Host Codex credential keeper
  ├─ codex login/refresh 수행
  ├─ auth.json atomic publish
  └─ generation 증가

Agent sandboxes
  ├─ auth directory read-only
  ├─ runtime state directory 분리
  └─ generation 변경 시 drain/restart
```

Codex가 access token refresh 과정에서 auth cache 쓰기를 요구하면 read-only sandbox의
요청이 실패할 수 있다. 다음 중 하나로 전환한다.

1. host keeper가 token을 갱신하고 모든 reader를 재시작
2. agent 시작 시 host auth snapshot을 agent별 writable state로 복사
3. agent별 독립 device login volume 사용

2번은 refresh token rotation이 agent copy 사이에서 충돌할 수 있으므로 장기 기본값으로
채택하기 전에 실측한다.

## Credential 갱신 protocol

host는 credential을 제자리에서 부분 수정하지 않는다.

```text
1. 새 credential을 같은 filesystem의 임시 파일에 기록
2. permission 0600 확인
3. 파일 flush/fsync
4. atomic rename으로 현재 credential 교체
5. generation metadata 교체
6. 해당 profile을 쓰는 agent를 drain
7. 진행 중 turn 종료
8. container/process 재시작
9. 새 ACP session 생성
10. auth status, Buzz presence, mention 응답 검증
```

container에 directory가 read-only로 mount돼 있어도 process가 credential을 메모리에
cache할 수 있으므로 파일 교체만으로 완료됐다고 보지 않는다.

## Login, logout, account switch

agent sandbox 안에서는 provider login/logout을 허용하지 않는다.

```text
금지:
  sandbox → login/logout → shared credential 변경 시도

허용:
  host operator → credential keeper → rotate → sandbox restart
```

account switch 순서:

1. credential profile을 사용하는 agent 전체 drain
2. host에서 기존 account logout/revoke 여부 결정
3. 새 account login 또는 token 생성
4. 새 generation publish
5. agent별 fresh session으로 재시작
6. internal audit에 old/new `credential_profile_id` 기록

실제 email, access token, refresh token은 audit log에 쓰지 않는다.

## 보안 한계

read-only mount는 수정 방지일 뿐 비밀성 경계가 아니다. sandbox process가 파일을 읽을
수 있다면 prompt injection이나 tool abuse로 token을 복사하거나 외부로 전송할 수 있다.

```text
read-only volume이 막는 것:
  credential overwrite/delete

막지 못하는 것:
  credential read/copy/exfiltration
```

최소 통제:

- rootless container/Podman
- non-root UID
- `cap-drop=ALL`
- `no-new-privileges`
- read-only root filesystem
- host home, Docker/Podman socket, kubeconfig mount 금지
- provider/Buzz/GitHub 등 필요한 endpoint만 outbound 허용
- credential path를 workspace와 MCP filesystem root에서 제외
- shell/debug log에서 secret redaction
- 동일 OAuth profile의 동시 agent 수 제한
- profile revoke 시 연결된 agent 전체 중단

credential 자체를 sandbox에서 숨겨야 하면 다음 단계에서 host auth proxy를 도입한다.

```text
Agent sandbox --credential 없음--> Host auth proxy --OAuth 주입--> Provider
```

Claude는 gateway pass-through 경로가 공식 문서화돼 있어 발전시키기 쉽다. Codex
subscription gateway는 초기 범위에서 제외한다.

## Failure model

| 장애 | 예상 영향 | 대응 |
|---|---|---|
| Host credential 만료 | profile을 쓰는 모든 agent 실패 | drain, host re-login, generation 교체, restart |
| 한 agent의 과도한 사용 | 같은 subscription limit 공유 | per-profile concurrency/WIP 제한 |
| Sandbox logout 시도 | read-only write 실패 또는 local state만 손상 | command/tool policy 차단, sandbox 교체 |
| Credential 파일 부분 기록 | 모든 reader auth 실패 | temp + fsync + atomic rename |
| Token refresh write 필요 | read-only agent auth 실패 | host keeper 또는 agent별 login으로 fallback |
| Credential 유출 | subscription account 전체 위험 | 즉시 revoke, 모든 sandbox stop, 재발급 |
| Host 재부팅 | agent reconnect 지연 | credential mount 확인 후 supervisor restart |

## Orchestrator inventory

오케스트레이터에는 credential 값이 아닌 profile 참조만 저장한다.

```yaml
agent_instance:
  id: laptop-claude-developer-a
  host_id: laptop
  persona: developer
  buzz_pubkey: "<hex>"

  provider_auth:
    provider: claude
    mode: subscription_oauth
    credential_profile_id: claude-primary
    credential_generation: 7
    mount_mode: read_only

  runtime:
    state_ref: volume://claude-developer-a-state
    workspace_ref: volume://claude-developer-a-workspace
```

하나의 Buzz pubkey는 동시에 하나의 active container에서만 사용한다. 하나의 provider
credential profile은 여러 agent가 사용할 수 있지만 profile-level concurrency limit을
적용한다.

## Phase 0 PoC

### Claude

- host `setup-token`으로 두 sandbox 동시 inference
- 두 sandbox의 config/session/cache가 분리되는지 확인
- host token 교체 후 drain/restart 복구
- subscription usage limit 발생 시 두 agent의 실패 형태 확인
- sandbox에서 logout이 shared secret를 변경하지 못하는지 확인

### Codex

- host `codex login --device-auth` 후 두 sandbox에서 read-only auth 사용
- 1시간 이상 및 장기 idle 후 요청으로 refresh 동작 확인
- auth file write 필요 여부와 오류 message 기록
- host auth 갱신 후 generation 변경과 restart 복구
- 한 sandbox의 logout/상태 변경이 다른 sandbox에 미치는 영향 확인

### 공통 수락 조건

1. sandbox가 host credential을 수정/삭제하지 못한다.
2. persona별 Buzz key, state, workspace가 섞이지 않는다.
3. credential rotation 중 새 작업이 배정되지 않는다.
4. rotation 후 기존 ACP session을 재사용하지 않는다.
5. credential이 workspace, log, Buzz, Kaneo, Git에 노출되지 않는다.
6. 실패 시 profile에 연결된 agent를 일괄 drain/revoke할 수 있다.

## 후속 단계

```text
Phase 1: direct subscription OAuth + host single-writer/read-only sandbox
Phase 2: credential keeper와 자동 rotation/restart
Phase 3: Claude gateway pass-through 및 usage 관측
Phase 4: 필요 시 API key + LiteLLM virtual key fallback
Phase 5: Codex subscription gateway는 별도 실험 후 결정
```

LiteLLM은 이미 배포돼 있어도 초기 subscription inference의 필수 의존성으로 사용하지
않는다. API 과금, 중앙 budget, provider fallback이 필요해지는 시점에 도입한다.

## 공식 근거

- [OpenAI Codex authentication](https://learn.chatgpt.com/docs/auth)
- [OpenAI Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Claude Code authentication](https://code.claude.com/docs/en/team)
- [Claude Code LLM gateway](https://code.claude.com/docs/en/llm-gateway)
