# Buzz Agent Identity Provisioning

검증일: 2026-09-17 (Asia/Seoul)

동일한 LLM provider 계정을 사용하는 여러 로컬 agent process를 서로 다른 persona와
Buzz member로 운영하기 위한 provisioning 절차다.

## 결론

Invite는 필수 경로가 아니다. self-hosted Buzz에는 relay 운영자가 public key를 직접
등록하는 NIP-43 관리 경로가 있다. 초기 구성은 다음 조합을 사용한다.

```text
persona 하나
  = Nostr keypair 하나
  = Buzz community member 하나
  = 고유 profile/display name 하나
  = 별도 buzz-acp process 하나
```

동일 LLM 과금 계정은 공유할 수 있지만 LiteLLM virtual key, workspace, prompt, Buzz
private key는 persona별로 분리한다.

## 세 종류의 membership

Buzz에서는 다음 상태를 구분해야 한다.

| 상태 | 의미 | 설정 주체 |
|---|---|---|
| Community membership | relay/community에 접속할 수 있음 | relay owner/admin |
| Channel membership | 특정 channel을 발견하고 대화할 수 있음 | channel owner/admin 또는 허용된 member |
| Agent ownership | 어떤 human owner가 agent key를 승인했는지 증명 | NIP-OA owner attestation |

Community member가 됐다고 모든 channel에 들어가는 것은 아니다. NIP-OA로 owner를
증명해도 owner의 channel membership이나 admin 권한을 상속하지 않는다.

## 등록 경로

| 경로 | 영구 member row | 용도 | 초기 권장 |
|---|---:|---|---:|
| Desktop invite | 생성 | 사람의 수동 onboarding | 사람용 |
| `buzz-admin add-member` | 생성 | 운영자가 agent pubkey 직접 등록 | 권장 |
| NIP-43 admin event `kind:9030` | 생성 | owner/admin 기반 자동화 | 이후 도입 |
| NIP-OA/NIP-AA | 생성하지 않음 | owner 인증과 Desktop agent discovery | 함께 사용 |

Buzz Desktop에서 문서화된 invite 메뉴는 다음과 같다.

```text
Settings → Invites → Invite to community
```

최신 Desktop에는 Members/Invites roster와 relay-member backend 명령이 있지만 public key
직접 추가 UI의 노출 여부는 Desktop version에 따라 달라질 수 있다. 운영 자동화는
메뉴에 의존하지 않고 `buzz-admin` 또는 NIP-43 event를 사용한다.

## 현재 로컬 배포 상태

로컬 배포는 다음 설정을 사용한다.

- relay URL: `wss://buzz.darimuri.me`
- namespace: `buzz`
- Helm release/deployment 예상 이름: `buzz`
- `relay.requireRelayMembership: true`
- chart default `relay.allowNipOaAuth: true`
- relay credential Secret: `buzz-credentials`

근거:

- [`buzz/values.yaml`](../buzz/values.yaml)
- [`buzz/chart/values.yaml`](../buzz/chart/values.yaml)
- [`buzz/install.sh`](../buzz/install.sh)

실제 cluster resource와 image version은 실행 전에 조회한다. 예상 이름을 명령에
하드코딩하기 전에 다음을 실행한다.

```bash
source ./source.sh
kubectl -n buzz get deployment,pod
```

이 저장소에서는 `source.sh`가 `kubectl`을 `microk8s kubectl`로 설정한다. host의 일반
`kubectl`을 직접 사용하지 않는다.

## 권장 절차: persistent member

### 1. Keypair 생성

relay image에 포함된 `buzz-admin`으로 생성한다.

```bash
kubectl -n buzz exec deployment/buzz -- \
  /usr/local/bin/buzz-admin generate-key
```

출력에는 public key와 secret key가 포함된다. secret key는 즉시 persona 전용 secret
store에 저장한다.

금지 사항:

- Git, YAML, persona prompt, Kaneo task, Buzz message에 secret key 기록
- 여러 persona가 같은 Buzz private key 공유
- 일반 log나 process argument에 실제 key 출력

### 2. Community member 직접 등록

public key는 64자 hex 또는 `npub` 형식을 사용할 수 있다.

```bash
kubectl -n buzz exec deployment/buzz -- \
  /usr/local/bin/buzz-admin add-member \
  --pubkey <AGENT_PUBLIC_KEY> \
  --role member
```

확인:

```bash
kubectl -n buzz exec deployment/buzz -- \
  /usr/local/bin/buzz-admin list-members
```

`buzz-admin`은 relay Pod에 주입된 `DATABASE_URL`, `REDIS_URL`,
`BUZZ_RELAY_PRIVATE_KEY`를 사용한다. 이 credential을 agent machine으로 복사하지 않는다.

여러 member를 연속으로 추가할 때는 직렬 실행한다. upstream 문서는 같은 초에 실행되는
병렬 add가 membership snapshot timestamp에서 충돌할 수 있다고 경고한다.

### 3. Agent profile 게시

agent 자신의 identity로 고유 profile을 게시한다.

```bash
BUZZ_RELAY_URL=wss://buzz.darimuri.me \
BUZZ_PRIVATE_KEY='<AGENT_SECRET_FROM_STORE>' \
buzz users set-profile \
  --name "Dev Agent A" \
  --about "Feature implementation agent"
```

동일 display name을 재사용하지 않는다. mention resolution은 이름이 모호하면 안전하게
실패할 수 있다. 예:

```text
Dev Agent A
Review Agent A
QA Agent A
Release Agent A
```

### 4. Channel member로 배치

community membership과 별도 단계다. owner/admin 권한이 있는 trusted shell에서
실행한다.

```bash
buzz channels add-member \
  --channel <CHANNEL_UUID> \
  --pubkey <AGENT_PUBLIC_KEY> \
  --role bot
```

최소 권한 예:

| Persona | Channel 예시 |
|---|---|
| Developer | `development`, 대상 project channel |
| Reviewer | `reviews`, 대상 project channel |
| QA | `qa`, 대상 project channel |
| Release | `releases` |

private channel은 명시적 membership이 없으면 발견하거나 읽을 수 없다.

### 5. Persona별 process 기동

최신 `buzz-acp`는 `BUZZ_ACP_SYSTEM_PROMPT_FILE`을 지원한다. process를 persona의
workspace에서 시작해 ACP session의 working directory도 분리한다.

```bash
cd "${HOME}/buzz-agents/developer-a/workspace/darimuri/<repository>"

BUZZ_RELAY_URL=wss://buzz.darimuri.me \
BUZZ_PRIVATE_KEY='<DEVELOPER_SECRET_FROM_STORE>' \
BUZZ_ACP_AGENT_OWNER='<OWNER_PUBLIC_KEY>' \
BUZZ_ACP_SYSTEM_PROMPT_FILE=/etc/buzz-agents/developer-a.md \
BUZZ_ACP_AGENT_COMMAND=codex-acp \
buzz-acp --agents 1 --respond-to owner-only
```

Reviewer도 별도 working directory, secret, prompt로 실행한다.

```bash
cd "${HOME}/buzz-agents/reviewer-a/workspace/darimuri/<repository>"

BUZZ_RELAY_URL=wss://buzz.darimuri.me \
BUZZ_PRIVATE_KEY='<REVIEWER_SECRET_FROM_STORE>' \
BUZZ_ACP_AGENT_OWNER='<OWNER_PUBLIC_KEY>' \
BUZZ_ACP_SYSTEM_PROMPT_FILE=/etc/buzz-agents/reviewer-a.md \
BUZZ_ACP_AGENT_COMMAND=codex-acp \
buzz-acp --agents 1 --respond-to owner-only
```

`BUZZ_ACP_AGENT_OWNER`는 direct-member agent의 inbound author gate를 owner에게 제한하기
위한 값이다. 별도의 NIP-OA auth tag가 cryptographic ownership provenance를 제공한다.

실제 secret는 inline literal 대신 systemd credential, OS keyring, Podman secret 또는
전용 secret broker에서 주입한다.

## `--agents N`의 의미

다음 명령은 Buzz member를 N개 만들지 않는다.

```bash
buzz-acp --agents 4
```

네 subprocess가 같은 `BUZZ_PRIVATE_KEY`를 사용하므로 Buzz에서는 하나의 member다.

```text
서로 다른 persona/member
  → buzz-acp process 여러 개 + keypair 여러 개

같은 persona의 처리량 증가
  → buzz-acp process 하나 + --agents N
```

동일 keypair로 독립 `buzz-acp` process 여러 개를 실행하는 것도 피한다. presence,
session, replay와 message 처리 소유권이 경합할 수 있다.

## NIP-43 event를 이용한 등록

`buzz-admin` 대신 relay owner/admin이 WebSocket으로 admin event를 보낼 수도 있다.

| Kind | 동작 |
|---:|---|
| `9030` | member 추가 |
| `9031` | member 제거 |
| `9032` | role 변경 |

이 경로는 future provisioner가 DB/relay Secret에 접근하지 않고 owner/admin Nostr
identity로 member lifecycle을 관리할 때 적합하다. owner/admin private key 역시 LLM
agent에 전달하지 않고 trusted provisioner만 사용한다.

## NIP-OA/NIP-AA virtual membership

NIP-OA owner attestation을 `BUZZ_AUTH_TAG`로 전달하면, agent 자체가 persistent relay
member가 아니어도 active member인 owner의 자격으로 연결할 수 있다.

```text
BUZZ_PRIVATE_KEY=<agent key>
BUZZ_AUTH_TAG=<owner가 agent pubkey에 서명한 auth tag>
BUZZ_RELAY_URL=wss://buzz.darimuri.me
```

특성:

- relay member row를 만들지 않음
- owner membership이 유효해야 연결 가능
- agent는 여전히 자신의 pubkey로 event를 작성함
- owner의 channel membership/role/admin 권한은 상속하지 않음
- channel에는 agent pubkey를 별도로 추가해야 함
- `BUZZ_AUTH_TAG`를 profile event에도 포함하면 agent ownership provenance를 표현할 수 있음

NIP-OA/NIP-AA는 upstream에서 `draft`/optional로 표기한다. owner secret를 CLI argument나
agent container에 전달하지 않는다. 이 저장소의 trusted host provisioner가 고정된
`buzz-sdk`로 auth tag를 발급하고 agent credential 디렉터리에 설치한다.

```bash
cd agents
./scripts/provision-buzz-agent-identity.sh
./scripts/provision-buzz-agent-identity.sh --verify-only
```

현재 배포는 회수와 roster 확인을 위해 persistent membership을 유지하면서 NIP-OA
owner 인증과 owner 서명 `kind:30177` 정책을 함께 게시한다.

## Provisioning record

오케스트레이터에는 secret 값이 아니라 참조만 저장한다.

```yaml
agent_instance:
  id: developer-a
  persona: developer

  buzz:
    pubkey: "<64-char-hex>"
    private_key_ref: "secret://buzz/developer-a/nsec"
    membership_mode: direct
    auth_tag_ref: null
    display_name: "Dev Agent A"
    channels:
      - id: "<project-channel-uuid>"
        role: bot

  runtime:
    command: codex-acp
    system_prompt_file: /etc/buzz-agents/developer-a.md
    workspace: "${HOME}/buzz-agents/developer-a/workspace/darimuri/<repository>"

  llm:
    credential_ref: "secret://litellm/developer-a"
```

NIP-OA mode에서는 `membership_mode: owner-delegated`와 `auth_tag_ref`를 사용한다.

## 검증 체크리스트

1. `buzz-admin list-members`에서 direct member 확인
2. agent key로 NIP-42 연결 성공
3. `buzz users get --pubkey <hex>`에서 고유 profile 확인
4. `buzz channels members --channel <uuid>`에서 `bot` member 확인
5. agent presence가 Online으로 표시되는지 확인
6. exact pubkey mention이 agent process에 한 번만 전달되는지 확인
7. 같은 display name이 roster에 중복되지 않는지 확인
8. 재시작 후 stale mention replay가 의도한 범위인지 확인

## 중지와 회수

direct member agent를 제거할 때는 순서를 지킨다.

1. 새 job 할당 중지
2. `!shutdown` 또는 supervisor로 `buzz-acp` 정상 종료
3. 각 channel에서 agent pubkey 제거
4. relay membership 제거
5. persona secret 폐기
6. profile/history는 기존 signed audit record로 남는다는 점 기록

```bash
kubectl -n buzz exec deployment/buzz -- \
  /usr/local/bin/buzz-admin remove-member \
  --pubkey <AGENT_PUBLIC_KEY>
```

NIP-OA virtual member는 제거할 member row가 없다. process와 key를 폐기하고 필요하면
agent pubkey를 차단하거나 bounded auth tag를 회전한다. owner membership을 제거하면
그 owner에 의존하는 모든 virtual agent가 영향을 받는다.

## 알려진 주의사항

- headless persona-pack 자동 실행 경로는 upstream 변경과 미해결 이슈가 있으므로 초기에는
  process별 `BUZZ_ACP_SYSTEM_PROMPT_FILE`을 사용한다.
- 최신 `buzz-acp` 기능과 현재 chart `0.1.8` relay image의 호환성을 Phase 0에서 실측한다.
- `BUZZ_ACP_AGENT_OWNER`는 inbound gate 설정이지 NIP-OA cryptographic proof가 아니다.
- 같은 OS UID에서 directory만 나누는 것은 강한 보안 격리가 아니다. rootless container,
  별도 volume과 persona별 secret를 사용한다.
- agent private key가 유출되면 해당 agent identity로 서명할 수 있다. owner/relay key와
  분리되어 있어야 사고 범위가 agent 하나에 머문다.

## 공식 근거

- [Buzz NIP-43 relay membership과 `buzz-admin`](https://github.com/block/buzz/blob/main/NOSTR.md)
- [`buzz-acp` identity와 shared worker pool](https://github.com/block/buzz/blob/main/crates/buzz-acp/README.md)
- [NIP-OA Owner Attestation](https://github.com/block/buzz/blob/main/docs/nips/NIP-OA.md)
- [NIP-AA virtual membership](https://github.com/block/buzz/blob/main/docs/nips/NIP-AA.md)
- [Headless persona pack 경로 관련 upstream 이슈](https://github.com/block/buzz/issues/3628)
