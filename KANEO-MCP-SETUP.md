# Kaneo MCP Setup and Authentication

2026-09-19에 현재 self-hosted Kaneo와 공식 `@kaneo/mcp` 패키지를 대상으로 설정,
device authorization, 읽기 전용 도구 호출을 직접 검증한 기록이다. 이 문서에는 실제
token, 사용자 이메일, 내부 ID와 device code를 기록하지 않는다.

## 결론

공식 Kaneo MCP는 현재 환경에서 정상 동작한다.

- transport: local stdio
- package: `@kaneo/mcp` `0.1.11`
- authentication: Kaneo device authorization
- credential cache: `~/.config/kaneo-mcp/credentials.json`
- cache permission: `0600`
- 검증된 읽기 도구: `whoami`, `list_workspaces`, `list_workspace_members`,
  `list_projects`, `list_workspace_labels`, `list_notifications`
- 확인된 tool 수: 36개

현재 workspace에는 project가 없어서 project/task/comment/relation/time-entry 쓰기
도구의 end-to-end 검증은 수행하지 않았다.

## 연결 방식 선택

Kaneo는 두 가지 MCP transport를 제공한다.

| 방식 | endpoint/process | 인증 | 용도 |
| --- | --- | --- | --- |
| Streamable HTTP | Kaneo instance의 `/api/mcp` | OAuth 2.1 PKCE | HTTP MCP를 지원하는 client, self-hosted 권장 경로 |
| stdio | local `@kaneo/mcp` process | device authorization 또는 API key | stdio가 필요한 Codex/Cursor/Claude 계열 client |

이번 검증은 stdio와 device authorization 조합을 사용했다. `/api/mcp` HTTP 연결과
그 OAuth 2.1 PKCE 흐름을 검증한 것은 아니다.

## Codex 설정

현재 Codex에는 다음 형태로 Kaneo MCP가 등록돼 있다. 실제 hostname은 각 host의
로컬 설정에만 두고 저장소 문서에는 기록하지 않는다.

```toml
[mcp_servers.kaneo]
command = "npx"
args = ["-y", "@kaneo/mcp", "serve"]

[mcp_servers.kaneo.env]
KANEO_API_URL = "https://kaneo.example.com"
```

`KANEO_API_URL`은 Kaneo API origin이며 `/api` suffix를 붙이지 않는다. 공식 package의
기본 device client ID는 `kaneo-mcp`다.

| 환경변수 | 의미 |
| --- | --- |
| `KANEO_API_URL` | Kaneo API origin. `/api`를 포함하지 않음 |
| `KANEO_MCP_CLIENT_ID` | device client ID. 기본값 `kaneo-mcp` |
| `KANEO_API_KEY` | 설정하면 interactive device flow 대신 Bearer API key 사용 |

이번 검증에서는 `KANEO_API_KEY`를 설정하지 않았으므로 device authorization이
실행됐다.

서버에서 `DEVICE_AUTH_CLIENT_IDS`를 별도로 설정하지 않으면 `kaneo-cli`와
`kaneo-mcp`가 기본 허용된다. 값을 직접 지정하면 기본값도 포함해 전체 allowlist를
써야 한다.

```env
DEVICE_AUTH_CLIENT_IDS=kaneo-cli,kaneo-mcp,my-approved-client
```

여기서 `kaneo-cli`는 공식 문서에 정의된 기본 허용 device client ID다. 현재 공식
Kaneo 저장소에는 이 이름의 일반 task-management CLI 설치 절차가 없다. 공식 MCP
실행 파일은 `kaneo-mcp`이며, 제3자의 `kaneo-cli` package와 혼동하지 않는다.

## 이번에 수행한 device 연동

별도 `login` 명령은 실행하지 않았다. 다음 순서로 첫 protected tool 호출이 인증을
자동 시작했다.

1. `KANEO_API_URL`을 주입해 `npx -y @kaneo/mcp serve`를 실행했다.
2. MCP `initialize`와 `notifications/initialized` handshake를 수행했다.
3. 읽기 전용 `whoami` tool을 처음 호출했다.
4. local MCP process가 Kaneo의 device-code endpoint에 code를 요청했다.
5. process가 verification URL과 user code를 표시하고 승인을 polling했다.
6. 사용자가 브라우저의 Kaneo device 화면에서 현재 Kaneo 계정으로 승인했다.
7. MCP가 승인을 감지한 뒤 `whoami` 요청을 완료했다.
8. 인증정보가 host의 `~/.config/kaneo-mcp/credentials.json`에 `0600`으로 저장됐다.
9. 같은 process에서 workspace, member, project, label, notification 조회가 성공했다.

공식 구현의 endpoint 흐름은 다음과 같다.

```text
@kaneo/mcp
  -> POST /api/auth/device/code
  <- verification URL + user code
  -> 사용자의 browser 승인
  -> POST /api/auth/device/token polling
  <- access credential
  -> ~/.config/kaneo-mcp/credentials.json
```

이 승인은 새 Kaneo member를 만드는 과정이 아니다. 이미 로그인한 Kaneo 사용자가
`kaneo-mcp` client에 자신의 Kaneo 권한을 사용하도록 승인한다. MCP tool은 해당
사용자에게 부여된 workspace role과 권한 범위 안에서 동작한다.

## 수동 실행과 진단

interactive installer는 다음처럼 실행한다.

```bash
npx @kaneo/mcp
```

stdio server 자체를 진단할 때는 다음처럼 실행한다.

```bash
KANEO_API_URL=https://kaneo.example.com npx -y @kaneo/mcp serve
```

전역 설치도 가능하지만 host별 버전 재현성을 위해 초기 구성에서는 `npx` 실행과
package version pin을 검토한다.

```bash
npm install -g @kaneo/mcp
kaneo-mcp
```

현재 local 등록 상태는 다음 명령으로 확인할 수 있다.

```bash
codex mcp list
```

이번 환경에서 이 명령은 stdio entry에 `Auth Unsupported`를 표시했다. 그러나 첫
tool 호출에서 `@kaneo/mcp` 자체의 device authorization이 정상 동작했다. 따라서 이
표시를 Kaneo 인증 미지원으로 해석하지 않는다. Codex의 transport-level auth 표시와
stdio child process가 자체 수행하는 device auth는 서로 다른 계층이다.

## 검증 결과

다음 항목을 실제 endpoint와 account data를 대상으로 확인했다.

| 검증 | 결과 |
| --- | --- |
| Kaneo API health | 정상 |
| MCP initialize | 성공, server `kaneo-mcp` `0.1.11` |
| tools discovery | 성공, 36개 |
| device approval | 성공 |
| credential cache 생성 | 성공, `0600` |
| `whoami` | 성공 |
| workspace 목록 | 성공 |
| workspace member 목록 | 성공 |
| project 목록 | 성공, 현재 0개 |
| workspace label 목록 | 성공, 현재 0개 |
| notification 목록 | 성공, 현재 0개 |

쓰기 도구는 사용하지 않았다. 테스트 project를 명시적으로 만든 뒤에만 create,
update, move, comment, label, relation과 time-entry lifecycle을 검증한다.

## 보안상 발견 사항

### `whoami` 응답의 session token

현재 확인한 `@kaneo/mcp` `0.1.11`의 `whoami` 결과에는 사용자 정보뿐 아니라 raw
`session.token`이 포함됐다. 이는 token을 LLM context, MCP trace 또는 debug log로
전달할 수 있으므로 multi-agent 운영에서 중요한 위험이다.

직접 `kaneo-mcp`를 실행하는 대화형 환경에는 이 위험이 남아 있다. Agent container는
`kaneo-mcp-safe-proxy`를 강제해 다음 통제를 적용한다.

- `tools/list`에서 `whoami`를 제거한다.
- 이름을 직접 지정한 `tools/call`도 upstream에 전달하기 전에 거부한다.
- MCP payload를 log로 출력하지 않고 upstream stderr도 agent log로 전달하지 않는다.
- 자동 테스트에서 tool discovery, 직접 호출, upstream 전달 여부와 token 비노출을
  검증한다.

공통 credential 운영 정책은 다음과 같다.

- credential directory를 workspace, artifact, backup, Git과 agent filesystem tool
  scope에서 제외한다.
- prompt injection에 노출되는 agent와 관리용 Kaneo identity를 분리한다.
- agent마다 별도 Kaneo user 또는 최소 권한 API key/device session을 사용한다.

### Host credential 공유

Device credential은 host의 사용자 인증정보다. 여러 sandbox가 같은 파일을 read-only
mount하면 같은 Kaneo 사용자와 권한으로 동작하므로 persona 분리가 authorization
분리가 되지는 않는다.

```text
같은 credential cache
  -> 같은 Kaneo user
  -> 같은 workspace role
  -> audit에서 persona를 사용자 identity로 구분할 수 없음
```

따라서 production 구성에서는 다음 우선순위를 사용한다.

1. 역할 또는 agent instance별 Kaneo user와 최소 권한
2. user별 독립 credential cache/secret
3. sandbox에는 read-only mount
4. host의 credential keeper만 갱신 가능
5. shared credential은 초기 개발이나 동일 trust-domain 안에서만 제한적으로 사용

### Credential 취급

- `credentials.json` 내용을 출력하거나 문서, issue, Buzz, Kaneo task에 붙이지 않는다.
- 권한이 `0600`인지 주기적으로 검사한다.
- token이 trace나 terminal capture에 노출되면 해당 session을 폐기하고 재인증한다.
- container image에 credential을 bake하지 않는다.
- read-only mount를 사용해도 process가 읽은 token은 memory와 tool output을 통해
  노출될 수 있으므로 tool allowlist와 log redaction을 함께 적용한다.

## 오케스트레이션 적용 방침

- 사람이 사용하는 대화형 agent는 공식 `@kaneo/mcp`를 사용할 수 있다.
- 중앙 orchestrator의 결정적 retry, idempotency와 reconciliation은 REST API를
  사용한다.
- headless worker에서 interactive device 승인이 운영 병목이면 agent별 최소 권한
  API key를 secret store로 배포하는 방식을 후속 검토한다.
- Kaneo MCP credential과 Claude/Codex subscription OAuth credential은 목적과 저장
  위치가 다른 별도 인증정보로 취급한다.
- Kaneo MCP 승인은 Buzz member 등록이나 GitHub App 설치를 대신하지 않는다.

## 공식 자료

- [Kaneo MCP documentation](https://kaneo.app/docs/core/integrations/mcp)
- [Official `@kaneo/mcp` README](https://github.com/usekaneo/kaneo/blob/main/packages/mcp/README.md)
- [`@kaneo/mcp` on npm](https://www.npmjs.com/package/@kaneo/mcp)
- [Kaneo environment setup](https://github.com/usekaneo/kaneo/blob/main/ENVIRONMENT_SETUP.md)
- [Device-flow implementation](https://github.com/usekaneo/kaneo/blob/main/packages/mcp/src/auth/device-flow.ts)
- [Credential store implementation](https://github.com/usekaneo/kaneo/blob/main/packages/mcp/src/auth/token-store.ts)
