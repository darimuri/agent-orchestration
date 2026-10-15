# Agent Orchestration Work Log

Buzz, Kaneo, GitHub/GHES와 여러 Claude/Codex agent를 이용한 개발 자동화 구성을
조사하고 설계한 작업 기록이다. 실제 credential, 사용자 이메일, device code,
session token과 내부 resource ID는 기록하지 않는다.

## 2026-09-12 ~ 2026-09-19

### 에이전트 오케스트레이션 타당성 조사

Buzz·Kaneo·GitHub/GHES를 중심으로 역할과 persona가 다른 여러 코딩 에이전트가 개발,
리뷰, 테스트와 릴리스를 자동화하는 구성이 가능한지 조사했다.

### 전체 아키텍처 및 구현 계획 수립

중앙 orchestrator, 여러 PC의 pull worker, 격리 sandbox, event normalization, dedupe,
작업 lease와 authoritative-state reconciliation 구조를 설계했다.

### GitHub/GHES 중심 forge 전략 결정

Gitea보다 GitHub.com과 GHES를 우선 지원하기로 결정하고 GitHub App을 server-to-server
identity의 기본으로 선택했다.

### GitHub review와 Actions 역할 정리

자동 리뷰는 사람의 PR approval을 흉내 내지 않고 commit SHA에 결합된 Check Run으로
게시하며, Actions는 신뢰 가능한 빌드·테스트 결과와 배포 gate에 사용하도록 했다.

### GitHub Free Organization fallback 설계

무료 private repository에서 ruleset, required reviewer 또는 environment 보호가 부족한
경우에도 비-LLM merge/deploy broker와 외부 정책 검사로 최대한 기능하도록 설계했다.

### Buzz agent identity와 member 등록 조사

동일한 provider 계정을 쓰더라도 persona별 격리 process와 독립 Nostr keypair를
사용해 Buzz에서는 서로 다른 member와 audit identity로 동작시키는 방식을 정리했다.

### 다중 host와 sandbox 실행 구조 설계

노트북과 데스크탑에서 host별로 여러 agent sandbox를 실행하고, sandbox에 접속해
로그인·로그아웃하거나 credential profile을 전환하는 운영 방식을 검토했다.

### Claude/Codex 구독 OAuth 공유 설계

초기 inference 인증은 구독 OAuth만 사용하고 host가 credential의 유일한 writer가
되며 sandbox는 필요한 인증 파일만 read-only로 mount하도록 설계했다.

### LiteLLM 도입 시점 결정

초기에는 Claude/Codex 구독 OAuth를 직접 사용하고 API 과금, 중앙 budget, rate limit과
provider fallback이 필요해질 때 LiteLLM을 후속 도입하기로 했다.

### Kaneo API와 MCP 기능 조사

Kaneo REST/OpenAPI, built-in `/api/mcp`, 공식 stdio `@kaneo/mcp`, outgoing webhook,
workspace role과 agent identity 분리 가능성을 조사했다.

### Kaneo MCP 실제 서버 확인

현재 self-hosted Kaneo API health와 등록된 stdio MCP를 확인하고 `@kaneo/mcp`
`0.1.11`이 36개 tool을 노출하는 것을 직접 검증했다.

### Kaneo device authorization 수행

`whoami` 최초 호출로 device flow를 시작하고 브라우저 승인을 완료했다. 발급된
credential cache가 host의 `~/.config/kaneo-mcp/credentials.json`에 `0600`으로
저장되는 것을 확인했다.

### Kaneo MCP 읽기 기능 검증

`whoami`, workspace, member, project, label과 notification 조회를 실제 계정으로
검증했다. 당시 workspace에는 project가 없었다.

### Kaneo MCP 인증 보안 검토

현재 `whoami` 응답이 raw `session.token`을 포함하는 것을 발견했다. 일반 agent에서
도구를 차단하거나 MCP proxy/patch에서 token과 개인정보를 제거해야 한다.

### Kaneo credential 공유 위험 정리

여러 persona가 동일 cache를 읽으면 모두 같은 Kaneo user와 workspace role로
동작하므로 process 격리가 authorization과 audit identity 분리를 대신하지 못한다.

### Kaneo MCP 설정 문서 작성

Codex 설정, stdio와 HTTP MCP 차이, device 인증 절차, 검증 결과와 보안 방침을
`KANEO-MCP-SETUP.md`에 정리했다.

### Kaneo `mcp-test` 프로젝트 생성

실제 Kaneo workspace에 비공개 `mcp-test` 프로젝트를 만들고 테스트 데이터 보존
목적을 프로젝트 설명에 기록했다.

### Kaneo project와 column 기능 검증

project 생성·수정·개별 조회·목록과 기본 `To Do`, `In Progress`, `In Review`, `Done`
column 조회를 검증했다.

### Kaneo task lifecycle 검증

서로 다른 status와 priority를 가진 task 3개를 만들고 조회, merge-update, status,
assignee, start date, due date, 정렬과 복합 filter를 검증했다.

### Kaneo comment와 activity 검증

comment 생성·수정·목록과 task activity history 조회를 검증했다. 별도의 E2E 결과
요약 comment도 대표 task에 남겼다.

### Kaneo label과 task relation 검증

workspace label을 만들고 task에 연결했다. `subtask`, `blocks`, `related` 세 가지
relation을 생성하고 관계 조회 결과를 확인했다.

### Kaneo time entry 검증

time entry 생성·수정·개별 조회·목록을 검증하고 45분 기록을 보존했다. 생성 직후
`duration=0`이었다가 수정 후 `2700`초로 계산되는 특이점을 확인했다.

### Kaneo search와 notification 검증

project·task·comment·activity 통합 검색과 notification 조회를 검증했다. `projectId`만
지정한 검색은 실패하고 `workspaceId`를 함께 전달하면 성공하는 동작을 확인했다.

### Kaneo move 제한 확인

`move_task`에 현재 project를 destination으로 지정하면 `Task is already in that
project`로 거절됐다. 불필요한 두 번째 project를 남기지 않기 위해 cross-project
이동은 수행하지 않았다.

### 테스트 데이터 보존

delete 계열 tool, comment 삭제, label detach와 relation 삭제는 호출하지 않았다.
`mcp-test` project, task 3개, comment, label, relation과 time entry를 그대로 남겼다.

## 작성된 문서

- `README.md`: 문서 index와 설계 요약
- `RESEARCH.md`: 기술·기능·보안 조사
- `ARCHITECTURE.md`: 권장 architecture와 trust boundary
- `PLAN.md`: 단계별 구현 계획과 acceptance criteria
- `GITHUB-FREE-ORG.md`: GitHub Free Organization fallback
- `BUZZ-AGENT-PROVISIONING.md`: Buzz persona identity와 member 등록
- `SUBSCRIPTION-OAUTH-SANDBOX.md`: host OAuth와 sandbox 공유 설계
- `KANEO-MCP-SETUP.md`: Kaneo MCP 설정·인증·검증 기록
- `adr/0001-github-primary.md`: GitHub/GHES 우선 결정
- `adr/0002-free-org-degraded-mode.md`: Free Organization degraded mode 결정

## 현재 상태

- 설계와 인증 검증 단계까지 완료했다.
- Kaneo MCP 읽기·쓰기 핵심 기능의 실제 E2E 검증을 완료했다.
- `mcp-test` 데이터는 후속 회귀 테스트와 agent 연결 검증에 재사용할 수 있다.
- orchestrator, worker runtime, GitHub App과 실제 automation workflow 구현은 아직
  시작하지 않았다.
