# 에이전트 실행환경 준비

이 문서는 Buzz에서 함께 동작하는 `dispatcher-planner`, `developer-a`,
`reviewer-a`의 호스트 실행환경을 준비하는 절차다. 실제로 완료한 정상 절차만
기록하며, credential 값은 출력하거나 저장소에 보관하지 않는다.

## 현재 구성

| 에이전트 | 공급자 | Codex 프로필 | 작업공간 | GitHub Gateway |
|---|---|---|---|---|
| `dispatcher-planner` | Codex | `dormael-interactive` | 읽기 전용 | Control App |
| `developer-a` | Codex | `darimuri-development-01` | 읽기/쓰기 | Developer App |
| `reviewer-a` | Codex | `dormael-interactive` | 읽기 전용 | Reviewer App |

Dispatcher와 Reviewer가 같은 Codex 계정을 사용하는 것은 Claude credential을
준비하기 전까지의 임시 구성이다. Buzz 키와 Kaneo 사용자는 세 에이전트별로
분리되어 있다.

호스트 데이터의 기본 위치는 `${HOME}/buzz-agents`다. 컨테이너의 에이전트
프로세스는 UID/GID `10001:10001`, GitHub Gateway는 `1000:1000`으로 실행된다.

## 1. 사전 조건

다음 도구가 필요하다.

- Docker와 Compose v2 (`docker compose`)
- `git`, `jq`, `node`, `flock`, `sudo`
- microk8s와 실행 중인 Buzz
- 실행 중인 Kaneo와 에이전트별 Kaneo 사용자
- `darimuri` Organization에 설치된 역할별 GitHub App

Compose는 Ubuntu에서 기존 `docker-compose` 대신 다음 패키지를 사용한다.

```bash
sudo apt install docker-compose-v2
docker compose version
```

GitHub App은 `darimuri-agent-developer-a`와
`darimuri-agent-reviewer-a`, `darimuri-agent-control-a`를 `darimuri` Organization의 **All repositories**
범위로 설치한다. 생성 및 검증 절차는
[`../github-apps/README.md`](../github-apps/README.md)를 따른다. Credential은
다음 저장소 외부 경로에 있어야 한다.

```text
${HOME}/.config/darimuri-agent-orchestration/github-apps/
  darimuri-agent-control-a/
  darimuri-agent-developer-a/
  darimuri-agent-reviewer-a/
```

별도 저장소의 Gateway 이미지를 Compose가 참조하는 태그로 빌드한다.

```bash
docker build \
  -t local/github-app-agent-gateway:196c5a3 \
  "${HOME}/my/clone/github.com/darimuri/github-app-agent-gateway"
```

## 2. 환경 파일 설정

```bash
cd "${HOME}/my/clone/github.com/darimuri/agent-orchestration/agents"
cp .env.example .env
chmod 0600 .env
```

Buzz owner 공개키는 `buzz/values.yaml`의 `ownerPubkey`에서 확인할 수 있다.

```bash
cd "${HOME}/my/clone/github.com/darimuri/k8s-test"
awk -F'"' '/^ownerPubkey:/ { print $2; exit }' buzz/values.yaml
```

출력된 64자리 공개키를 `.env`의 `BUZZ_AGENT_OWNER_HEX`에 넣는다. private key나
`nsec`를 넣으면 안 된다.

현재의 전체 Codex 구성을 사용하려면 `.env`의 공급자 설정을 다음과 같이 둔다.

```dotenv
DISPATCHER_PROVIDER=codex
DISPATCHER_IMAGE=local/buzz-agent-codex:0.154.0
DISPATCHER_DOCKERFILE=docker/Dockerfile.codex
DISPATCHER_MODEL=gpt-5.3-codex

DEVELOPER_PROVIDER=codex
DEVELOPER_MODEL=gpt-5.3-codex

REVIEWER_PROVIDER=codex
REVIEWER_IMAGE=local/buzz-agent-codex:0.154.0
REVIEWER_DOCKERFILE=docker/Dockerfile.codex
REVIEWER_MODEL=gpt-5.3-codex
```

나머지 경로와 Organization 설정은 다음 기본값을 사용한다.

```dotenv
AGENT_WORKSPACE_ORGANIZATION=darimuri
AGENT_WORKSPACE_GIT_URL_TEMPLATE=git@github.com:{owner}/{repository}.git
AGENT_WORKSPACE_DEFAULT_REF=main
GITHUB_GATEWAY_ALLOWED_OWNERS=darimuri
GITHUB_CONTROL_APP_SLUG=darimuri-agent-control-a
GITHUB_DEVELOPER_APP_SLUG=darimuri-agent-developer-a
GITHUB_REVIEWER_APP_SLUG=darimuri-agent-reviewer-a
```

Kaneo device 인증과 세 에이전트가 공통으로 사용할 Codex 이미지를 먼저 빌드한다.

```bash
cd "${HOME}/my/clone/github.com/darimuri/agent-orchestration/agents"
docker compose build developer-a
docker image inspect local/buzz-agent-codex:0.154.0 >/dev/null
```

## 3. 런타임 디렉터리와 저장소 준비

일반 호스트 사용자로 실행한다. 스크립트가 필요한 작업에만 `sudo`를 호출한다.

```bash
cd "${HOME}/my/clone/github.com/darimuri/agent-orchestration/agents"
./scripts/provision-runtime.sh
```

이 명령은 다음 작업을 수행한다.

- 세 에이전트의 credential 및 Organization 작업공간 디렉터리 생성
- GitHub Gateway의 `apps.json`, `agents.json`, `jobs.json` 준비
- Dispatcher, Developer, Reviewer의 Gateway bearer token 발급
- 컨테이너 UID에 맞는 소유권과 권한 설정

각 에이전트가 사용할 저장소를 별도 clone으로 추가한다.

```bash
./scripts/provision-agent-repository.sh darimuri/k8s-test
./scripts/provision-agent-repository.sh darimuri/github-app-agent-gateway
```

컨테이너에서는 각각 다음 위치로 보인다.

```text
/workspace/darimuri/k8s-test
/workspace/darimuri/github-app-agent-gateway
```

다른 Organization 저장소가 필요해지면 같은 스크립트로 추가한다. 각 에이전트는
서로 다른 clone을 사용한다.

## 4. Buzz 에이전트 키 등록

클러스터 명령은 저장소의 `source.sh`를 먼저 적용해 microk8s 명령을 사용한다.
각 에이전트마다 서로 다른 Nostr private key를 생성하고 Buzz member로 등록한다.

```bash
cd "${HOME}/my/clone/github.com/darimuri/k8s-test"
source ./source.sh

(
  set -euo pipefail
  umask 077
  nak_bin=/home2/dormael/buzz/.tools/nak
  tmp=
  trap '[[ -z "${tmp}" ]] || rm -f "${tmp}"' EXIT

  for agent in dispatcher-planner developer-a reviewer-a; do
    tmp="$(mktemp)"
    "${nak_bin}" key generate >"${tmp}"
    pubkey="$("${nak_bin}" key public <"${tmp}")"

    sudo install -m 0600 -o 10001 -g 10001 \
      "${tmp}" \
      "${HOME}/buzz-agents/${agent}/credentials/buzz-private-key"
    rm -f "${tmp}"
    tmp=

    kubectl -n buzz exec deployment/buzz -- \
      /usr/local/bin/buzz-admin add-member \
      --pubkey "${pubkey}" \
      --role member

    printf '%s pubkey: %s\n' "${agent}" "${pubkey}"
  done
)
```

출력되는 공개키는 확인용이다. `buzz-private-key` 파일이나 그 내용은 공유하거나
Git에 추가하지 않는다.

커뮤니티 멤버 등록에는 이름이나 owner 관계가 포함되지 않는다. trusted host의 owner
키로 NIP-OA 인증 태그를 발급하고, 인증 태그가 포함된 agent 프로필과 owner가 서명한
`kind:30177` 정책을 게시한다. 스크립트는 private key나 인증 태그를 출력하지 않는다.

```bash
cd "${HOME}/my/clone/github.com/darimuri/agent-orchestration/agents"
./scripts/provision-buzz-agent-identity.sh
```

이 작업은 각 credential 디렉터리에 UID/GID `10001:10001`, mode `0600`인
`buzz-auth-tag`를 설치한다. 공식 Buzz SDK의 고정 커밋으로 만든 로컬 provisioner
이미지가 서명을 계산하며 owner key는 이미지 layer나 명령 인자로 전달되지 않는다.
프로필과 정책만 다시 검사할 때는 다음을 실행한다.

```bash
./scripts/provision-buzz-agent-identity.sh --verify-only
```

세 이름은 서로 다르며 같은 키를 유지한다. 인증된 프로필이 agent와 owner의 관계를
증명하고, owner 서명 정책이 `respond_to=owner-only`를 선언한다. 이 두 event와 채널의
`bot` membership이 함께 있어야 Buzz Desktop의 해당 채널 `@` 자동완성 대상이 된다.

현재 세 에이전트는 `agent test` 채널에 `bot` 역할로 등록했다.

```text
channel: agent test
channel id: e04d48c5-f100-4e75-9362-aaac11094227
members: Dispatcher Planner, Developer A, Reviewer A
role: bot
```

다른 채널을 사용할 때는 owner/admin identity로 각 공개키를 별도로 추가한다.

```bash
buzz channels add-member \
  --channel <CHANNEL_UUID> \
  --pubkey <AGENT_PUBLIC_KEY> \
  --role bot
```

## 5. Kaneo 사용자와 device credential 준비

Kaneo에 다음 사용자 세 명을 만들고 필요한 workspace/project 권한을 부여한다.

- `dispatcher-planner`
- `developer-a`
- `reviewer-a`

각 명령이 출력하는 device URL을 열고, 반드시 해당 에이전트의 Kaneo 사용자로
승인한다.

```bash
cd "${HOME}/my/clone/github.com/darimuri/agent-orchestration/agents"

./scripts/provision-kaneo-credential.sh dispatcher-planner
./scripts/provision-kaneo-credential.sh developer-a
./scripts/provision-kaneo-credential.sh reviewer-a
```

사용자를 바꾸거나 credential을 갱신할 때는 기존 세션을 폐기하는 `--replace`를
사용한다.

```bash
./scripts/provision-kaneo-credential.sh --replace dispatcher-planner
```

## 6. Codex 프로필 준비

Codex 계정은 이름이 있는 호스트 프로필로 보관한다. 기존 대화형 계정은 다음과
같이 복사했다.

```bash
profile_dir="${HOME}/.config/darimuri-agent-orchestration/codex/dormael-interactive"
install -d -m 0700 "${profile_dir}"
install -m 0600 "${HOME}/.codex/auth.json" "${profile_dir}/auth.json"
```

두 번째 개발 계정은 독립된 `CODEX_HOME`으로 로그인했다.

```bash
profile_dir="${HOME}/.config/darimuri-agent-orchestration/codex/darimuri-development-01"
install -d -m 0700 "${profile_dir}"
CODEX_HOME="${profile_dir}" codex login --device-auth
```

프로필을 런타임 credential 디렉터리에 일반 파일로 배치한다. 컨테이너 밖의 절대
경로를 가리키는 symbolic link는 컨테이너에서 해석되지 않으므로 사용하지 않는다.

```bash
# Dispatcher: dormael-interactive
sudo install -m 0600 -o 10001 -g 10001 \
  "${HOME}/.config/darimuri-agent-orchestration/codex/dormael-interactive/auth.json" \
  "${HOME}/buzz-agents/dispatcher-planner/credentials/codex-auth.json"

# Developer: darimuri-development-01
sudo install -m 0600 -o 10001 -g 10001 \
  "${HOME}/.config/darimuri-agent-orchestration/codex/darimuri-development-01/auth.json" \
  "${HOME}/buzz-agents/developer-a/credentials/codex-auth.json"

# Reviewer: dormael-interactive
sudo install -m 0600 -o 10001 -g 10001 \
  "${HOME}/.config/darimuri-agent-orchestration/codex/dormael-interactive/auth.json" \
  "${HOME}/buzz-agents/reviewer-a/credentials/codex-auth.json"
```

계정을 바꿀 때는 원하는 프로필의 `auth.json`을 같은 방식으로 다시 설치하고 해당
Compose 서비스를 재생성한다.

## 7. 사전 검사

Preflight는 credential 내용을 출력하지 않고 파일 존재 여부, UID, mode, 작업공간
권한과 Gateway 설정을 확인한다.

```bash
cd "${HOME}/my/clone/github.com/darimuri/agent-orchestration/agents"
sudo ./scripts/preflight.sh
docker compose config --quiet
```

정상 결과는 다음과 같다.

```text
Preflight passed. No credential values were read or printed.
```

## 8. 시작과 상태 확인

```bash
docker compose up -d
docker compose ps
docker compose logs --tail=100 dispatcher-planner developer-a reviewer-a github-gateway
```

GitHub 작업을 맡기기 전에는 trusted host에서
`${HOME}/buzz-agents/github-gateway/jobs.json`에 해당 repository와 역할을 허용하는
job assignment를 추가해야 한다. `jobs.json`이 비어 있으면 에이전트의 GitHub 도구
호출은 거부된다.

## Credential 배치 결과

각 에이전트 디렉터리에는 다음 파일이 준비된다.

```text
${HOME}/buzz-agents/<agent>/credentials/
  buzz-private-key
  buzz-auth-tag
  kaneo-credentials.json
  codex-auth.json
```

세 에이전트에는 추가로 다음 파일이 있다.

```text
github-gateway-agent-token
```

Credential 디렉터리는 mode `0700`, 내부 파일은 `0600`, 소유자는 UID/GID
`10001:10001`이어야 한다. GitHub App private key, Codex 인증정보, Kaneo 세션,
Buzz private key는 Git에 commit하지 않는다.

## Fourth role: selective F2 procedure only

Do not append `host-operator` to legacy three-agent loops or reuse another persona's
private key/HOME/Codex login/Kaneo session. Follow `HOST_OPERATOR_F2_ACCEPTANCE.md` after
explicit owner deployment authorization. Source PR review does not authorize these
host/browser/network effects. All fourth selectors are literal `--agent host-operator`.

The owner prepares a separate fourth Git manifest and approved three-key public roster,
then runs selected runtime and selected bounded storage, adds only necessary independent
RO clones, and installs independent owner-generated Buzz, dedicated Kaneo account device
session and fourth Codex login credentials. Existing provisioners still default to
three; selected runtime exits before any Gateway requirement or write. No new Gateway
role or Executor mount is introduced. Metadata preflight is distinct from live account,
model/ACP and authorization acceptance. Leave normal ext4 lost+found untouched.
