# GitHub App bootstrap

`apps.json`은 GitHub.com에서 사용하는 역할별 App 이름, bootstrap 여부, 설치 범위,
최대 permission과 새 App의 초기 webhook event를 선언한다. `create-apps.sh`는 기본적으로 bootstrap
App만 대상으로 GitHub App Manifest flow를 진행한다.

## App 목록

1. `darimuri-agent-developer-a`
2. `darimuri-agent-reviewer-a`
3. `darimuri-agent-control-a`
4. `darimuri-forge-publisher-a`
5. `darimuri-merge-broker-a`
6. `darimuri-deploy-broker-a`

현재 bootstrap 대상은 Control, Developer, Reviewer 세 개다. 나머지는
`--include-future-roles`를 명시한 경우에만 생성·검증 대상에 포함된다.
`kaneo-darimuri`는 기존 Kaneo integration 전용이며 이 목록에 포함하지 않는다.

세 bootstrap App은 다음 repository permission을 가져야 한다.

| App | Repository permissions |
|---|---|
| `darimuri-agent-control-a` | Contents: read, Issues: read and write |
| `darimuri-agent-developer-a` | Contents: read and write, Pull requests: read and write, Issues: read and write |
| `darimuri-agent-reviewer-a` | Actions: read, Checks: read and write, Contents: read, Pull requests: read and write, Issues: read and write |

기존 App의 permission은 Manifest flow로 변경할 수 없다. Organization App 설정의
**Permissions & events**에서 Developer와 Reviewer에 Issues `Read and write`를 추가하고,
Control App을 새로 만들거나 같은 정책으로 갱신한다. 추가 권한 승인 요청이 생기면
Organization owner가 승인한 뒤 세 App의 installation이 **All repositories**인지 확인한다.
그 다음 아래 검증 명령으로 저장된 private key, 실제 permission과 설치 범위를 확인한다.

## 사전 조건

- `gh`, `jq`, `openssl`, `python3`
- `gh auth login --hostname github.com` 완료
- `darimuri` organization에서 GitHub App을 생성하고 설치할 권한
- 기본 브라우저가 Organization owner인 `dormael` 계정으로 로그인된 상태
- 로컬 브라우저가 `127.0.0.1` callback에 접근 가능

등록 내용을 먼저 확인한다.

```bash
./create-apps.sh --dry-run
```

이미 만든 bootstrap App의 실제 permission, `All repositories` 설치 범위와
`k8s-test` 접근을 다시 확인한다. Control, Developer 또는 Reviewer credential이 없거나 실제
등록 상태가 `apps.json`과 다르면 실패한다. GitHub가 암묵적으로 반환하는
`metadata: read`는 비교에서 정규화한다.

Webhook은 **General → Webhook → Active**를 해제한 상태로 유지한다. GitHub는 비활성
Webhook의 기존 event 선택값을 API에 남겨 두면서 설정 화면에서는 숨기므로 검증 결과에
정보로만 출력한다. 이 구성에는 webhook 수신 endpoint가 없다.

```bash
./create-apps.sh --verify-installations
```

Future 역할까지 명시적으로 포함하려면 다음 옵션을 추가한다.

```bash
./create-apps.sh --include-future-roles
./create-apps.sh --verify-installations --include-future-roles
```

## 실행

```bash
./create-apps.sh
```

각 App마다 다음 순서로 진행한다.

1. 터미널에서 Create/Skip/Quit을 선택한다.
2. 스크립트가 localhost callback을 시작하고 GitHub App Manifest 화면을 연다.
3. 브라우저에서 등록 소유자가 `darimuri` Organization인지 확인하고 App 이름을 바꾸지
   않은 채 permission/event를 확인한다.
4. `Create GitHub App`을 누른다.
5. callback이 받은 일회용 code를 스크립트가 manifest conversion API로 교환한다.
6. private key와 secret을 저장소 밖 credential directory에 저장한다.
7. 브라우저가 다른 계정으로 로그인돼 있으면 Organization owner인 `dormael`로
   전환한다. 설치 화면에서 `darimuri`와 `All repositories`를 선택한다.
8. 터미널로 돌아와 Enter를 누르면 App JWT로 permission과 installation의 `all`
   범위를 확인하고 `darimuri/k8s-test`에 실제 접근 가능한지 검증한다.

검증 실패 시 다음 App으로 자동 진행하지 않는다. 설치 화면 다시 열기(`r`), 명시적으로
건너뛰기(`s`), 전체 중단(`q`) 중 하나를 선택해야 한다. `agent-darimuri` 개인 계정에
설치하면 `scope=all`이어도 그 개인 계정 소유 repository에만 적용되며
`darimuri/k8s-test`에는 접근할 수 없다.

기본 credential 경로는 다음과 같다.

```text
~/.config/darimuri-agent-orchestration/github-apps/<app-slug>/
  app.json
  manifest.json
  private-key.pem
  client-secret
  webhook-secret
```

Directory는 `0700`, file은 `0600`으로 생성된다. 다음 환경변수로 위치를 바꿀 수 있다.

```bash
GITHUB_APP_CREDENTIALS_DIR=/secure/path/github-apps ./create-apps.sh
```

검증할 repository 이름은 기본적으로 `k8s-test`이며 다음처럼 변경할 수 있다.

```bash
GITHUB_APP_VERIFY_REPOSITORY=another-repository ./create-apps.sh
```

Private key, client secret, webhook secret과 manifest conversion 응답은 repository에
복사하거나 commit하지 않는다. 생성 도중 실패하면 GitHub App 설정에서 새 private key를
발급하고 기존 key를 폐기한다.

Manifest conversion 응답의 App owner가 `darimuri`가 아니면 credential은 복구를 위해
저장하지만 설치를 중단한다. 잘못된 개인 계정 소유 App을 삭제하거나 Organization으로
이전한 뒤 credential directory를 archive하고 다시 실행한다. 브라우저 로그인과
`gh auth login`은 별도 session이므로 둘 다 올바른 계정인지 확인한다.

Installation 확인은 일반 `gh auth` token의 `/user/installations` endpoint를 사용하지
않는다. 저장된 App client ID와 private key로 10분 미만의 App JWT를 만들고
`/app/installations` 및 `/repos/{owner}/{repo}/installation`을 조회한다. JWT는 file에
저장하거나 출력하지 않는다.

## Manifest와 실제 권한

`apps.json`의 permission은 App registration의 최대 권한이다. 실제 job용 installation
token을 발급할 때 gateway가 repository와 permission을 다시 축소한다. App 생성 후
permission을 늘리면 organization owner의 재승인이 필요하므로 manifest 변경은 보안
변경으로 review한다.

Mock API 기반 회귀 test는 실제 credential이나 GitHub 호출 없이 bootstrap 대상,
필수 credential, permission과 설치 범위 검증을 확인한다.

```bash
./test-create-apps.sh
```

GitHub App Manifest는 webhook을 비활성화해도 유효한 hook URL을 요구한다. 현재 endpoint가
아직 배포되지 않았으므로 모든 App은 project URL을 placeholder로 넣고
`hook_attributes.active=false`로 생성한다. 다음 환경변수로 다른 placeholder를 지정할 수
있다.

```bash
GITHUB_APP_WEBHOOK_PLACEHOLDER_URL=https://example.com/github/webhook ./create-apps.sh
```

실제 endpoint가 준비되면 App 설정에서 HTTPS webhook URL과 secret을 연결하고 HMAC
검증을 완료한 뒤 활성화한다.

## 잘못된 owner로 생성된 App 복구

브라우저가 `agent-darimuri` 같은 다른 계정으로 로그인된 상태에서 manifest를 승인하면
App registration 자체가 그 개인 계정 소유가 된다. `scope=all`은 그 개인 계정 소유
repository 전체를 뜻하며 `darimuri/k8s-test` 접근 권한을 주지 않는다. 브라우저 계정을
나중에 전환해도 이미 만든 App의 owner는 바뀌지 않는다.

삭제·재생성보다 ownership transfer를 우선한다.

1. 브라우저에서 잘못된 owner 계정으로 로그인한다.
2. **Settings → Developer settings → GitHub Apps → 대상 App → Advanced**로 이동한다.
3. **Transfer ownership**에서 새 owner로 `darimuri` Organization을 선택한다.
4. 기존 개인 계정 installation이 제거될 수 있다는 경고를 확인하고 transfer한다.
5. 세 App 모두 transfer한 뒤 `gh` CLI를 `dormael`로 다시 인증한다.

```bash
gh auth login --hostname github.com
gh auth status --hostname github.com
```

6. 기본 브라우저도 `dormael`로 로그인하고 스크립트를 다시 실행한다.
7. Organization 소유 App을 `darimuri`에 설치하고 repository 범위를 선택한다.

스크립트는 저장된 `app.json` owner가 아니라 private key로 인증한 `/app`의 live owner를
권위로 사용한다. 따라서 transfer 뒤 local metadata가 이전 owner를 가리켜도 App ID와
private key가 유효하면 transfer를 감지하고 계속 진행한다.

Transfer 후 기존 private key가 동작하지 않으면 Organization의 App 설정에서 새 private
key를 생성해 local `private-key.pem`을 안전하게 교체한다. Transfer가 불가능하거나 App을
새로 만들기로 결정한 경우에만 잘못 만든 App을 삭제하고 credential directory를 archive한
뒤 재생성한다.
