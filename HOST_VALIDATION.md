# Kaneo #12 호스트 검증

[English](HOST_VALIDATION.en.md)

담당자는 dormael입니다. 움직이는 브랜치가 아닌, Kaneo/Buzz에 보고된 정확한
이전 커밋을 기준으로 실행합니다. 아래 절차는 검증 증거를 수집하며 운영 전환을
승인하는 절차가 아닙니다. 검증과 리뷰가 끝날 때까지 기존 `k8s-test` 런타임을
운영 기준으로 유지합니다.

## 1. 검증 기준 revision과 선행조건

신뢰할 수 있는 Linux 호스트에서 준비된 이전 worktree를 사용합니다. 에이전트에서
보이는 경로는 `/workspace/darimuri/agent-orchestration-task12`이며 호스트의 마운트
경로는 다를 수 있습니다. 다른 trusted checkout에서 검증한다면 HEAD와 파일 트리가
보고된 이전 커밋과 일치해야 합니다. 비어 있는 대상 저장소의 main은 검증하지 않습니다.

기존 proxy 테스트 8/8 결과의 기준 SHA는
`693dbb36298d7f832c09546b2c64b7ba5756a79c`입니다. 이후 언어판을 나눈 문서 커밋은
새 HEAD를 만듭니다. 아래 `expected_sha`에는 **실제로 검증할 checkout의 보고된
최종 SHA**를 넣고, 그 SHA를 로그에 기록합니다. 기존 테스트 결과를 새 HEAD에서
다시 실행한 결과로 표현하지 않습니다. 문서 변경만으로 host 검증이 완료되지는 않습니다.

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

Node 22(런타임 이미지의 기준 버전), GNU coreutils, 호스트 사용자가 접근 가능한
Docker daemon이 필요합니다. 이미지 빌드에는 기존에 고정한 base image와 npm
패키지에 접근할 네트워크가 필요합니다. App mock 테스트와 컨테이너 smoke 테스트에는
운영 credential이 필요하지 않습니다. runtime provisioning fixture 테스트는 sudo로
임시 UID 10001/1000 파일과 로컬 fixture clone을 관리하고 정리하므로 root가 아닌
일반 호스트 사용자로 실행합니다. 이 절차의 일부로 에이전트에 호스트 도구를 설치하거나
Docker socket을 마운트하지 않습니다.

## 2. 격리된 패키지 테스트와 이미지 검증

빌드 스크립트는 `agents/.env`를 자동으로 읽어 적용하므로, 검증 checkout에 실제
`agents/.env`가 없는지 확인합니다. 기존 런타임 환경 파일은 외부에 유지하고 뒤의
preflight에서만 사용합니다. 저장소에 기록된 기본값을 검증하도록 AGENT_* 빌드
덮어쓰기 설정이 없는 새 셸에서 저장소 루트를 기준으로 실행합니다.

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

네 명령을 모두 실행하고 실패를 포함한 각 종료 코드를 보존합니다. 기대 결과는
proxy 테스트 8/8, `GitHub App bootstrap tests passed.`,
`Runtime provisioning tests passed.`, 두 이미지 빌드와 proxy 테스트 성공입니다.
images 로그에는 `Container entrypoint smoke tests passed.`와
`Gateway agent provisioning tests passed.`가 있어야 하며 모두 종료 코드 0이어야 합니다.
이미지 스크립트는 전체 Gateway provisioning 테스트를 포함합니다. 실행하지 못한
테스트는 통과가 아닌 대기 상태입니다. 빌드는 로컬 이미지 태그와 캐시를 변경하므로
검증용 호스트에서 실행하거나 운영 자동화가 해당 태그를 사용하지 않는지 확인합니다.
이 단계에는 `compose up`, 재시작, 실제 provisioning, 볼륨 삭제가 포함되지 않습니다.

## 3. 기존 호스트 설정의 읽기 전용 검증

Git 외부에 있는 기존의 신뢰할 수 있는 호스트 환경 파일을 절대 경로로 지정합니다.
설정된 credential 경로는 호스트에 그대로 둡니다. 파일 내용을 대화에 붙여 넣지 않습니다.

```bash
runtime_env=/absolute/host/path/to/existing-runtime.env
run_check preflight sudo bash agents/scripts/preflight.sh "$runtime_env"
run_check compose docker compose --env-file "$runtime_env" \
  -f agents/compose.yaml config --quiet
```

종료 코드 0과 `Preflight passed. No credential values were read or printed.`를
기대합니다. preflight는 존재 여부, 소유자, 권한 및 설정 일관성을 확인하며 서비스를
provisioning하거나 재시작하지 않습니다. `config --quiet`는 치환된 secret을 출력하지
않고 검증합니다. 실패하면 해당 검사 항목을 보고하고, 별도 승인 없이 권한을 고치거나
운영 설정을 변경하지 않습니다.

## 4. Buzz / Kaneo / Gateway 연결 증거

이미 실행 중인 에이전트의 기존 인증 세션만 사용합니다. 기존 developer 서비스 안에서
다음 읽기 전용 Buzz CLI 검사를 실행할 수 있습니다.

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

채널 조회 성공 응답을 기대합니다. 기존 서비스가 없으면 검사를 대기로 기록하고
새 서비스를 시작하지 않습니다. 같은 Buzz 스레드에서 Developer A에게 다음 native
MCP 호출을 실행하고 identity/repository/task 상태만 보고하도록 요청합니다.

exec 셸은 실행 중인 entrypoint가 export한 변수를 상속하지 않으므로 기존 마운트
파일에서 인증을 로드합니다. 셸 추적(set -x)을 켜거나 변수 값을 출력하지 않습니다.
이 명령은 런타임 인증 절차로 credential을 읽기만 하며 변경하지 않습니다.

```text
mcp__kaneo__get_task({"taskId":"xbb7u0bj8sc1p30ewc6709yb"})
mcp__github_gateway__github_gateway_identity({})
mcp__github_gateway__github_get_repository({"jobId":"kaneo12-agent-orchestration-developer"})
mcp__github_gateway__github_get_repository({"jobId":"kaneo12-k8s-test-developer"})
```

기대 결과는 #12 담당자 developer-a, Gateway identity developer-a/developer,
저장소 darimuri/agent-orchestration 및 darimuri/k8s-test입니다. 이전 smoke assignment가
아닌 이 활성 job만 사용합니다(만료: 2026-10-18T06:05:06Z). Buzz event ID와 실제 실행
중인 image ID를 별도로 기록합니다. 기존 컨테이너 검사는 현재 연결을 입증하며 새로
빌드한 이미지가 배포됐음을 입증하지 않습니다. 새 런타임의 전체 연결 검증에는 별도로
승인된 격리 검증 인스턴스 또는 운영 변경이 필요하므로 해당 수락 조건은 대기로 유지합니다.

## 5. 증거 기록과 배포 범위

이전 커밋 SHA, 호스트/런타임 image ID, 명령 종료 코드, 비공개 로그 위치와 남은 실패를
Kaneo #12에 기록합니다. 공유 전에 로그에 secret이 없는지 확인합니다. 환경 파일,
token, auth tag 또는 credential 출력은 업로드하지 않습니다. 개발자는 draft PR에
증거를 연결하고 독립 리뷰를 요청합니다. 검증과 리뷰 후에만 별도의 원본 저장소 PR에서
대상 revision을 고정하고 기존 구현을 제거할 수 있습니다. merge, 배포, 운영 재시작은
현재 작업의 승인 범위 밖입니다. 롤백은 [MIGRATION.md](MIGRATION.md)를 참고합니다.
