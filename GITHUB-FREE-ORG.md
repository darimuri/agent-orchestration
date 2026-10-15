# GitHub Free Organization 호환 전략

조사일: 2026-09-13 (Asia/Seoul)

## 결론

GitHub Free Organization에서도 GitHub App, webhook, Issue/PR, Check Run, Actions를
사용해 자동화의 대부분을 구현할 수 있다. 그러나 private repository에서는 protected
branch, ruleset, required review/status check, CODEOWNERS 강제, Actions environment를
사용할 수 없다. 따라서 자동화 기능은 유지하되 강제 지점을 외부 orchestrator의
publisher/merge/deploy broker로 옮기는 degraded mode가 필요하다.

이 mode는 GitHub 내부 통제와 완전히 동등하지 않다. repository write/admin 권한이
있는 사람이 UI/API로 직접 push 또는 merge하는 것까지 GitHub Free private repo에서
기술적으로 막을 수는 없다. 자동화 경로는 강제할 수 있지만 사람의 직접 우회는
권한 최소화, 감사, 운영 규칙으로 완화한다.

## 기능 가용성

| 기능 | Free public | Free private | Team private | Enterprise Cloud/GHES |
|---|---:|---:|---:|---:|
| GitHub App, webhook, installation token | 가능 | 가능 | 가능 | 가능 |
| Issue, PR, Check Run | 가능 | 가능 | 가능 | 가능 |
| GitHub Actions | 가능 | 가능, quota | 가능, quota | 가능 |
| Protected branch와 required checks/reviews | 가능 | 불가 | 가능 | 가능 |
| Repository ruleset | 가능 | 불가 | 가능 | 가능 |
| Organization-wide ruleset | 불가 | 불가 | 가능 | Enterprise 범위 가능 |
| CODEOWNERS required review | 가능 | 불가 | 가능 | 가능 |
| Actions environment/secret | 가능 | 불가 | 가능 | 가능 |
| Private repo environment required reviewer | 해당 없음 | 불가 | 불가 | 가능 |

GitHub 공식 문서는 Free organization의 protected branch와 ruleset을 public repository에만
제공한다고 명시한다. private repository에는 GitHub Team 이상이 필요하다:
[Protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches),
[Rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets).

Free private repository에서는 Actions environment와 environment secret도 사용할 수
없다. Team private repository는 environment를 만들 수 있지만 required reviewer와 wait
timer 같은 deployment protection rule은 public repository 또는 Enterprise가 필요하다:
[Managing environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments),
[Deployments and environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

### Actions quota

GitHub Free Organization의 private repository에는 매월 다음 기본량이 포함된다.

- GitHub-hosted standard runner: 2,000분
- Actions artifact와 GitHub Packages 공유 저장량: 500MB
- cache: repository당 10GB

결제 수단이 없으면 quota 소진 후 추가 hosted-runner 사용이 차단된다. public repository의
standard GitHub-hosted runner와 self-hosted runner 사용은 무료다:
[GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

## Capability mode

오케스트레이터는 요금제 이름으로 동작을 추측하지 않고 실제 기능을 탐지해 다음
mode 중 하나를 선택한다.

```yaml
github_capabilities:
  protected_branches: true | false
  repository_rulesets: true | false
  organization_rulesets: true | false
  required_status_checks: true | false
  required_pull_request_reviews: true | false
  code_owner_review: true | false
  actions_environment: true | false
  environment_required_reviewers: true | false
  github_hosted_runners: true | false
```

| Mode | 대표 환경 | 정책 강제 위치 |
|---|---|---|
| `native-guarded` | Free public, Team private의 merge | GitHub protected branch/ruleset + broker 이중 확인 |
| `external-guarded` | Free private | publisher/merge/deploy broker |
| `enterprise-guarded` | Enterprise Cloud, GHES | ruleset + environment + broker 이중 확인 |

API가 `403` 또는 `404`를 반환했다고 곧바로 기능 부재로 판단하지 않는다. App permission
부족, repository visibility, plan, GHES version을 구분하고 operator가 확정한 capability
snapshot을 저장한다.

## Free private degraded mode

### 1. 개발: agent는 target repository에 쓰지 않는다

Free private에서는 developer App에 `contents: write`를 주면 default branch까지 쓸 수
있고 GitHub가 branch restriction으로 막아주지 못한다. 따라서 LLM agent에는 다음만
허용한다.

- `contents: read`, metadata/issue/PR read
- ephemeral workspace에서 patch와 commit metadata 생성
- orchestrator artifact endpoint에 patch bundle 업로드

신뢰된 비-LLM `publisher`가 patch를 검증한 뒤 feature branch와 PR을 만든다.

```text
Developer agent --patch bundle--> Publisher broker --feature branch/PR--> GitHub
```

publisher 검증 항목:

- active job/lease와 base SHA 일치
- 대상 repository와 branch prefix 일치
- default/protected-like ref 직접 갱신 거부
- patch path traversal, submodule, symlink, binary size 제한
- `.github/workflows/**`, `CODEOWNERS`, orchestration policy 변경은 별도 high-risk 분류
- 동일 effect key의 branch/PR이 이미 있는지 조회 후 생성

publisher App private key는 agent/worker에 전달하지 않는다.

### 2. 리뷰와 병합: required check 대신 merge broker

Actions와 reviewer App은 계속 Check Run을 게시할 수 있지만 GitHub Free private에서는
이를 required로 만들 수 없다. 자동화가 사용하는 유일한 merge 경로를 비-LLM merge
broker로 만들고, broker가 현재 PR head SHA에 대해 다음을 직접 조회한다.

- 지정 GitHub Actions workflow/check 성공
- `agent-review/<policy-version>` Check Run 성공
- review 결과의 head SHA가 현재 SHA와 동일
- Kaneo task의 acceptance/risk 상태
- 필요한 human approval ledger
- publisher/developer와 reviewer trust domain 분리

조건을 만족한 경우에만 broker가 merge API를 호출한다. agent와 일반 worker에는 merge
credential을 주지 않는다.

잔여 위험: repository write/admin 사용자는 GitHub UI나 별도 token으로 broker를 우회할
수 있다. 가능한 계정은 read/triage로 낮추고, 실제 write/admin은 소수 운영자와 broker
App에만 남긴다. orchestrator는 broker 밖에서 발생한 default-branch push/merge를
webhook과 polling으로 탐지해 Buzz/Kaneo에 경보를 남긴다.

### 3. 릴리스: GitHub environment 대신 외부 deploy broker

Free private에서는 production secret를 GitHub Actions에 두지 않는다. Actions는
unprivileged build/test와 immutable artifact 생성까지만 담당한다.

```text
GitHub Actions --digest/SBOM/signature--> Artifact registry
Human --digest-bound approval--> Orchestrator approval ledger
Deploy broker --short-lived target credential--> Production
```

- approval은 allowlist된 Buzz Nostr key 또는 검증된 Kaneo human actor가 특정 artifact
  digest와 environment에 대해 서명/확정한다.
- production credential은 GitHub repository/Actions secret가 아니라 별도 deploy
  broker/secret store에 둔다.
- deploy broker는 approval expiry, actor, digest, target environment, health policy를
  검사한다.
- build job과 deploy job은 runner, identity, secret store를 공유하지 않는다.
- 고위험 환경은 2인 승인 정책을 선택할 수 있다.

### 4. Actions quota 대응

- 빠른 unit/lint는 GitHub-hosted runner quota를 사용한다.
- 무거운 integration/build는 job 하나만 실행하는 ephemeral self-hosted runner로
  이동할 수 있다.
- self-hosted runner는 agent worker와 분리하고 untrusted job 종료 후 폐기한다.
- 대용량 artifact는 Actions storage 대신 GHCR/GHES Packages 또는 Zot/MinIO로 옮긴다.
- queue 전에 남은 hosted minutes/budget을 확인하고 quota가 없으면 compatible runner로
  route하거나 Kaneo에 `Blocked: CI capacity`를 표시한다.

## Public Free mode

public repository라면 protected branch, repository ruleset, required check/review,
CODEOWNERS, environment protection을 사용할 수 있다. 원래 설계를 거의 그대로 적용한다.
다만 organization-wide ruleset은 Team/Enterprise 기능이므로 repository별 ruleset JSON을
소스 관리하고 drift detector가 각 repository를 확인한다.

외부 publisher/merge/deploy broker는 public mode에서도 방어 심층화와 GitHub/GHES 간
이식성을 위해 유지할 수 있다. capability가 있으면 GitHub native gate와 broker가 모두
통과해야 한다.

## 불변식

plan이나 repository visibility와 관계없이 다음은 유지한다.

1. LLM agent는 GitHub App private key, merge credential, production credential을 받지
   않는다.
2. reviewer 결과는 현재 head SHA에 묶인다.
3. build artifact와 approval은 immutable digest로 연결된다.
4. 동일 actor/trust domain이 작성과 독립 리뷰를 동시에 완료하지 않는다.
5. webhook 유실과 재전송은 polling reconciliation과 idempotency로 보정한다.
6. native gate가 없으면 자동으로 보호 수준이 같다고 주장하지 않고 `external-guarded`
   mode와 잔여 위험을 UI/log에 표시한다.

## Phase 0 확인 항목

- repository visibility와 organization plan
- protected branch/ruleset/environment API 실제 생성 가능 여부
- GitHub-hosted Actions quota와 결제 수단 부재 시 차단 동작
- App별 permission 축소와 installation token 동작
- publisher patch validation 및 default branch 직접 push 거부
- merge broker 밖의 merge/default push 탐지 경보
- external approval ledger와 deploy broker의 digest binding
