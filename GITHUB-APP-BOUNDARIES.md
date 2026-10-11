# GitHub App 역할 경계와 초기 구성

- 상태: Accepted for bootstrap
- 작성일: 2026-09-20

## 목적

GitHub는 PR 작성자가 자신의 PR을 승인하지 못한다. Agent가 사람 계정의 token으로
branch와 PR을 만들면 그 사람은 동일 actor로 간주되어 최종 승인자가 될 수 없다.
반대로 모든 자동화를 하나의 GitHub App으로 실행하면 Developer와 Reviewer도 같은
`<app>[bot]` actor로 기록되어 역할 분리가 사라진다.

초기 구성은 agent instance마다 App을 만드는 대신, GitHub에서 강제해야 하는 trust
domain마다 App을 하나씩 둔다. 여러 instance는 같은 역할 App을 공유할 수 있으며
instance 수준의 감사 정보는 branch, commit trailer, Check Run `external_id`와 내부
job ID로 보완한다.

## 결정

개인 PoC의 최소 구성은 세 GitHub App과 한 사람 계정이다.

```text
darimuri-agent-control-a[bot]
  job-scoped Issue 관리

darimuri-agent-developer-a[bot]
  branch push + PR 생성
           |
           v
darimuri-agent-reviewer-a[bot]
  inline finding + SHA-bound Check Run
           |
           v
human owner
  최종 Approve + merge
```

중요한 불변식은 `agent-developer` installation token으로 PR까지 생성하는 것이다. 사람
계정으로 PR을 생성하면 그 사람이 PR author가 되어 자신의 변경을 승인할 수 없다.
App이 작성한 PR은 App bot과 사람 reviewer가 서로 다른 actor이므로 같은 사람이 App의
owner/operator여도 GitHub의 self-approval 제한에 걸리지 않는다.

자동 Reviewer는 사람 approval을 흉내 내지 않는다. 인라인 finding은 PR review comment로
게시하고 통과 여부는 현재 head SHA에 묶인 `agent-review/<policy-version>` Check Run으로
표현한다. 사람 계정만 최종 `APPROVE`를 게시한다.

### GitHub.com 등록 이름

다음 이름과 slug를 실제 GitHub.com App 등록 계약으로 사용한다. 이름은 2026-09-25에
GitHub API에서 미등록 상태를 확인했으며, 생성 직전에 충돌 여부를 다시 검사한다.

| 논리 역할 | GitHub.com App 이름/slug | GitHub actor | 생성 시점 |
|---|---|---|---|
| `agent-developer` | `darimuri-agent-developer-a` | `darimuri-agent-developer-a[bot]` | bootstrap |
| `agent-reviewer` | `darimuri-agent-reviewer-a` | `darimuri-agent-reviewer-a[bot]` | bootstrap |
| `agent-control` | `darimuri-agent-control-a` | `darimuri-agent-control-a[bot]` | bootstrap |
| `forge-publisher` | `darimuri-forge-publisher-a` | `darimuri-forge-publisher-a[bot]` | external-guarded publish 구현 시 |
| `merge-broker` | `darimuri-merge-broker-a` | `darimuri-merge-broker-a[bot]` | 자동 merge broker 구현 시 |
| `deploy-broker` | `darimuri-deploy-broker-a` | `darimuri-deploy-broker-a[bot]` | production 배포 구현 시 |

`kaneo-darimuri`는 Kaneo repository integration 전용 App이며 위 역할 App과 credential,
installation 및 audit actor를 공유하지 않는다. GitHub Enterprise Server는 host마다 App을
별도로 등록하고 `github_host` profile에서 논리 역할과 실제 slug를 매핑한다.

App manifest와 단계별 생성 도구는 [github-apps/README.md](github-apps/README.md)를
따른다.

## 초기 App과 권한

실제 permission 이름과 지원 여부는 GitHub.com/GHES capability probe에서 확정한다.
아래 표는 허용 상한이며 job token은 대상 repository와 필요한 permission으로 더 줄인다.

| 논리 App | 초기 permission | 금지 permission/행위 | GitHub.com actor |
|---|---|---|---|
| `agent-control` | metadata/contents read, issues write | contents write, checks write, administration, source/merge/deploy tool | `darimuri-agent-control-a[bot]` |
| `agent-developer` | metadata read, contents/issues/pull requests write | checks write, administration, ruleset bypass, review/merge tool | `darimuri-agent-developer-a[bot]` |
| `agent-reviewer` | metadata/contents/actions read, checks/issues/pull requests write | contents write, administration, branch push, merge/deploy tool | `darimuri-agent-reviewer-a[bot]` |

`agent-reviewer`의 `pull requests: write`는 인라인 review comment를 게시하기 위해
필요하다. 이 permission의 API 범위가 역할보다 넓을 수 있으므로 agent tool surface에는
comment/review 작성만 노출하고 merge endpoint는 노출하지 않는다. Reviewer token은
source push에 사용할 수 없도록 `contents: read`를 유지한다.

`agent-developer` 역시 `pull requests: write`를 받지만 review와 merge 명령은 tool
surface에서 제거한다. App은 default branch/ruleset bypass actor에 포함하지 않고,
feature branch prefix와 repository를 credential broker가 확인한다.

## PR 흐름

1. Orchestrator가 execution에 대상 repository, base SHA와 역할을 고정한다.
2. Credential broker가 해당 repository에 한정한 `agent-developer` installation token을
   발급한다.
3. Developer가 `agent/<task-number>-<slug>` branch를 push하고 같은 token으로 PR을
   생성한다. PR author는 사람 계정이 아니라 `darimuri-agent-developer-a[bot]`이어야 한다.
4. CI가 현재 head SHA를 검증한다.
5. 별도 execution과 credential로 Reviewer가 diff와 CI evidence를 읽고 인라인 finding과
   `agent-review/<policy-version>` Check Run을 현재 head SHA에 게시한다.
6. 새 commit이 push되면 이전 review 결과를 merge 근거로 사용하지 않고 Reviewer를 다시
   실행한다.
7. required CI와 agent review가 성공한 뒤 사람 owner가 GitHub에서 최종 승인하고
   merge한다.

사람이 직접 작성한 PR은 같은 사람 계정으로 승인할 수 없다. 독립된 사람 승인이 정책상
필수라면 다른 실제 사용자 reviewer가 필요하다. 별도 machine user/PAT를 사람 승인처럼
사용하지 않는다.

`issues: write`는 세 역할이 각자의 GitHub actor로 이슈와 댓글을 관리하기 위해 사용한다.
Gateway는 이를 그대로 노출하지 않고 활성 job의 agent ID, role, repository를 확인한 뒤
Issue 전용 MCP 도구만 제공한다. Issue와 댓글 삭제는 제공하지 않는다.

## 후속 App을 추가하는 시점

초기부터 모든 App을 만들지 않는다. 책임과 credential이 실제로 필요할 때 분리한다.

| App | 추가 조건 | 책임 |
|---|---|---|
| `forge-publisher` | ADR-0002의 `external-guarded` patch publish 구현 | 검증된 patch만 feature branch/PR로 게시 |
| `merge-broker` | native merge gate가 부족하고 자동 merge가 필요 | 최신 SHA의 CI/review/human approval 재조회 후 merge |
| `deploy-broker` | production 배포 자동화 시작 | 승인된 immutable artifact만 지정 environment에 배포 |

`agent-control`은 Dispatcher의 Issue actor로 bootstrap한다. Projects와 webhook ingest는
별도 범위이며, publisher/merge/deploy broker는 GitHub Free private 등 native gate가
부족한 mode에서만 도입한다.

## App을 나누는 기준

- Agent instance마다 App을 만들지 않는다.
- 같은 역할의 여러 Developer instance는 `agent-developer` App을 공유할 수 있다.
- 작성과 검토처럼 GitHub actor가 달라야 하는 역할은 App을 분리한다.
- App private key는 broker만 보관하며 worker나 LLM process에 전달하지 않는다.
- Installation token은 job 시작 시 repository와 permission을 축소해 발급한다.
- 한 App의 여러 installation token은 GitHub에서 같은 App actor로 보이므로 token을
  여러 개 발급하는 것만으로 역할 분리가 되지 않는다.

## Branch protection과 Check Run

native protection을 사용할 수 있으면 다음 정책을 적용한다.

- required `agent-review/<policy-version>` Check Run의 source를 `agent-reviewer` App으로
  고정한다.
- required CI와 review thread resolution을 활성화한다.
- 최근 reviewable push는 last pusher가 아닌 actor의 승인을 요구한다.
- 고위험 경로는 CODEOWNERS 또는 ruleset의 human reviewer를 요구한다.
- Developer와 Reviewer App을 bypass list에 넣지 않는다.

Automated Check Run은 사람 approval을 대체하지 않는다. 개인 PoC에서 사람 approval을
필수 gate로 강제할 수 없는 요금제라면 operator가 수동으로 승인·merge하고, 자동 merge가
필요해질 때 ADR-0002의 external merge broker를 구현한다.

## Bootstrap 확인 목록

- [ ] 세 App을 `darimuri` Organization의 All repositories 범위로 설치한다.
- [ ] 세 App 모두 Issue 조회·생성·수정·댓글·닫기·재열기가 성공하고 actor가 구분된다.
- [ ] Developer App으로 branch push와 PR 생성은 성공한다.
- [ ] Developer App의 default branch push와 Check Run 생성은 거부된다.
- [ ] Reviewer App의 source push는 거부되고 review comment와 Check Run은 성공한다.
- [ ] PR author가 `darimuri-agent-developer-a[bot]`으로 표시된다.
- [ ] 사람 owner가 해당 PR을 승인할 수 있다.
- [ ] 같은 head SHA의 required CI와 reviewer Check만 merge 근거로 인정된다.
- [ ] App private key가 agent container, workspace, log에 나타나지 않는다.

## 공식 참고 자료

- [GitHub App 설치 인증](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
- [Pull request review API](https://docs.github.com/en/rest/pulls/reviews)
- [Checks API](https://docs.github.com/en/rest/guides/using-the-rest-api-to-interact-with-checks)
- [Protected branch와 required review](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Ruleset에서 사용할 수 있는 규칙](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
