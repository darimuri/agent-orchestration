# ADR-0001: GitHub/GHES를 기본 Forge로 사용

- 상태: Accepted
- 결정일: 2026-09-13

## 맥락

초기 설계는 저장소에 이미 배포된 Gitea와 act-runner를 기본 코드/CI 원장으로
가정했다. 실제 운영 대상은 GitHub.com과 GitHub Enterprise Server(GHES)가 중심이다.
두 환경을 같은 integration contract로 지원하면서도 인증, webhook, ruleset, runner의
차이는 명시적으로 처리해야 한다.

## 결정

1. 기본 forge adapter는 `github`이며 GitHub.com과 GHES를 host profile로 구분한다.
2. 서버 간 인증은 장기 PAT가 아니라 trust domain별 GitHub App을 사용한다.
3. worker에는 App private key를 주지 않고 repository/permission을 축소한 1시간짜리
   installation access token만 job 단위로 전달한다.
4. 개발 자동화, 자동 리뷰, control-plane App을 분리한다.
5. 자동 리뷰는 사람을 흉내 낸 approval보다 SHA-bound Check Run으로 게시한다.
6. merge는 ruleset/branch protection과 required checks가 강제한다.
7. 기능이 있으면 production 배포는 GitHub Actions environment의 required reviewer와
   prevent self-review를 기본 human gate로 사용한다. Free private는 ADR-0002의 외부
   deploy broker를 사용한다.
8. GitHub.com에서는 untrusted PR에 GitHub-hosted runner를 우선한다. GHES에서는
   self-hosted runner가 필요하므로 ephemeral JIT runner 또는 ARC를 사용한다.
9. Gitea는 제거하지 않지만 초기 구현 범위 밖의 선택적 `forge` adapter로 낮춘다.
10. App은 agent instance별이 아니라 GitHub에서 분리해야 하는 trust domain별로 만든다.
    개인 PoC는 `agent-developer`와 `agent-reviewer` 두 App으로 시작하고, control,
    publisher, merge/deploy broker는 해당 책임을 구현할 때 추가한다.
11. Developer App이 branch와 PR을 모두 생성해 App bot이 PR author가 되게 한다. 사람
    owner는 agent 작성 PR의 최종 승인과 merge를 담당한다.
12. Reviewer App은 자동 approval을 사람 승인처럼 사용하지 않고 현재 head SHA의 Check
    Run과 인라인 finding을 게시한다.
13. GitHub.com App 등록명은 `darimuri-agent-developer-a`, `darimuri-agent-reviewer-a`,
    `darimuri-agent-control-a`, `darimuri-forge-publisher-a`, `darimuri-merge-broker-a`,
    `darimuri-deploy-broker-a`로 고정한다. `kaneo-darimuri`는 Kaneo integration 전용으로
    유지한다.

`pull_requests: write`는 PR 생성, review, merge 관련 작업을 함께 포함하므로 App
permission만으로 개발자 역할을 완전히 세분화할 수 없다. developer App이 PR author와
last pusher가 되게 하고, review/merge tool 미노출, bypass 금지, required reviewer Check,
last-push approval, CODEOWNERS/human review로 보완한다.

초기 permission과 actor 흐름, App 추가 시점은
[GitHub App 역할 경계와 초기 구성](../GITHUB-APP-BOUNDARIES.md)을 따른다.

## 이유

- GitHub App은 특정 repository와 세분화된 권한으로 설치할 수 있고 installation
  access token은 1시간 후 만료된다.
- GitHub webhook은 `X-GitHub-Delivery` GUID와 `X-Hub-Signature-256`을 제공해 검증과
  중복 제거가 명확하다.
- Checks API는 특정 head SHA에 자동 리뷰/QA 결과를 귀속할 수 있다.
- ruleset과 Actions environment는 persona prompt 밖에서 merge/release 정책을 실제로
  강제한다.
- GitHub.com과 GHES가 공통 API 모델을 공유하므로 host별 capability 차이를 adapter
  내부에서 격리할 수 있다.

## 결과

- 오케스트레이터는 GitHub App credential broker와 webhook receiver를 포함한다.
- `github_host`마다 web/API URL, App ID/installation ID, 지원 기능을 저장한다.
- GHES version과 license에 따라 ruleset, environment, ARC, OIDC 기능을 capability로
  탐지하고 지원하지 않는 기능은 branch protection이나 별도 human gate로 대체한다.
- GitHub App은 UI상 하나의 actor로 보이므로 agent instance의 세부 귀속은 branch,
  commit trailer, Check Run `external_id`, PR comment와 내부 audit correlation ID로 보완한다.
- 별도 사람 reviewer 계정은 사람이 직접 작성한 PR에 독립 human approval을 요구할 때만
  필요하다. Agent 작성 PR은 Developer App bot과 사람 owner가 서로 다른 actor가 된다.

## 공식 근거

- [GitHub App 개요](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-creating-github-apps)
- [GitHub App installation 인증](https://docs.github.com/en/enterprise-server@3.22/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
- [Webhook 검증](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [GitHub webhook delivery headers](https://docs.github.com/en/webhooks/webhook-events-and-payloads)
- [GitHub ruleset 규칙](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GHES deployment environments](https://docs.github.com/en/enterprise-server@3.22/actions/reference/workflows-and-actions/deployments-and-environments)
- [Self-hosted runner 보안 및 autoscaling](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
