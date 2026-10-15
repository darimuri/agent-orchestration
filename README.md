# Agent Orchestration

Buzz, Kaneo, GitHub/GHES를 중심으로 여러 PC에서 역할별 코딩 에이전트를 운영해
개발, 리뷰, 테스트, 릴리스를 자동화하기 위한 조사 및 설계 문서다.

이 저장소는 `darimuri/k8s-test`의 `agent-orchestration/`에서 분리한 런타임과
설계 문서를 포함한다. [이전 기록](MIGRATION.md)과
[런타임 사용법](agents/README.md)을 참고한다.

## 결론

구현 가능하다. 다만 Buzz와 Kaneo만 서로 직접 연결하는 구성으로는 중복 실행,
장애 복구, 작업 임대, 자기 승인 방지를 충분히 보장하기 어렵다. 다음처럼 책임을
분리한 작은 중앙 오케스트레이터와 PC별 pull worker가 필요하다.

- **Kaneo**: 우선순위, 담당자, 수락 조건, 진행 상태를 보관하는 작업 원장
- **Buzz**: 사람과 에이전트의 대화, 호출, 결과 보고, 감사 가능한 협업 이벤트
- **GitHub/GHES**: issue, 브랜치, 커밋, PR, 리뷰, 태그의 코드 원장
- **GitHub Actions**: 빌드와 테스트 결과 및 배포 environment gate의 원장
- **Orchestrator**: 이벤트 정규화, 정책 평가, 중복 제거, 작업 lease, 상태 조정
- **Agent worker**: 여러 PC에서 항상 실행되며 작업을 pull한 뒤 격리 컨테이너 실행
- **Provider subscription OAuth**: 초기 inference 인증 경로; host credential을 sandbox가 read-only로 공유
- **LiteLLM**: API 과금·중앙 budget·provider fallback이 필요할 때 도입하는 후속 선택지

Buzz가 협업과 에이전트 호출을 담당하고 Kaneo가 계획을 담당하되, 둘 중 어느
쪽도 코드나 테스트 결과의 최종 원장으로 취급하지 않는다.

GitHub Free private repository도 정식 지원 대상으로 본다. 이 경우 사용할 수 없는
branch/ruleset/environment gate를 비-LLM publisher, merge, deploy broker가 보완하며,
native GitHub 보호와 동일한 수준이라고 과장하지 않고 잔여 위험을 명시한다.

## 문서

- [RESEARCH.md](RESEARCH.md): 2026-09-12 조사 및 2026-09-13 GitHub/GHES 보완
- [ARCHITECTURE.md](ARCHITECTURE.md): 권장 구성, 이벤트 흐름, 역할, 인증, 격리와 실패 처리
- [PLAN.md](PLAN.md): 단계별 구현 계획, 산출물, 수락 조건, 중단 조건
- [GITHUB-FREE-ORG.md](GITHUB-FREE-ORG.md): 무료 Organization 기능표와 private repo fallback
- [GITHUB-APP-BOUNDARIES.md](GITHUB-APP-BOUNDARIES.md): Developer/Reviewer App과 사람 승인자의 초기 권한 경계
- [github-apps/README.md](github-apps/README.md): 역할별 GitHub App manifest와 대화형 생성 스크립트
- [BUZZ-AGENT-PROVISIONING.md](BUZZ-AGENT-PROVISIONING.md): persona별 Buzz identity 등록과 기동 절차
- [SUBSCRIPTION-OAUTH-SANDBOX.md](SUBSCRIPTION-OAUTH-SANDBOX.md): Claude/Codex 구독 OAuth와 host 공유 credential 설계
- [KANEO-MCP-SETUP.md](KANEO-MCP-SETUP.md): Kaneo MCP 설정, device 인증, 검증 결과와 보안 주의사항
- [KANEO-VS-GITHUB-PROJECTS.md](KANEO-VS-GITHUB-PROJECTS.md): Kaneo 유지와 GitHub Projects 작업 원장 통합안 비교
- [adr/0001-github-primary.md](adr/0001-github-primary.md): GitHub/GHES를 기본 forge로 선택한 결정
- [adr/0002-free-org-degraded-mode.md](adr/0002-free-org-degraded-mode.md): 무료 private repo에서도 동작하는 전략

## 설계 당시 범위

아래는 초기 설계 당시의 범위다. 현재 런타임과 호스트 준비 절차는
[agents/README.md](agents/README.md)를 따른다. 이 저장소 이전 자체로 다음 운영
리소스를 생성하거나 변경하지 않는다.

- 클러스터 리소스와 서비스 계정
- Kaneo 프로젝트, 사용자, API key, outgoing webhook
- Buzz 에이전트 keypair, persona pack, workflow
- GitHub App, repository ruleset/branch protection, Actions workflow/environment
- 각 PC의 worker와 rootless container 환경

## 우선 결정할 사항

구현 전에 [PLAN.md의 Phase 0](PLAN.md#phase-0--호환성-및-위험-스파이크)을 통과해야
한다. 특히 darimuri/k8s-test 저장소의 Buzz chart는 upstream chart `0.1.8` 기반이고 Kaneo 설치는
upstream `main`을 고정하지 않는다. 문서에서 확인한 최신 기능이 현재 클러스터에
그대로 존재한다고 가정하면 안 된다.
