# Kaneo와 GitHub Projects 비교

- 상태: 평가 및 권고안, 결정 전
- 작성일: 2026-09-20

## 목적

현재 아키텍처는 Kaneo를 작업 원장으로, GitHub/GHES를 issue·코드·PR·리뷰의
원장으로 사용한다. 그러나 대부분의 작업이 GitHub issue와 PR로 귀결된다면 Kaneo와
GitHub Projects가 비슷한 상태와 메타데이터를 중복해서 관리하게 된다.

이 문서는 Kaneo를 별도 작업 원장으로 유지할 때의 실익과 운영 비용을 정리하고,
GitHub Projects로 작업 관리를 통합하는 대안을 평가한다. 아직 기존 설계를 변경하는
최종 ADR은 아니며, Phase 0에서 운영 요구사항을 확인한 뒤 채택 여부를 결정한다.

## 요약

GitHub를 기본 forge로 확정하고 작업 대부분이 코드 변경이라면 GitHub
Issues/Projects를 작업 원장으로 사용하는 편이 단순하다. Kaneo의 주요 차별점은 기능
우위보다 자체 호스팅, forge 독립성, 여러 forge 및 비개발 업무를 하나의 보드에서
관리하는 데 있다.

현재 범위에서는 이 장점보다 다음 이중 원장 비용이 더 클 가능성이 높다.

- Kaneo task와 GitHub issue/PR 사이의 생성 및 링크 동기화
- 양쪽 상태가 다를 때 권위 있는 값을 선택하는 reconciliation
- webhook 재전송, 순서 역전과 부분 실패 처리
- 별도 PostgreSQL, 인증, 백업, 업그레이드와 장애 대응
- Kaneo MCP credential과 tool surface의 추가 보안 관리

따라서 기본 권고는 **GitHub Issues/Projects 통합안을 우선 검증하고, 아래의 Kaneo
유지 조건이 실제 요구사항일 때만 Kaneo를 유지하는 것**이다.

## 기능 및 운영 비교

| 관점 | GitHub Projects | Kaneo |
|---|---|---|
| 코드 작업 연결 | issue와 PR이 기본 객체이며 repository 상태와 직접 연결 | task와 issue/PR 사이에 integration 및 링크 필요 |
| 보기와 계획 | table, board, roadmap, custom field, iteration, chart 지원 | 단순한 project/board/task 중심 UI |
| 자동화 | built-in workflow, Actions, GraphQL/API 사용 | REST API, webhook, MCP 사용 |
| 에이전트 연동 | 공식 GitHub MCP가 issues, PR, projects toolset 제공 | 공식 Kaneo MCP가 task, project, label 등을 제공 |
| 자체 호스팅 | GitHub.com Projects는 SaaS 종속; GHES는 별도 제품 | 애플리케이션과 데이터를 직접 운영 가능 |
| 여러 forge | GitHub 객체에 최적화되고 GitHub 경계에 종속 | GitHub/Gitea 등과 독립된 공통 업무 원장으로 사용 가능 |
| 비개발 업무 | draft item으로 가능하지만 GitHub 중심 | 코드 저장소와 무관한 일반 업무에 자연스러움 |
| 운영 부담 | GitHub 사용 시 추가 서비스가 거의 없음 | 서비스, DB, 백업, 인증, 관측과 업그레이드 필요 |
| 장애 경계 | GitHub 장애가 코드와 업무 관리에 함께 영향 | forge와 업무 원장을 분리할 수 있음 |
| 데이터 주권 | GitHub 운영 및 요금제에 의존 | 데이터와 배포를 직접 통제 |

GitHub Projects는 단순 Kanban을 넘어 issue/PR 양방향 연결, 여러 view, custom field,
iteration, roadmap, chart와 automation을 제공한다. GitHub 공식 MCP도 Projects toolset을
제공하므로 MCP 접근성만으로 Kaneo를 선택할 근거는 약해졌다.

## Kaneo를 유지할 조건

다음 중 하나 이상이 실제 필수 요구사항이면 Kaneo를 독립 작업 원장으로 유지할 가치가
있다.

1. 업무 데이터의 자체 호스팅과 독립 백업이 필수다.
2. GitHub.com, GHES, Gitea 등 여러 forge의 작업을 하나의 workflow로 관리해야 한다.
3. 홈랩 운영, 인프라 요청, 문서나 행정 작업처럼 repository에 속하지 않는 업무가
   상당한 비중을 차지한다.
4. forge 계정 및 repository 권한과 분리된 업무 담당자·상태·감사 모델이 필요하다.
5. GitHub 장애나 장기 이전 중에도 업무 원장이 독립적으로 동작해야 한다.
6. GitHub 요금제나 Projects 정책에 종속되지 않는 workflow가 요구된다.

단순히 Kanban UI가 필요하거나 agent가 MCP로 task를 갱신해야 한다는 이유만으로는
Kaneo를 추가하기에 충분하지 않다. GitHub Projects와 공식 GitHub MCP도 해당 기능을
제공한다.

## GitHub Projects 통합안

Kaneo를 제거하면 책임 경계는 다음처럼 단순화된다.

```text
GitHub Issues / Projects
  작업, 우선순위, 수락 조건, 담당자, risk, requested role, 진행 상태

GitHub PR / Actions
  브랜치, 코드 변경, 인라인 리뷰, CI 결과, 승인과 병합

Buzz
  사람과 agent의 대화, 호출, 진행 알림, 결과 및 blocker 요약

Orchestrator
  GitHub webhook 수신, 정책 평가, dedupe, lease, worker dispatch, reconciliation
```

초기 field와 label 예시는 다음과 같다.

| 항목 | 표현 |
|---|---|
| 실행 가능 상태 | Project `Status=Ready` |
| 자동화 승인 | `agent:ready` label 또는 별도 boolean field |
| 우선순위 | `Priority` single-select field |
| 위험도 | `Risk` single-select field |
| 요청 역할 | `Requested role` single-select field |
| 수락 조건 | GitHub issue body의 체크리스트 |
| 구현 결과 | `Closes #<issue>`를 포함한 PR |
| 검증 결과 | 현재 head SHA의 Actions와 reviewer Check Run |

오케스트레이터는 `repository-id:issue-number:role:input-revision` 같은 deterministic key로
job을 생성한다. Project column 이동이나 Buzz 메시지만으로 완료를 선언하지 않고 PR,
Actions와 merge webhook을 다시 조회해 issue 및 Project 상태를 갱신한다.

## 통합안의 장점

- task, issue, PR 사이의 reciprocal link 및 중복 생성 로직이 사라진다.
- 코드 변경과 수락 조건, PR, CI evidence가 한 권한 및 API 모델 안에 있다.
- GitHub App, webhook, Actions와 MCP만 운영하면 되어 credential 종류가 줄어든다.
- Project automation으로 PR merge와 issue close에 따른 상태 변경을 처리할 수 있다.
- 사람이 GitHub에서 보는 상태와 orchestrator가 판단하는 상태가 동일해진다.

## 통합안의 단점과 잔여 위험

- GitHub 장애가 코드와 작업 관리 양쪽에 동시에 영향을 준다.
- GitHub.com을 사용하면 업무 데이터와 workflow가 SaaS에 종속된다.
- GitHub Free private repository의 보호 기능 제약은 ADR-0002와 같이 별도로 보완해야
  한다.
- 여러 forge를 지원할 때 GitHub Projects를 공통 추상화로 사용할 수 없으므로 forge별
  adapter 또는 별도 업무 원장이 다시 필요해질 수 있다.
- 코드와 무관한 업무까지 GitHub issue로 표현하면 사용자 경험이 부자연스러울 수 있다.

## 전환 시 제거하거나 변경할 범위

이 권고를 채택하면 다음 설계가 함께 변경되어야 한다.

- `ARCHITECTURE.md`의 Kaneo work-system-of-record 역할을 GitHub Issues/Projects로 이동
- Kaneo webhook ingest, polling reconciliation과 task projection 제거
- dispatcher가 Kaneo task 대신 GitHub issue 및 Project field를 생성·갱신
- `KANEO-MCP-SETUP.md`와 agent container의 Kaneo MCP를 필수 경로에서 제외
- prompt의 Kaneo 상태 확인 및 업데이트 절차를 GitHub issue/Project 절차로 교체
- `PLAN.md`의 Kaneo identity, credential, webhook 관련 작업 축소

기존 Kaneo 데이터를 실제로 운영하기 시작한 뒤 전환한다면 task별 GitHub issue를 만들고
원본 Kaneo URL과 상태를 migration metadata로 남긴다. 아직 설계 단계이므로 지금 결정하면
데이터 migration 없이 문서와 bootstrap configuration만 정리할 수 있다.

## 결정 기준

Phase 0에서 다음 질문에 답한 뒤 별도 ADR로 최종 결정한다.

1. 운영 업무 중 GitHub repository와 연결되지 않는 task의 예상 비율은 얼마인가?
2. 초기 운영에서 GitHub 외의 forge를 실제로 동시에 지원해야 하는가?
3. 업무 데이터 자체 호스팅이 필수 요구사항인가, 선호사항인가?
4. GitHub Projects와 공식 MCP가 필요한 task CRUD 및 field 갱신을 모두 제공하는가?
5. Kaneo를 유지해 얻는 장애 격리가 추가 운영 및 reconciliation 비용보다 큰가?

1~3이 모두 부정적이고 4가 긍정적이면 Kaneo를 제거하고 GitHub Projects를 작업 원장으로
채택한다. 반대로 자체 호스팅, multi-forge 또는 비개발 업무가 핵심이면 Kaneo를 유지한다.

## 공식 참고 자료

- [GitHub Projects 개요](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects)
- [GitHub Projects 문서](https://docs.github.com/en/issues/planning-and-tracking-with-projects)
- [GitHub MCP Server](https://github.com/github/github-mcp-server)
- [Kaneo repository와 공식 MCP 안내](https://github.com/usekaneo/kaneo)
- [Kaneo 환경 및 GitHub integration 설정](https://github.com/usekaneo/kaneo/blob/main/ENVIRONMENT_SETUP.md)
