# ADR-0002: GitHub Free private repository를 external-guarded mode로 지원

- 상태: Accepted
- 결정일: 2026-09-13

## 맥락

GitHub Free Organization의 private repository에는 protected branch, ruleset, required
review/status check, CODEOWNERS 강제, Actions environment가 제공되지 않는다. 그러나
무료 Organization도 주요 운영 대상으로 지원해야 한다.

## 결정

1. 요금제 이름이 아니라 실제 GitHub capability를 탐지한다.
2. native 보호 기능이 부족하면 `external-guarded` mode를 선택한다.
3. LLM developer는 target repository에 write하지 않고 patch bundle을 만든다.
4. 비-LLM publisher broker가 feature branch와 PR을 만든다.
5. 비-LLM merge broker가 현재 SHA의 Actions/reviewer check와 approval을 확인해 merge한다.
6. production secret는 GitHub에 두지 않고 외부 deploy broker가 digest-bound human
   approval 후 사용한다.
7. write/admin 사용자의 직접 우회는 완전히 막을 수 없는 잔여 위험으로 공개하고
   권한 최소화, 탐지, 경보로 완화한다.
8. 유료/native 기능이 있으면 같은 broker 검증에 GitHub gate를 추가해 방어를 강화한다.

## 결과

- 무료 private repository에서도 개발, CI, AI review, 병합, release 흐름을 자동화할 수
  있다.
- GitHub native branch/environment enforcement와 동일한 보안 보장은 주장하지 않는다.
- publisher, merge, deploy broker가 추가되어 control plane의 책임과 운영 비용이 늘어난다.
- plan/visibility 변경 시 code 변경 없이 capability mode를 전환할 수 있다.

## 상세 설계

[GitHub Free Organization 호환 전략](../GITHUB-FREE-ORG.md)을 따른다.
