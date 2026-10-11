# Portfolio review / 포트폴리오 검토 안내

## 문제와 제작 의도

정책 판단과 실제 차단의 경계를 코드와 로그에 표시하기. 이 저장소는 Linux 시스템 호출의 결과와 실패를 관측 가능한 계약으로 연결하는 교육용 구현입니다.

## 핵심 설계

제한된 정책 parser가 unknown field와 중복·충돌을 거부합니다. 정책 revision을 교체하기 전에 후보를 준비하고 실패 시 기존 상태를 유지합니다. 감사 이벤트의 PID 출처와 retrospective 판단을 표시하며 enforce는 unsupported로 명시적으로 실패합니다.

## 코드 검토 경로

1. [`src/dirguardctl.c`](../src/dirguardctl.c)의 CLI 진입점에서 자원 획득과 오류 반환을 찾습니다.
2. [코드 해설](CODE_WALKTHROUGH.md)에서 핵심 함수와 소유권을 따라갑니다.
3. [최신 검증 기록](VALIDATION_CHECKPOINT.md)과 [요구사항 추적표](REQUIREMENTS_TRACEABILITY.md)를 비교합니다.
4. [기술 질문](TECHNICAL_INTERVIEW.md)과 [정답 없는 실습](DEBUGGING_EXERCISES.md)으로 직접 설명·재현합니다.

검토 질문: FAN_CLOSE_WRITE의 deny 판단이 쓰기를 막았다는 뜻이 아닌 이유는? 새 정책 적용 실패 후 어떤 상태가 남는가? 경로 문자열만으로 namespace 경계를 보장할 수 있는가?

## English

**Purpose:** Make the boundary between policy decisions and actual mediation explicit.

A restricted policy parser rejects unknown fields, duplicates and conflicts. Reload prepares a candidate before swapping revisions and retains the previous state on failure. Audit records identify attribution sources and retrospective decisions; enforce returns an explicit unsupported result.

Start with the linked source entry point, follow `CODE_WALKTHROUGH.md`, and compare the dated checkpoint with requirement traceability. Review questions: Why does a deny decision after FAN_CLOSE_WRITE not prevent a write? What survives a failed reload? Can a path string establish a namespace boundary?

The five study documents cover subsystem purpose, data/control flow, Linux interfaces, memory/resource lifetime, concurrency, security assumptions, failures and alternatives. Three reproduction exercises remain unsolved. Repository checks and the owner's demonstrated competence are tracked separately; neither AI assistance nor automated test completion establishes personal mastery.
