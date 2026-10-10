# Technical Defense — Linux Protected Directory Guard

## 한국어

정답은 포함하지 않습니다. 각 답변에서 policy 설명, 관찰된 이벤트, kernel enforcement 결과를 구분하세요.

### 코드 읽기와 흐름

1. policy 파일이 `open(O_NOFOLLOW)`부터 `parse_policy`를 거쳐 `policy explain` JSON이 되기까지 추적하세요.
2. `read_policy_line`의 line/total byte 경계는 어떤 자원 위험을 막고, 어떤 parser 속성은 fuzz test가 필요한가요?
3. `safe_scope`가 `realpath` 이후 broad root를 다시 확인하는 이유와 남는 rename race를 설명하세요.
4. `path_within`이 경계 구분을 하지 않으면 어떤 sibling path 오판이 생기나요?
5. parser의 root/rule state machine은 어떤 YAML 문법을 거부하며 그 이유는 무엇인가요?
6. 겹치는 rule 검증과 `evaluate`의 most-specific 선택을 함께 설명하세요. 어떤 충돌이 reject되나요?
7. `policy explain` JSON에서 `decision:"deny"`와 `enforced:false`가 동시에 존재하는 이유를 말하세요.

### Linux API와 디버깅

8. fanotify group 생성 성공과 mount mark 성공이 서로 다른 검증 단계인 이유는 무엇인가요?
9. `FAN_CLASS_NOTIF`와 `FAN_OPEN_PERM`의 호출/응답 의미는 어떻게 다른가요?
10. 하나의 `read` 결과 안에서 `event_len`, `metadata_len`, 남은 buffer를 검증하지 않으면 어떤 버그가 가능하나요?
11. `FAN_Q_OVERFLOW`를 받은 뒤 관찰 로그를 complete라고 표시하면 왜 부정확한가요?
12. event FD, journal FD, fanotify group FD는 각각 누가 소유하며 각 실패 경로에서 언제 닫아야 하나요?
13. event path는 보호 root 밖이지만 같은 mount 안에 있습니다. 이 구현은 어떻게 처리해야 하며 어떤 한계가 남나요?
14. `doctor`가 fanotify group 생성 성공을 보여도 audit mount mark가 실패할 수 있는 이유는 무엇인가요?
15. 부분 write, `EINTR`, `ENOSPC`, `poll` 오류, `/proc/self/fd` 실패는 종료 코드와 coverage에 어떤 영향을 줘야 하나요?
16. 현재 root 권한 없이 CI에서 검증할 수 있는 것과 disposable VM에 남겨야 할 것은 무엇인가요?

### 보안과 identity

17. mount mark의 더 넓은 관찰 범위를 path filter로 줄여도 해결되지 않는 symlink/rename/bind-mount/namespace 문제가 무엇인가요?
18. `readlink` path, `st_dev` major/minor, inode가 서로 다른 정보를 나타내는 이유는 무엇인가요?
19. fanotify PID를 observed로 분류하고 verified actor라고 부르지 않는 이유는 무엇인가요? 어떤 정보(예: UID, process start time)가 더 필요한가요?
20. audit event의 `unknown`과 policy explain의 `allow/deny`를 하나의 신뢰도 수준으로 표현하면 어떤 오해가 생기나요?
21. journal의 `O_NOFOLLOW`, owner 검사, `0600` mode가 막는 위협과 막지 못하는 위협은 각각 무엇인가요?
22. `/sys/kernel/security/lsm`에서 `bpf`를 읽는 것으로 입증되지 않는 것은 무엇이며 BPF hook preflight에 어떤 추가 증거가 필요한가요?

### 설계 선택과 기술 방어

23. fanotify permission event, BPF LSM, Landlock, audit-only의 범위와 실패 모드를 비교하세요.
24. write, rename, unlink, mmap에 enforcement를 주장하기 전에 어떤 hook별 positive/negative operation matrix가 필요하나요?
25. policy reload를 추가한다면 parse 실패, dry-run 실패, 부분 apply 시 마지막 유효 revision을 어떻게 보존하겠습니까?
26. daemon 종료와 queue overflow에서 fail-open/closed/unsupported 중 어떤 동작을 mode별로 선택하겠습니까? SRS의 안전 경계로 근거를 설명하세요.
27. 이 저장소의 다음 불확실성을 가장 줄일 테스트 하나를 선택하고 근거를 제시하세요: parser fuzz, privileged mount mark, namespace isolation, queue-overflow injection, 또는 성능 측정.

## English

Questions only; no answer key is included. Separate policy explanation, observed event, and kernel enforcement in each defense.

### Code reading and flow

1. Trace a policy file from `open(O_NOFOLLOW)` through `parse_policy` to the `policy explain` JSON.
2. Which resource risks do the line/total-byte limits in `read_policy_line` prevent, and which parser properties still need fuzzing?
3. Why does `safe_scope` recheck a broad root after `realpath`, and which rename race remains?
4. What sibling-path mistake would occur if `path_within` did not check a component boundary?
5. Which YAML syntax does the root/rule parser state machine reject, and why?
6. Explain overlap validation and `evaluate`'s most-specific selection together. Which conflicts are rejected?
7. Why can `policy explain` contain `decision:"deny"` and `enforced:false` at the same time?

### Linux APIs and debugging

8. Why are fanotify group creation and mount marking separate support/permission gates?
9. How do the request/response semantics of `FAN_CLASS_NOTIF` differ from `FAN_OPEN_PERM`?
10. What bugs can occur if a packed read buffer is not checked against `event_len`, `metadata_len`, and remaining bytes?
11. Why is it inaccurate to call the audit complete after `FAN_Q_OVERFLOW`?
12. Who owns the event FD, journal FD, and fanotify group FD, and when must each close on failure paths?
13. An event path is outside the protected root but on the same mount. What should this implementation do, and which limitations remain?
14. Why can `doctor` report fanotify group creation while `audit` still fails to mark the mount?
15. How should partial writes, `EINTR`, `ENOSPC`, `poll` errors, and `/proc/self/fd` failures affect exit status and coverage?
16. Which checks can run in unprivileged CI, and which belong in a disposable VM?

### Security and identity

17. Which symlink, rename, bind-mount, and namespace issues remain after filtering a broader mount mark by path?
18. Why do the `readlink` path, `st_dev` major/minor, and inode represent different information?
19. Why is the fanotify PID only observed rather than a verified actor? What additional evidence such as UID or process start time would help?
20. What misunderstanding follows if audit `unknown` and policy-explain `allow/deny` are presented at one confidence level?
21. Which threats do the journal's `O_NOFOLLOW`, owner check, and `0600` mode mitigate, and which do they not?
22. What does reading `bpf` from `/sys/kernel/security/lsm` fail to prove, and what additional BPF hook preflight evidence is needed?

### Design tradeoffs and defense

23. Compare fanotify permission events, BPF LSM, Landlock, and audit-only in scope and failure modes.
24. Which hook-specific positive/negative operation matrix is required before claiming enforcement for write, rename, unlink, or mmap?
25. If policy reload were added, how would parse failure, dry-run failure, and partial apply preserve the last valid revision?
26. For daemon exit and queue overflow, which of fail-open, fail-closed, or unsupported would you choose per mode? Defend it against the SRS safety boundary.
27. Choose the single next test that would reduce the most uncertainty: parser fuzzing, privileged mount marking, namespace isolation, queue-overflow injection, or performance measurement.

Do not infer owner mastery from CTest success. Evidence must come from an independently attempted exercise and a reasoned technical defense.
