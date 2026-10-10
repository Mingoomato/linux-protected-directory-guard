# Debugging and Independent Reproduction Exercises

## 한국어

아래 세 문제는 미완료 연습입니다. 완성 패치나 정답 코드는 제공하지 않습니다. 실제 enforce를 켜지 말고 임시 디렉터리 또는 테스트 double만 사용하세요. privileged fanotify 실험은 폐기 가능한 VM에서만 해야 합니다.

### 연습 1 — policy parser property/fuzz 검사

**목표:** 작은 policy grammar의 경계와 거부 조건을 독립적으로 재현합니다.

**시작 지점:** `parse_policy`, `read_policy_line`, `tests/policy_validation.py`, `MAX_LINE`, `MAX_POLICY_BYTES`.

정상 policy에서 필드 순서/공백/주석을 변형하고, 중복 필드·잘못된 들여쓰기·비정상 종료 줄·exact limit 및 1 byte 초과·누적 크기 초과·out-of-root scope를 만드는 property/fuzz test harness를 작성하세요. 실패가 bounded input 안에서 결정적으로 반환되는지 확인하고 parser가 지원하는 YAML subset의 한계를 문서화하세요.

**제약:** unrestricted YAML parser로 교체하지 말고, attacker 크기의 line을 무제한 할당하지 마세요. Fuzzing은 사용자 공간 parser만 대상으로 합니다.

**합격 기준:** seed가 고정된 테스트를 반복할 수 있고, crash/hang 없이 accepted/rejected 결과를 재현하며, 경계 상한을 넘어서는 입력을 거부합니다.

### 연습 2 — fanotify record 및 FD 수명 검증

**목표:** event buffer parser와 descriptor 정리를 실패 경로까지 검증합니다.

**시작 지점:** `src/fanotify_records.h`, `cmd_audit`, `tests/fanotify_metadata_test.c`, `fanotify(7)`.

test seam 또는 작은 fake event source를 추가해 정상 record, `event_len` overrun, `metadata_len` mismatch, queue overflow, FAN_NOFD, root 밖 path, event-FD 경로 오류, short write, `EINTR` 및 저장 실패를 주입하세요. 각 FD가 정확히 한 번 닫히고, gap/error가 0 종료나 healthy coverage로 표시되지 않는지 검증하세요.

**제약:** permission event나 allow/deny 응답을 추가하지 마세요. VM 외부에서 mount mark를 시도하지 마세요.

**합격 기준:** 각 수신 event FD의 소유권 전이표와 테스트 증거가 있고, 오류 응답이 `degraded`/`gap` 의미를 보존합니다.

### 연습 3 — dirfd 기준 경로 identity 실험 설계

**목표:** pathname 정규화와 kernel object identity가 달라지는 상황을 재현합니다.

**시작 지점:** `safe_scope`, `path_within`, event FD의 `readlink`/`fstat`, SRS의 symlink/hardlink/bind mount 및 namespace 항목.

임시 트리에서 rename race, symlink alias, hardlink, bind mount, 두 개 mount namespace 케이스를 구성하고 path 문자열, `st_dev`, inode가 어떻게 달라지는지 기록하세요. 이후 후보 설계로 root directory FD + `openat2` resolution flag를 비교하되 production policy enforcement에 연결하지 마세요.

**제약:** 실제 system root를 수정하지 말고, 차단/deny를 주장하지 마세요. bind mount와 namespace 테스트는 disposable VM에서만 실행하세요.

**합격 기준:** 각 케이스에서 문자열 비교가 보장하지 못하는 것을 설명하고, 테스트로 재현 가능한 coverage gap을 작성합니다.

### 소유자 시도 기록

학습자가 직접 수행한 연습, 코드 리뷰 또는 기술 방어 답변은 아직 관찰되지 않았습니다. 소유자 재현 상태는 **시도 증거 없음**, 숙련도는 **평가되지 않음**입니다. CTest 통과는 개인 숙련 증거가 아닙니다.

## English

These three exercises are intentionally unsolved. No complete patch or answer code is included. Use temporary directories and test doubles; never enable enforcement. Run privileged fanotify experiments only in a disposable VM.

### Exercise 1 — Policy parser property/fuzz testing

Build a deterministic property or fuzz harness around `parse_policy`, `read_policy_line`, and the existing validation tests. Mutate valid policies and generate duplicate fields, bad indentation, missing final newline, exact/over-limit lines, total-size overflow, and out-of-root scopes. Confirm bounded deterministic rejection and document the supported YAML subset.

Do not replace the parser with unrestricted YAML or allocate attacker-sized lines. Acceptance means repeatable seeds, no crash/hang, documented accepted/rejected behavior, and tested input limits.

### Exercise 2 — Fanotify record and FD lifetime verification

Use a test seam or fake event source with valid records, length overruns, metadata mismatches, queue overflow, `FAN_NOFD`, out-of-root paths, path-resolution errors, short writes, `EINTR`, and storage failures. Verify each received event FD closes exactly once and any gap/error cannot appear as healthy zero-exit coverage.

Do not add permission events or allow/deny responses. Run mount-mark checks only in a disposable VM. Acceptance includes an FD ownership table and tests preserving `degraded`/`gap` semantics.

### Exercise 3 — dirfd-based path identity experiment

Create temporary rename-race, symlink, hardlink, bind-mount, and mount-namespace cases. Record when pathname text, `st_dev`, and inode differ. Compare a root-directory-FD plus `openat2` resolution design, but do not connect the experiment to production enforcement.

Do not modify system roots or claim blocking. Bind-mount and namespace tests belong in a disposable VM. Acceptance explains what string matching cannot guarantee and records reproducible coverage gaps.

### Owner attempt record

No owner-authored exercise, code review, or technical-defense response has been observed. Owner reproduction is **not yet attempted/evidenced** and mastery is **unassessed**. CTest success is not evidence of personal mastery.
