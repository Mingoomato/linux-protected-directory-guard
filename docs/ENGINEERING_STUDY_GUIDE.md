# Engineering Study Guide — Linux Protected Directory Guard

## 한국어

### 학습 목표와 상태

이 프로젝트는 좁은 정책 언어를 안전하게 파싱하고, 규칙을 설명하며, fanotify 알림을 차단과 혼동하지 않고 기록하는 과정을 학습합니다. 현재 구현은 audit-only 부분 구현입니다. GCC Release, Clang Release 및 Clang ASan/UBSan CTest가 각각 3/3 통과했고, Clang libFuzzer + ASan/UBSan CTest는 4/4 통과했습니다. parser fuzz smoke는 seeded 입력으로 2,000회 실행했고, reload rollback과 100개의 synthetic out-of-root CLI 요청을 검사했습니다. 이것들은 실제 fanotify workload 검증은 아닙니다. 정적 분석과 비특권 정책 회귀도 통과했습니다. `doctor`는 BPF 설정·활성 LSM·BTF·bpftool 상태를 보고하며, 현재 호스트의 사전 점검은 bpftool 부재로 incomplete입니다. `FAN_CLOSE_WRITE`의 사후 policy evaluation은 추가됐지만 이번 변경은 아직 검증하지 않았습니다. 실제 fanotify mount mark·실이벤트, self-event suppression, SIGHUP reload loop, queue overflow, privileged VM, BPF hook 및 성능 게이트는 미검증입니다. 자동 테스트 통과는 SRS 전체 구현이나 학습자의 개인 숙련 증거가 아닙니다.

### 중요한 하위 시스템이 존재하는 이유

| 하위 시스템 | 존재 이유 | 주요 코드 |
|---|---|---|
| 제한된 정책 파서 | 미지의 YAML 기능을 추측하지 않고, 입력량과 문법을 제한 | `parse_policy`, `read_policy_line` |
| parser fuzz harness | 잘못된 바이트열이 production parser에 들어가도 사용자 공간 crash/UB가 발생하는지 탐색 | `tests/policy_parser_fuzz.c`, `tests/fuzz_corpus/policy-v1` |
| audit 정책 reload | SIGHUP에서 candidate 검증·dry-run 후 마지막 유효 revision을 event loop 경계에서 교체 | `reload_signal`, `reload_policy`, `policy_dry_run` |
| journal self-event guard | audit 파일 자체를 file identity로 식별해 자신의 open event 기록이 반복되지 않게 함 | `file_identity_equal`, `cmd_audit` |
| 경로/범위 검증 | 절대 경로를 canonicalize하고 광범위 root 및 범위 충돌을 거부 | `safe_scope`, `path_within`, `scopes_overlap` |
| 결정적 정책 설명 | 규칙 우선순위를 사람이 검사하되 실제 kernel 차단과 구분 | `evaluate`, `cmd_explain` |
| capability 진단 | fanotify group 생성 시도와 BPF LSM 설정·활성 상태·BTF·tooling을 분리해 기록하며, hook 부착을 주장하지 않음 | `cmd_doctor`, `bpf_lsm_config_enabled`, `executable_on_path` |
| 감사 이벤트 수집 | 알림 event를 기록하되 permission response는 보내지 않음 | `cmd_audit`, `fanotify_records.h` |
| JSONL 결정 저널 | 정책 revision, 이유, hook, path와 device/inode identity, actor 출처를 남김 | `json_escape`, `write_all`, `cmd_audit` |

### 데이터 및 제어 흐름

1. `main`이 명령을 고릅니다. 정책이 필요한 명령은 고정 크기 `struct policy`에 `parse_policy` 결과를 먼저 완성합니다.
2. 파서는 `open(O_NOFOLLOW)`로 policy 파일의 최종 symlink를 거부하고, `MAX_LINE`과 `MAX_POLICY_BYTES`를 적용합니다. 중복/알 수 없는 키, 잘못된 들여쓰기, 중복 ID/root, 모호한 범위를 거부합니다. 지원하는 것은 의도적으로 작은 YAML subset입니다.
3. root와 rule scope는 `realpath`로 정규화되고 broad root가 다시 검사됩니다. 각 rule은 선언된 root 아래 있어야 합니다. 충돌 action은 거부하며, 유효한 동일 action 중첩 범위는 가장 구체적인 scope가 선택됩니다.
4. `policy explain`은 입력 경로와 operation을 검사하고 정책 결과를 `guard_decision.v1` JSON으로 씁니다. `enforced:false`, `hook_verified:false`, `coverage:audit_only`가 이 결과가 설명에 불과함을 나타냅니다.
5. `audit`는 선택 root가 policy root와 정확히 일치하는지 확인한 뒤 `fanotify_init(FAN_CLASS_NOTIF)`와 `fanotify_mark(FAN_MARK_MOUNT)`를 호출합니다. mount mark가 더 넓을 수 있어 event FD의 `/proc/self/fd/N` 경로를 root 아래인지 필터링합니다.
6. metadata version/length를 검증하고, event FD에서 `fstat`한 device major/minor와 inode를 pathname과 별도로 기록합니다. 제공된 PID는 `fanotify_event_metadata.pid` 출처와 함께 기록하고 검증된 장기 프로세스 신원으로 취급하지 않습니다.
7. `FAN_CLOSE_WRITE`가 오면 `open_for_write` 정책을 사후 평가해 선택된 규칙/default action을 기록합니다. 이미 쓰기가 끝난 뒤이므로 이는 차단 결과가 아니며 항상 `enforced=false`입니다. `FAN_OPEN`은 접근 모드를 알 수 없어 `unknown`으로 기록합니다.
8. event FD와 log FD는 모든 정상/오류 경로에서 닫습니다. queue overflow, metadata 오류, path/read/poll/write 실패는 coverage gap/degraded로 처리하고 0이 아닌 종료를 반환합니다. 종료 신호나 지정 시간이 끝나면 종료 이유를 기록합니다.
9. `enforce`는 항상 `PDG_UNSUPPORTED_ENFORCEMENT`를 반환합니다. BPF LSM은 진단만 하며 program을 load하지 않습니다.
10. `doctor`는 `fanotify_init` 결과와 errno를 기록하고, `/boot/config-<release>`에서 `CONFIG_BPF_LSM`, `/sys/kernel/security/lsm`에서 정확한 active LSM token, `/sys/kernel/btf/vmlinux`, `PATH`의 실행 가능한 `bpftool`을 확인합니다. hook을 선택하지 않았으므로 `bpf_hook_probe=not_run_no_hook_selected`입니다.
11. `PDG_ENABLE_FUZZING=ON`이면 Clang libFuzzer target이 같은 production parser translation unit을 ASan/UBSan으로 빌드합니다. 고정 corpus의 `@ROOT@`는 실행 중 생성한 canonical 임시 경로로 치환되고, 각 입력은 제한된 임시 파일을 거쳐 `parse_policy`에 전달됩니다. CTest smoke는 2,000개 입력을 실행합니다. 100개의 별도 synthetic 경로 테스트는 `policy explain`의 root 바깥 거부만 검사합니다.
12. audit 중 SIGHUP은 flag만 설정합니다. 단일 event loop가 다음 경계에서 policy file을 candidate struct로 파싱하고, 보호 root가 그대로인지·revision이 새 값인지 확인한 뒤 operation 목록을 dry-run합니다. 통과하면 전체 `struct policy`를 교체하고, 실패하면 기존 객체를 보존합니다. journal과 동일한 `(st_dev, st_ino)`인 event FD는 기록 전에 닫고 건너뜁니다.

### Linux 인터페이스, 소유권 및 concurrency

- 사용 인터페이스: `uname`, `fopen`/`fgets`, `access`, `getenv`, `snprintf`, `open`, `fdopen`, `fgetc`, `realpath`, `fanotify_init`, `fanotify_mark`, `poll`, `read`, `readlink`, `fstat`, `fchmod`, `write`, `close`, `/boot/config-*`, `/proc/self/fd`, `/sys/kernel/security/lsm`, `/sys/kernel/btf/vmlinux`.
- `policy`와 고정 입력 버퍼는 호출 스택이 소유합니다. `FILE*`는 `fclose`가 underlying fd까지 닫습니다.
- `cmd_audit`는 fanotify group FD와 journal FD를 소유합니다. 각 `meta->fd`는 수신 프로그램이 닫아야 하는 event FD입니다. `write_all`은 부분 write와 `EINTR`를 처리합니다.
- 버퍼는 metadata 구조체에 맞춰 정렬하고 `event_len`, `metadata_len`, 남은 read 길이를 교차 검증합니다. 파서와 event buffer는 입력 길이에 따라 동적 확장하지 않습니다.
- event loop는 단일 스레드입니다. signal handler는 `sig_atomic_t` 플래그만 세우고 정리/저널 작성은 일반 흐름에서 합니다. SIGHUP candidate는 reload 함수의 stack 소유이며, parse/root compatibility/dry-run 후 event loop 경계에서 active struct로 복사합니다. 이는 이 단일-thread 루프에서의 논리적 atomicity이며 concurrent lock-free swap은 아닙니다. 실패 candidate는 active revision을 덮지 않습니다.
- fuzz target도 기본 libFuzzer 실행처럼 단일 process에서 순차 호출을 가정합니다. 초기화가 생성한 임시 root와 policy 파일은 target이 소유하며 `atexit`에서 정리합니다. 입력 버퍼는 고정 크기이고, 매 iteration policy 파일을 truncate/write한 뒤 parser가 연 stream을 `fclose`로 닫습니다. 별도의 privileged kernel 자원은 생성하지 않습니다.
- log FD의 `fstat` device/inode는 monitor 수명 동안 보관합니다. event FD의 identity가 일치하면 해당 event FD를 닫고 건너뜁니다. 이는 journal 자기 이벤트 재귀를 막는 예외 하나이며, 관리자 test-tool 예외를 제공하지는 않습니다.

### 보안 가정과 실패 양상

정책 파일, 경로, CLI 인수는 불신 입력입니다. 제한된 YAML 파서는 full YAML이 아니며 quoted scalar/alias/tag를 지원하지 않습니다. `realpath` 이후 경로가 바뀔 수 있고 문자열 필터만으로 rename, hardlink, bind mount, mount namespace 및 inode 재사용을 해결하지 못합니다. 로그는 symlink를 따르지 않고 현재 UID 소유 regular file만 받아 mode `0600`을 적용합니다. JSON path 출력은 valid UTF-8을 보존하고 quote/backslash/control 및 잘못된 UTF-8 바이트를 escape합니다.

fanotify group 생성과 mount mark는 별도 capability/support 점검입니다. `FAN_CLASS_NOTIF`는 요청을 막지 않습니다. doctor의 `CONFIG_BPF_LSM`/BTF/tool 상태는 읽기 전용 환경 증거이며 hook attach 증거가 아닙니다. mount queue overflow는 관측 누락을 뜻하므로 gap 기록 후 degraded 종료합니다. `/proc/self/fd` 접근 불가, event FD가 없는 비-overflow event, 잘린 metadata, log 저장 실패, poll/read 오류도 성공적인 완전 수집으로 보고하지 않습니다. 아직 이 오류 경로를 실제 privileged VM에서 주입하지 않았습니다.

fanotify PID는 event metadata에 들어온 PID 관측값일 뿐이고 UID, process start time, pidfd를 저장하지 않습니다. BPF가 active LSM 목록에 있어도 특정 hook을 붙일 수 있다는 뜻은 아닙니다. 이 버전은 root attacker 방어, 모든 파일 변경 통제, mmap/kernel I/O/원격 변경 관측을 약속하지 않습니다.

### 대안과 공식 문서

- fanotify permission event는 요청 처리/응답을 요구하므로 fail-open/closed, timeout, queue stall, filesystem 지원을 설계해야 합니다. 현재 버전에서 사용하지 않습니다.
- BPF LSM은 특정 커널 hook 범위에 한정되며 CONFIG/BTF/active LSM/attach 가능성과 격리 VM별 검증이 필요합니다.
- Landlock은 보통 호출 프로세스의 이후 접근을 제한하는 sandbox 인터페이스이지, 임의의 모든 프로세스를 제어하는 daemon 대체물이 아닙니다.
- audit-only와 policy explanation은 안전한 학습 표면이지만 차단 기능은 아닙니다.
- 공식/기술 참고: [Linux kernel fanotify guide](https://docs.kernel.org/6.15/admin-guide/filesystem-monitoring.html), [kernel procfs guide](https://docs.kernel.org/filesystems/proc.html), [`fanotify(7)`](https://man7.org/linux/man-pages/man7/fanotify.7.html), [`fanotify_init(2)`](https://man7.org/linux/man-pages/man2/fanotify_init.2.html), [`fanotify_mark(2)`](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html), [`uname(2)`](https://man7.org/linux/man-pages/man2/uname.2.html), [`access(2)`](https://man7.org/linux/man-pages/man2/access.2.html), [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html), [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html), [Linux LSM](https://docs.kernel.org/admin-guide/LSM/index.html), [Landlock](https://docs.kernel.org/userspace-api/landlock.html).
- parser fuzzing reference: [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html) describes its target ABI, input corpus directories, mutation and sanitizer use.

## English

This project teaches bounded policy parsing, deterministic explanation, and audit-only fanotify observation without confusing a policy result with kernel enforcement. It remains a partial audit-only implementation. GCC Release, Clang Release, and Clang ASan/UBSan CTest each passed 3/3; the Clang libFuzzer + ASan/UBSan suite passed 4/4, including a 2,000-input seeded parser smoke. Reload rollback and one hundred synthetic out-of-root CLI requests were also checked; these do not exercise live fanotify workloads. Static analysis and unprivileged policy regressions passed. `doctor` reports BPF config/active-LSM/BTF/tool state; the current host has an incomplete preflight because `bpftool` is absent. Live fanotify mount marks/events, journal self-event suppression, SIGHUP event-loop reload, overflow injection, privileged VM behavior, BPF hooks, and performance gates remain unverified. Automated tests do not prove full SRS completion or the owner's personal mastery.

The policy parser uses a fixed-size `struct policy`, `open(O_NOFOLLOW)`, bounded line and total-input sizes, explicit fields, canonical roots, and conflict checks. `evaluate` chooses the most-specific valid same-action scope. `policy explain` returns a policy result with `enforced:false`, `hook_verified:false`, and `coverage:audit_only`.

The observer creates a `FAN_CLASS_NOTIF` group, marks the containing mount, reads packed metadata, validates version and lengths against the available bytes, resolves each event FD through `/proc/self/fd`, and filters to the configured canonical root. `fstat` device major/minor and inode are recorded separately from the path. The PID field is labeled with its fanotify metadata source, not as a durable process identity. A `FAN_CLOSE_WRITE` record retrospectively evaluates `open_for_write` and stores the selected allow/deny rule or default action; the write has already happened and `enforced:false` means no access was blocked. `FAN_OPEN` does not reliably identify the access mode, so it remains `unknown` and is marked `not_evaluated`. Permission responses are never sent. This newly added policy-evaluation path and its schema fields have not been technically verified.

With `PDG_ENABLE_FUZZING=ON`, Clang builds `tests/policy_parser_fuzz.c` with libFuzzer, ASan, and UBSan. It includes the same parser implementation as the CLI, expands a corpus root marker into a private temporary directory, and rewrites a bounded temporary regular file before each parse. The seeded CTest run makes 2,000 calls and looks for memory-safety failures and crashes. It does not prove that all malformed policies are rejected correctly. A separate fixed set of 100 synthetic out-of-root CLI paths tests the `policy explain` guard only; it does not execute processes under fanotify.

For audit policy updates, SIGHUP only sets a signal-safe flag. At the next event-loop boundary the program parses a candidate, requires the same root set and a different revision, and runs a dry-run over the supported operation list before replacing the active policy object. The single-threaded loop provides logical atomicity for its readers; a rejected candidate leaves the active revision untouched. A unit test exercises transaction decisions, but signal delivery and journal records are not run because the fanotify path is privileged. The journal's device/inode identity is compared with each in-scope event FD to skip the journal's own event; live suppression remains unverified, and administrator-tool exceptions are not implemented.

`doctor` performs a separate read-only preflight: `uname` selects `/boot/config-<release>`, bounded `fgets` reads `CONFIG_BPF_LSM`, the exact `bpf` token is searched in `/sys/kernel/security/lsm`, `access` checks kernel BTF readability and executable `bpftool` candidates from `PATH`, and JSON reports each observation plus `not_run_no_hook_selected`. A missing config is `unknown`; a missing bpftool makes the aggregate state `incomplete`. This is environment evidence, not proof that a program verifies or attaches.

Relevant interfaces include `uname(2)`, `access(2)`, `fopen(3)`/`fgets(3)`, `fanotify_init(2)`, `fanotify_mark(2)`, `poll(2)`, `read(2)`, `readlink(2)`, `fstat(2)`, `write(2)`, and `close(2)`. The kernel interfaces are the fanotify API, `/proc/self/fd`, securityfs LSM list, kernel config file, and `/sys/kernel/btf/vmlinux`.

The policy and parser buffers are stack-owned. `cmd_doctor` uses bounded stack buffers for kernel release, config path, PATH candidates, and the active-LSM file; its `FILE*` is closed after config/LSM reads. The audit function owns the fanotify FD, log FD, read buffer, and each event FD; every valid event FD is closed. Reload owns a candidate policy on the calling stack and replaces the active object only after checks pass; the signal handler writes only a `sig_atomic_t` flag. The fuzz harness owns a fixed input-expansion buffer, an `mkdtemp` root, and an `mkstemp` policy path; it closes each write descriptor and relies on `parse_policy`/`fclose` for read-side cleanup before `atexit` removes the temporary paths. libFuzzer calls this target sequentially by default. `write_all` handles partial writes and `EINTR`. A no-follow owner-checked regular journal is restricted to mode `0600`; its `(st_dev, st_ino)` pair is retained to ignore the journal's own in-scope event. JSON output preserves valid UTF-8 and escapes invalid pathname bytes.

Malformed metadata, queue overflow, missing event FDs, path resolution errors, poll/read errors, and journal failures produce explicit degraded/unsupported results instead of a healthy-success claim. `realpath` and path filtering do not solve rename races, hard links, bind mounts, namespace identity, or inode reuse. fanotify group creation is not proof that mount marking or a particular filesystem/hook is supported. Active BPF LSM is not proof a program can attach. `enforce` always returns `PDG_UNSUPPORTED_ENFORCEMENT`.

Alternatives include fanotify permission events, BPF LSM, Landlock, and audit-only explanation; each has a different operation and failure boundary. Permission events can make a kernel access wait for a userspace response; BPF LSM operates at chosen kernel hooks and needs verifier/attach and workload evidence; Landlock restricts a cooperating process's future actions; audit-only records observations without blocking. Official references are linked above and in `docs/LINUX_INTERNALS_EXPLAINED.md`, including the kernel fanotify, BPF LSM, LSM, Landlock and procfs documentation plus the relevant system-call manual pages.
