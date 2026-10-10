# Code Walkthrough — Linux Protected Directory Guard

## 한국어

### 1. 정책 읽기와 검증 (`parse_policy`)

`main`은 policy가 필요한 명령에서 `struct policy`를 스택에 만들고 `parse_policy`로 완전히 채운 뒤 사용합니다. 파서는 `open(O_RDONLY|O_CLOEXEC|O_NOFOLLOW)`, `fdopen`, `read_policy_line`을 거쳐 한 줄씩 읽습니다. 한 줄 크기와 전체 policy byte 수에 상한이 있습니다. 파서는 알려진 top-level 필드와 규칙 필드만 허용하고 중복/누락, 잘못된 들여쓰기, 잘못된 operation/action, 중복 ID/root를 거부합니다.

`safe_scope`는 절대 경로를 요구하고 `realpath`로 정규화한 뒤 `/`, `/etc`, `/usr`, `/home`, `/var`, `/root` 등 넓은 root를 다시 거부합니다. `path_within`은 문자열 prefix 뒤가 NUL 또는 `/`인지 확인해 `/lab/a`가 `/lab/ab`의 부모로 오인되지 않게 합니다. 정책 규칙 범위는 보호 root 아래여야 하고, 서로 겹치는 충돌 action은 reject합니다.

### 2. 정책 설명 (`cmd_explain` → `evaluate`)

설명 경로도 canonicalize하고 선언된 root 안에 있는지, operation이 허용 목록인지 확인합니다. `evaluate`는 같은 operation과 일치하는 rule 중 가장 긴 scope를 택하고 없으면 `default_action`을 씁니다. 응답에는 policy ID/revision, rule 또는 `DEFAULT_ACTION` reason, path, `actor_attribution:unknown`, `errno:null`, `enforced:false`, `hook_verified:false`, `coverage:audit_only`가 들어갑니다. `deny` 문자열은 설명 결과이며 실제 접근이 막혔다는 뜻이 아닙니다.

### 3. 감사 수집 (`cmd_audit`)

1. `--root`를 canonicalize하고 policy의 보호 root와 정확히 일치해야 합니다.
2. `fanotify_init(FAN_CLASS_NOTIF|FAN_NONBLOCK)`으로 알림 group을 만들고 `fanotify_mark(FAN_MARK_MOUNT)`로 mount에 `FAN_OPEN` 및 `FAN_CLOSE_WRITE`를 표시합니다. 이 두 호출의 성공 여부와 권한 요구는 서로 다릅니다.
3. 로그 파일은 `O_NOFOLLOW|O_APPEND|O_NONBLOCK`로 열고 `fstat`으로 현재 UID 소유 regular file인지 확인합니다. mode를 `0600`으로 낮춥니다.
4. `poll`로 기다렸다가 `read`한 byte buffer를 metadata record로 순회합니다. 각 record는 버전, reserved 필드, `event_len`, `metadata_len`, 남은 buffer 길이를 검사합니다. 구조 검증은 `src/fanotify_records.h`의 `metadata_record_valid`가 담당합니다.
5. event FD를 `/proc/self/fd/N`으로 `readlink`해 path를 얻고 보호 root 밑인지 확인합니다. `fstat(event_fd)`로 device major/minor와 inode를 따로 읽습니다. PID는 metadata 출처를 함께 기록합니다. 이 값들은 경로 문자열과 동일한 개념이 아닙니다.
6. `FAN_CLOSE_WRITE`는 `open_for_write` policy를 event 이후 평가해 rule/default action을 `decision`과 `reason_code`에 기록합니다. 이것은 이미 끝난 write를 되돌리거나 막지 않는 사후 판단입니다. `FAN_OPEN`은 접근 모드를 알 수 없으므로 `unknown` 및 `OPEN_ACCESS_MODE_UNOBSERVABLE`로 남깁니다. JSON line은 길이 제한된 buffer에서 생성하고 `write_all`은 부분 write와 `EINTR`를 처리합니다. 파일이 아닌 event, queue overflow, metadata/path/read/poll/log 오류는 명시적으로 degraded 종료합니다. 정상 duration 또는 signal 종료도 journal에 남깁니다.
7. 각 정상 event FD와 group/log FD를 `close`합니다. 이 빌드에서 permission response를 보내거나 deny를 실행하지 않습니다.

### 4. Capability 진단 및 안전 명령

`cmd_doctor`는 기본 fanotify group 생성과 errno를 기록하고, `/sys/kernel/security/lsm`의 정확한 `bpf` token, `/boot/config-<uname.release>`의 `CONFIG_BPF_LSM`, kernel BTF 파일, PATH의 실행 가능한 `bpftool`을 확인합니다. JSON에는 preflight 상태와 `not_run_no_hook_selected` probe 결과를 포함합니다. 이 검사는 mount mark, filesystem별 coverage, BPF hook attach를 검증하지 않습니다. `enforce`는 지원되지 않는 JSON 오류를 반환하며 `disable`은 영속 hook이 없다는 메시지만 냅니다.

### 5. 소유권·실패 경로 확인

- `main` 소유: `struct policy`; 호출 종료 시 자동 해제.
- `parse_policy` 소유: `FILE*`/FD와 고정 line buffer; `fclose`가 파일 자원을 닫음.
- `cmd_audit` 소유: fanotify group FD, journal FD, 정렬된 read buffer, kernel이 넘긴 event FD.
- 경계 테스트: malformed metadata가 다음 record로 건너뛰지 않고 중단하는지, out-of-scope event에서 event FD를 닫는지, 로그 오류가 성공으로 보이지 않는지 확인합니다.
- 실제 privileged event 수집과 overflow/log fault injection은 아직 VM에서 검증하지 않았습니다.

### 6. 정책 parser fuzz 경로

`PDG_ENABLE_FUZZING=ON`을 켜면 CMake가 Clang libFuzzer target을 추가합니다. `tests/policy_parser_fuzz.c`는 CLI와 같은 `dirguardctl.c` translation unit을 포함해 내부 `parse_policy`를 직접 호출합니다. 초기화 시 `mkdtemp` root와 `mkstemp` policy 파일을 만들고, seed의 `@ROOT@`를 그 canonical 경로로 바꿉니다. 각 입력마다 임시 파일을 truncate/write하고 실제 parser의 `open(O_NOFOLLOW)` 경로로 읽게 합니다. target은 parse의 성공 여부 자체를 oracle로 삼지 않고, crash와 ASan/UBSan 오류를 찾습니다.

CTest runner는 seed를 임시 corpus 디렉터리에 복사해 `-runs=2000` 변이를 수행하고 생성 corpus를 임시 디렉터리와 함께 지웁니다. seed 파일 자체를 fuzzer 인자로 주면 입력 재생만 하므로, 디렉터리 인자를 주는 runner가 필요합니다. smoke 통과는 parser grammar의 완전성이나 장시간 fuzzing을 보장하지 않습니다.

### 7. audit 정책 reload와 self-event 제외

`cmd_audit`는 SIGINT/SIGTERM handler 외에 SIGHUP handler를 설치합니다. handler는 `reload_requested` flag만 설정합니다. event loop가 flag를 확인하면 `reload_policy`가 새 `struct policy`를 임시 객체로 파싱하고, 현재 revision과 다른지, 보호 root 집합이 같은지 확인하고 `policy_dry_run`을 수행합니다. 모두 통과한 경우에만 `*active = candidate`로 바꿉니다. 단일 스레드 event loop가 교체 경계 밖에서 policy를 읽지 않으므로 이 구현에서 원자성은 event-loop 관점의 논리적 swap입니다. 파싱/호환성 실패는 기존 policy를 유지하고 거부 사실을 stderr와 journal에 씁니다. journal write가 실패하면 monitor는 degraded로 끝납니다.

audit 시작 시 `fstat(logfd)`의 device/inode를 저장합니다. event FD를 `fstat`한 identity가 journal과 같으면 해당 event FD를 닫고 skip합니다. 이는 journal 자기 event를 다시 journal에 쓰는 loop를 막습니다. SRS의 administrator test-tool exception과 실제 privileged self-event 시험은 아직 없습니다. `tests/policy_reload_test.c`는 reload transaction의 candidate 성공/실패 경로를 단위 검사하지만 SIGHUP 전달과 fanotify event loop를 실행하지 않습니다.

## English

### 1. Policy input (`parse_policy`)

`main` creates a stack-owned `struct policy` and fully parses it before a command uses it. `parse_policy` opens the file with `O_NOFOLLOW`, wraps the descriptor in `FILE*`, and reads through `read_policy_line`. Both per-line and total-byte limits apply. Only known fields and indentation are accepted; duplicates, missing fields, invalid operations/actions, and duplicate rule IDs/roots fail.

`safe_scope` requires an absolute path, canonicalizes with `realpath`, then rejects broad roots. `path_within` checks the component boundary after the textual prefix. Every rule scope must lie under a declared root; overlapping rules with conflicting actions are rejected.

### 2. Policy explanation (`cmd_explain` → `evaluate`)

The requested path is canonicalized and checked against a protected root and operation allow-list. `evaluate` selects the longest matching scope for the operation, otherwise using the default action. The JSON includes policy identity/revision, rule/default reason, scope path, unknown actor and errno, and the explicit `enforced:false`, `hook_verified:false`, `coverage:audit_only` boundary. A `deny` here explains policy; it does not mean Linux denied an access.

### 3. Audit collection (`cmd_audit`)

The command requires an exact protected root, creates a `FAN_CLASS_NOTIF` group, then marks the containing mount for `FAN_OPEN` and `FAN_CLOSE_WRITE`. It opens an append-only no-follow journal, checks that it is an owned regular file, and restricts permissions to `0600`.

The loop waits with `poll`, reads a byte buffer, validates metadata version/reserved fields/event length/metadata length against the remaining bytes, and resolves event FDs through `/proc/self/fd/N`. It filters the resolved path to the exact configured root and records `fstat` device major/minor and inode separately. A supplied PID is labeled by its metadata source. For `FAN_CLOSE_WRITE`, `evaluate` selects the `open_for_write` rule/default action after the write has completed; JSON records that retrospective decision and `enforced:false`. For `FAN_OPEN`, the access mode is not trustworthy, so the record remains unknown with `OPEN_ACCESS_MODE_UNOBSERVABLE`. JSON output uses bounded buffers and `write_all` handles short writes and `EINTR`.

Queue overflow, malformed records, missing event FDs, path/read/poll/journal failures produce a degraded nonzero exit. Normal duration/signal stops are journaled. Every valid event FD and both owned group/log descriptors are closed. No permission response is ever sent.

### 6. Audit policy reload and self-event exclusion

`cmd_audit` installs a SIGHUP handler that sets only `reload_requested`. At an event-loop boundary, `reload_policy` parses into a candidate object, requires a different revision and the same protected-root set, then runs `policy_dry_run`. Only a fully accepted candidate replaces the active struct. Because the event loop is single-threaded, no event handler can read a partially replaced policy; a failed candidate keeps the old revision. The monitor journals accepted/rejected reload outcomes and degrades if that journal write fails. This transaction helper is unit-tested; SIGHUP delivery and event-loop behavior remain unverified on the privileged fanotify path.

After checking an event FD is under the protected root, the loop compares its `fstat` device/inode with the journal's saved identity. A match closes and skips the FD, preventing the journal's own open event from being recorded recursively. Other self-process events and administrator test-tool exceptions are not implemented. The identity comparator is unit-tested; live event suppression is not.

### 4. Diagnostics and failure ownership

`cmd_doctor` records basic group creation and errno, exact active-LSM token, `CONFIG_BPF_LSM` from `/boot/config-<uname.release>`, kernel BTF presence, executable `bpftool` availability, an aggregate preflight state, and the explicit `not_run_no_hook_selected` probe result. These read-only checks do not prove mount marking, filesystem coverage, or hook attachability. `enforce` is explicitly unsupported and `disable` has no persistent hook to remove. The stack policy is owned by `main`; the parser owns its stream; `cmd_audit` owns the fanotify and journal FDs, read buffer, and each returned event FD. Privileged runtime and injected failure cases remain unverified.

### 5. Policy parser fuzz path

With `PDG_ENABLE_FUZZING=ON`, CMake adds a Clang libFuzzer target that includes the same `dirguardctl.c` translation unit and calls the internal `parse_policy`. Startup creates a `mkdtemp` root and `mkstemp` policy file, then expands the seed's `@ROOT@` marker to that canonical path. Each input truncates and rewrites the temporary file before exercising the production `open(O_NOFOLLOW)` parser path. The target seeks crashes and ASan/UBSan findings; it does not use the parser's accepted/rejected result as a semantic oracle.

The CTest runner copies the seed into a temporary corpus directory and runs 2,000 mutations there, cleaning generated corpus files afterward. Passing the seed as a file would replay it rather than mutate it, so the directory-based runner is intentional. This smoke run is not proof of grammar completeness or sustained fuzz coverage.
