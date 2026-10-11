# Linux Protected Directory Guard

[검토 안내 / Reviewer guide](docs/PORTFOLIO_REVIEW.md) · [최신 검증 / Latest checkpoint](docs/VALIDATION_CHECKPOINT.md)

[:kr: 한국어](#한국어) · [:us: English](#english)

## 한국어

`dirguardctl`은 좁은 YAML 정책을 검증·설명하고, 지원되는 호스트에서 실습 경로의 파일 열기 이벤트를 감사 로그로 기록하는 학습용 도구입니다. 제작 의도는 정책의 적용 범위와 우선순위, 경로와 inode identity의 차이, fanotify 관측 범위, Linux 파일 접근 hook의 한계를 실제 코드와 테스트로 이해하는 것입니다. 기본 모드는 `audit`이며, 이 빌드는 파일 접근을 차단하지 않습니다. `enforce`는 항상 `PDG_UNSUPPORTED_ENFORCEMENT`로 종료합니다.

### 빌드 및 사용

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
mkdir -p "$HOME/guard-lab"
./build/dirguardctl doctor --json
./build/dirguardctl policy validate --file ./lab-policy.yaml
./build/dirguardctl policy explain --file ./lab-policy.yaml --path "$HOME/guard-lab/file.txt" --op open_for_write
```

YAML 파서는 plain scalar, 보호 root 목록, 단순 규칙만 지원합니다. 따옴표 scalar, alias/tag, `subject:any` 이외의 주체는 지원하지 않습니다. audit 프로세스는 SIGHUP으로 audit policy를 교체할 수 있지만 protected root는 고정되며, 이 기능은 enforcement policy나 kernel map을 갱신하지 않습니다. audit는 fanotify 권한과 mount mark 지원이 필요하며, 실패하면 `coverage=unsupported`를 명시합니다.

Linux 전용 학습 프로젝트입니다. `CONFIG_FANOTIFY`가 활성화된 커널과 mount 표시 권한이 있어야 audit 이벤트를 받을 수 있으며, 특정 배포판/파일시스템의 hook 동작은 보장하지 않습니다. `doctor`는 fanotify group 생성을 시도하고 active LSM, `CONFIG_BPF_LSM`, kernel BTF, `bpftool` 유무를 기록합니다. 현재 저장소는 BPF program을 load하지 않으며 hook probe도 수행하지 않습니다.

이벤트에서 `FAN_CLOSE_WRITE`가 확인되면 이미 끝난 쓰기를 대상으로 `open_for_write` 정책을 평가해 선택된 allow/deny와 규칙 근거를 사후 기록합니다. `FAN_OPEN`은 접근 모드를 신뢰성 있게 알려 주지 않으므로 policy decision은 `unknown`입니다. 두 경우 모두 `enforced:false`이며 파일 접근을 막았다는 뜻은 아닙니다. 새 사후 평가 경로는 구현됐으나 아직 기술 검증을 하지 않았습니다.

지원되지 않는 집행 결과 예시:

```json
{"error":"PDG_UNSUPPORTED_ENFORCEMENT","coverage":"unsupported","enforced":false}
```

### 검증 및 안전 경계

현재 GCC Release CTest 3/3, Clang Release CTest 3/3, Clang ASan/UBSan CTest 3/3, 선택형 Clang libFuzzer + ASan/UBSan CTest 4/4가 통과했습니다. parser fuzz smoke는 2,000회 변이 실행하며, reload transaction과 정책·audit 인수·JSON decision·fanotify metadata 경계 테스트를 포함합니다. 추가로 `policy explain`은 100개의 synthetic out-of-root 경로를 거부했습니다. 이는 실제 fanotify workload 검증이 아닙니다. fanotify 실이벤트, mount mark, journal self-event 제외의 실제 동작, SIGHUP reload loop, BPF LSM hook, VM 동작 및 성능은 검증하지 않았습니다. 상세 내용은 [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)를 참고하세요.

선택형 parser fuzz gate:

```sh
cmake -S . -B cmake-build-pdg-fuzz -DCMAKE_C_COMPILER=clang -DPDG_ENABLE_FUZZING=ON
cmake --build cmake-build-pdg-fuzz --parallel
ctest --test-dir cmake-build-pdg-fuzz --output-on-failure
```

mount 수준 fanotify 알림은 정책 경로보다 넓게 관찰할 수 있어 코드가 `/proc/self/fd`로 확인한 경로를 보호 root 아래로 필터링합니다. 그래도 rename, mmap, unlink, 커널 내부 I/O, 원격 변경 등은 보장된 범위가 아닙니다. 권한 부여·거부 제품으로 사용하지 말고, 특권 실험은 스냅샷이 있는 폐기 가능한 VM에서만 수행하세요.

실행 중 audit 프로세스에 `SIGHUP`을 보내면 새 정책을 parse·검증하고, audit root 목록과 revision을 확인한 뒤 event-loop 경계에서 새 revision으로 전환합니다. 실패하면 현재 revision을 유지하고 거부 결과를 stderr/journal에 남깁니다. monitor 중인 protected root는 바꾸지 않습니다. 이 동작은 transaction helper로 단위 검증했으며 실제 fanotify loop에서의 signal/journal 동작은 아직 검증하지 않았습니다.

복구: 이 빌드는 persistent hook을 설치하지 않습니다. foreground audit는 `Ctrl-C`로 중지하고, VM 실험에서 예상치 못한 상태가 생기면 하이퍼바이저에서 실험 전 snapshot을 되돌리세요. 테스트 전에 VM snapshot과 recovery console을 준비하세요.

자세한 범위는 [`docs/HOOK_COVERAGE.md`](docs/HOOK_COVERAGE.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)를 참고하세요.

### 학습·독립 재현 패키지

- [`docs/ENGINEERING_STUDY_GUIDE.md`](docs/ENGINEERING_STUDY_GUIDE.md) — 하위 시스템의 의도와 설계 경계
- [`docs/CODE_WALKTHROUGH.md`](docs/CODE_WALKTHROUGH.md) — 코드 경로와 데이터 흐름
- [`docs/LINUX_INTERNALS_EXPLAINED.md`](docs/LINUX_INTERNALS_EXPLAINED.md) — Linux API, kernel interface, 자원 수명
- [`docs/DEBUGGING_EXERCISES.md`](docs/DEBUGGING_EXERCISES.md) — 답안이 공개되지 않은 3개 독립 실습
- [`docs/TECHNICAL_INTERVIEW.md`](docs/TECHNICAL_INTERVIEW.md) — repository-specific 기술 방어 질문 33개

## English

dirguardctl validates a narrow YAML policy subset, explains policy choices, probes limited host capabilities, and can emit audit-only fanotify notifications for a lab mount. This educational project was built to make policy scope and precedence, Linux path-versus-inode identity, and filesystem-hook limits inspectable in code. It remains a partial audit-only implementation; the CLI never enforces policy in this build.

## Build

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel
    ctest --test-dir build --output-on-failure

## Verification and safety boundary

GCC Release CTest passed 3/3, Clang Release passed 3/3, Clang ASan/UBSan passed 3/3, and the optional Clang libFuzzer + ASan/UBSan suite passed 4/4, including 2,000 seeded mutations. The policy reload transaction was unit-tested, and `policy explain` rejected 100 synthetic paths outside the configured root. These checks do not exercise real fanotify workloads. Live mount marking, journal self-event suppression, SIGHUP inside the fanotify loop, privileged VM behavior, selected BPF hooks, resource-fault injection, and performance remain unverified. `enforce` is unsupported and cannot block file operations. See [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) and [`docs/REQUIREMENTS_TRACEABILITY.md`](docs/REQUIREMENTS_TRACEABILITY.md).

## Supported environment and example result

This is a Linux-only educational project. Live audit needs a kernel with `CONFIG_FANOTIFY` and permission to mark the containing mount. No specific distribution/filesystem hook behavior is guaranteed. `doctor` attempts basic group creation and reports the active LSM, `CONFIG_BPF_LSM`, kernel BTF, and `bpftool` availability. This repository does not load a BPF program or run a hook probe. A `FAN_CLOSE_WRITE` event now triggers a retrospective `open_for_write` policy evaluation and records the selected allow/deny action and reason with `enforced:false`. `FAN_OPEN` does not reveal a trustworthy access mode, so its policy decision stays unknown. This new code has not been technically verified.

Example unsupported enforcement result:

    {"error":"PDG_UNSUPPORTED_ENFORCEMENT","coverage":"unsupported","enforced":false}

## Lab use

Create an owned lab directory, copy configs/lab-policy.yaml, and replace its example root with the canonical path:

    mkdir -p "$HOME/guard-lab"
    ./build/dirguardctl doctor --json
    ./build/dirguardctl policy validate --file ./lab-policy.yaml
    ./build/dirguardctl policy explain --file ./lab-policy.yaml --path "$HOME/guard-lab/file.txt" --op open_for_write

Audit requires a kernel with fanotify and permission to mark the containing mount. It logs only paths beneath the selected protected root, even though FAN_MARK_MOUNT observes a wider mount. If capability probing or mount marking fails, the command returns an explicit unsupported/error state. It does not issue permission events.

The duration must be a non-negative integer. JSONL records distinguish the resolved path from event-FD device/inode identity and label the PID with its fanotify metadata source. `FAN_CLOSE_WRITE` policy results are retrospective and never imply a blocked write; `FAN_OPEN` is unknown because the access mode is unavailable. The journal's own `(device,inode)` identity is filtered to prevent its open event from feeding back into its own records; the live fanotify path has not been exercised here. Queue overflow or metadata, path, read, poll, or journal failures stop the monitor with a degraded result. The journal must be an owned regular file; its permissions are restricted to `0600`.

While audit is running, `SIGHUP` asks it to parse and validate a candidate policy, require the same protected-root set and a new revision, dry-run the supported operation catalog, and swap at the event-loop boundary. A failed candidate leaves the active revision intact. The transaction helper is unit-tested; the privileged signal/event-loop path remains unverified.

## Guarantee boundary

Audit observes selected open/close notifications and cannot block writes, rename, unlink, mmap, kernel internal I/O, or remote changes. A `deny` on `FAN_CLOSE_WRITE` is a retrospective policy result after the write; `enforced:false` explicitly means it was not blocked. Enforce always returns PDG_UNSUPPORTED_ENFORCEMENT. BPF LSM is probed for diagnostics only and no BPF program is loaded. Run privileged experiments only in a disposable VM with a recovery console.

Recovery: this build installs no persistent hook. Stop a foreground audit with `Ctrl-C`. If a disposable VM experiment leaves an unexpected state, revert the hypervisor snapshot taken before the experiment. Prepare the snapshot and recovery console before testing.

The YAML reader intentionally accepts a small subset: plain scalar values, protected-root lists, and simple rule entries. It rejects repeated fields, overlapping protected roots, ambiguous conflicting scopes, and broad roots after canonicalization. Quoted scalars, aliases, custom tags, and subject selectors other than any are unsupported. Audit mode accepts SIGHUP for a validated same-root policy revision swap; this does not reload kernel enforcement state. Run `ctest --test-dir build --output-on-failure` for policy validation, reload transaction, explain, duration parsing, metadata boundaries, and unsupported-enforcement checks. The normal suite does not run a privileged mount-mark test; see `docs/TEST_RESULTS.md` and `docs/REQUIREMENTS_TRACEABILITY.md` for the partial status.

## Study and independent reproduction

- [Engineering study guide](docs/ENGINEERING_STUDY_GUIDE.md) — subsystem purpose and design boundaries
- [Code walkthrough](docs/CODE_WALKTHROUGH.md) — code paths and data flow
- [Linux internals explained](docs/LINUX_INTERNALS_EXPLAINED.md) — Linux APIs, kernel interfaces, and resource lifetimes
- [Debugging exercises](docs/DEBUGGING_EXERCISES.md) — three unsolved independent exercises
- [Technical interview](docs/TECHNICAL_INTERVIEW.md) — 33 repository-specific defense questions

An optional Clang libFuzzer target is available with `-DPDG_ENABLE_FUZZING=ON`. Its seeded smoke test runs 2,000 mutated parser inputs with ASan/UBSan. The suite also rejects 100 synthetic out-of-root paths through `policy explain`; neither check substitutes for live fanotify filtering or 100 real workload trials. See `docs/TEST_RESULTS.md` for the measured boundary.
