# Linux Protected Directory Guard

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

YAML 파서는 plain scalar, 보호 root 목록, 단순 규칙만 지원합니다. 따옴표 scalar, alias/tag, `subject:any` 이외의 주체, 정책 hot reload는 지원하지 않습니다. audit는 fanotify 권한과 mount mark 지원이 필요하며, 실패하면 `coverage=unsupported`를 명시합니다.

Linux 전용 학습 프로젝트입니다. `CONFIG_FANOTIFY`가 활성화된 커널과 mount 표시 권한이 있어야 audit 이벤트를 받을 수 있으며, 특정 배포판/파일시스템의 hook 동작은 보장하지 않습니다. `doctor`는 기본 group 생성과 active LSM 목록만 확인합니다.

지원되지 않는 집행 결과 예시:

```json
{"error":"PDG_UNSUPPORTED_ENFORCEMENT","coverage":"unsupported","enforced":false}
```

### 검증 및 안전 경계

현재 GCC/Clang Release CTest와 Clang ASan/UBSan CTest가 각각 2/2 통과했습니다. 정책 오류 회귀, audit duration 인수, JSON decision 계약 및 fanotify metadata 길이 경계 단위 테스트를 포함합니다. fanotify 실이벤트, mount mark, BPF LSM hook, VM 동작 및 성능은 검증하지 않았습니다. 상세 내용은 [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)를 참고하세요.

mount 수준 fanotify 알림은 정책 경로보다 넓게 관찰할 수 있어 코드가 `/proc/self/fd`로 확인한 경로를 보호 root 아래로 필터링합니다. 그래도 rename, mmap, unlink, 커널 내부 I/O, 원격 변경 등은 보장된 범위가 아닙니다. 권한 부여·거부 제품으로 사용하지 말고, 특권 실험은 스냅샷이 있는 폐기 가능한 VM에서만 수행하세요.

복구: 이 빌드는 persistent hook을 설치하지 않습니다. foreground audit는 `Ctrl-C`로 중지하고, VM 실험에서 예상치 못한 상태가 생기면 하이퍼바이저에서 실험 전 snapshot을 되돌리세요. 테스트 전에 VM snapshot과 recovery console을 준비하세요.

자세한 범위는 [`docs/HOOK_COVERAGE.md`](docs/HOOK_COVERAGE.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)를 참고하세요.

## English

dirguardctl validates a narrow YAML policy subset, explains policy choices, probes limited host capabilities, and can emit audit-only fanotify notifications for a lab mount. This educational project was built to make policy scope and precedence, Linux path-versus-inode identity, and filesystem-hook limits inspectable in code. It remains a partial audit-only implementation; the CLI never enforces policy in this build.

## Build

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel
    ctest --test-dir build --output-on-failure

## Supported environment and example result

This is a Linux-only educational project. Live audit needs a kernel with `CONFIG_FANOTIFY` and permission to mark the containing mount. No specific distribution/filesystem hook behavior is guaranteed. `doctor` checks only basic group creation and the active LSM list.

Example unsupported enforcement result:

    {"error":"PDG_UNSUPPORTED_ENFORCEMENT","coverage":"unsupported","enforced":false}

## Lab use

Create an owned lab directory, copy configs/lab-policy.yaml, and replace its example root with the canonical path:

    mkdir -p "$HOME/guard-lab"
    ./build/dirguardctl doctor --json
    ./build/dirguardctl policy validate --file ./lab-policy.yaml
    ./build/dirguardctl policy explain --file ./lab-policy.yaml --path "$HOME/guard-lab/file.txt" --op open_for_write

Audit requires a kernel with fanotify and permission to mark the containing mount. It logs only paths beneath the selected protected root, even though FAN_MARK_MOUNT observes a wider mount. If capability probing or mount marking fails, the command returns an explicit unsupported/error state. It does not issue permission events.

The duration must be a non-negative integer. JSONL records distinguish the resolved path from event-FD device/inode identity and label the PID with its fanotify metadata source. Queue overflow or metadata, path, read, poll, or journal failures stop the monitor with a degraded result. The journal must be an owned regular file; its permissions are restricted to `0600`.

## Guarantee boundary

Audit observes selected open/close notifications and cannot block writes, rename, unlink, mmap, kernel internal I/O, or remote changes. Enforce always returns PDG_UNSUPPORTED_ENFORCEMENT; enforced=false is never represented as a denial. BPF LSM is probed for diagnostics only and no BPF program is loaded. Run privileged experiments only in a disposable VM with a recovery console.

Recovery: this build installs no persistent hook. Stop a foreground audit with `Ctrl-C`. If a disposable VM experiment leaves an unexpected state, revert the hypervisor snapshot taken before the experiment. Prepare the snapshot and recovery console before testing.

The YAML reader intentionally accepts a small subset: plain scalar values, protected-root lists, and simple rule entries. It rejects repeated fields, overlapping protected roots, ambiguous conflicting scopes, and broad roots after canonicalization. Quoted scalars, aliases, custom tags, subject selectors other than any, and policy hot reload are unsupported. Run `ctest --test-dir build --output-on-failure` for policy validation, explain, duration parsing, metadata boundaries, and unsupported-enforcement checks. The normal suite does not run a privileged mount-mark test; see `docs/TEST_RESULTS.md` and `docs/REQUIREMENTS_TRACEABILITY.md` for the partial status.
