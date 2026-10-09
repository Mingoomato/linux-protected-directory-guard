# Linux Protected Directory Guard

[:kr: 한국어](#한국어) · [:us: English](#english)

## 한국어

`dirguardctl`은 좁은 YAML 정책을 검증·설명하고, 실습 경로의 파일 열기 이벤트를 감사 로그로 기록하는 학습용 도구입니다. 제작 의도는 정책의 적용 범위와 우선순위, fanotify 관측 범위, Linux 파일 접근 hook의 한계를 실험으로 이해하는 것입니다. 기본 모드는 `audit`이며, 이 빌드는 파일 접근을 차단하지 않습니다. `enforce`는 항상 `PDG_UNSUPPORTED_ENFORCEMENT`로 종료합니다.

### 빌드 및 사용

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
mkdir -p "$HOME/guard-lab"
./build/dirguardctl doctor --json
./build/dirguardctl policy validate --file ./lab-policy.yaml
./build/dirguardctl policy explain --file ./lab-policy.yaml --path "$HOME/guard-lab/file.txt" --op open_for_write
```

YAML 파서는 plain scalar, 보호 root 목록, 단순 규칙만 지원합니다. 따옴표 scalar, alias/tag, `subject:any` 이외의 주체, 정책 hot reload는 지원하지 않습니다. audit는 fanotify 권한과 mount mark 지원이 필요하며, 실패하면 `coverage=unsupported`를 명시합니다.

### 검증 및 안전 경계

현재 Release 빌드, 비특권 정책 스모크 CTest 1/1, 별도 ASan/UBSan 스모크가 통과했습니다. 추가 회귀 항목은 정규화 후 광범위 root 우회, top-level/rule 중복 키, 중복 root/ID, 충돌하는 중첩 rule, 같은 action의 구체 scope 선택입니다. fanotify audit, mount mark, BPF LSM, VM hook 동작은 검증하지 않았습니다.

mount 수준 fanotify 알림은 정책 경로보다 넓게 관찰할 수 있어 코드가 `/proc/self/fd`로 확인한 경로를 보호 root 아래로 필터링합니다. 그래도 rename, mmap, unlink, 커널 내부 I/O, 원격 변경 등은 보장된 범위가 아닙니다. 권한 부여·거부 제품으로 사용하지 말고, 특권 실험은 스냅샷이 있는 폐기 가능한 VM에서만 수행하세요.

자세한 범위는 [`docs/HOOK_COVERAGE.md`](docs/HOOK_COVERAGE.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)를 참고하세요.

## English

dirguardctl validates a narrow YAML policy subset, explains policy choices, probes host capabilities, and can emit audit-only fanotify notifications for a lab mount. The CLI never enforces policy in this build.

## Build

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel

## Lab use

Create an owned lab directory, copy configs/lab-policy.yaml, and replace its example root with the canonical path:

    mkdir -p "$HOME/guard-lab"
    ./build/dirguardctl doctor --json
    ./build/dirguardctl policy validate --file ./lab-policy.yaml
    ./build/dirguardctl policy explain --file ./lab-policy.yaml --path "$HOME/guard-lab/file.txt" --op open_for_write

Audit requires a kernel with fanotify and permission to mark the containing mount. It logs only paths beneath the selected protected root, even though FAN_MARK_MOUNT observes a wider mount. If capability probing or mount marking fails, the command returns an explicit unsupported/error state. It does not issue permission events.

## Guarantee boundary

Audit observes selected open/close notifications and cannot block writes, rename, unlink, mmap, kernel internal I/O, or remote changes. Enforce always returns PDG_UNSUPPORTED_ENFORCEMENT; enforced=false is never represented as a denial. BPF LSM is probed for diagnostics only and no BPF program is loaded. Run privileged experiments only in a disposable VM with a recovery console.

The YAML reader intentionally accepts a small subset: plain scalar values, protected-root lists, and simple rule entries. It rejects repeated fields, overlapping protected roots, ambiguous conflicting scopes, and broad roots after canonicalization. Quoted scalars, aliases, custom tags, subject selectors other than any, and policy hot reload are unsupported. Run `ctest --test-dir build --output-on-failure` for policy validation, explain, and explicit unsupported-enforcement checks. It does not start fanotify or run a privileged mount-mark test; see `docs/TEST_RESULTS.md`.
