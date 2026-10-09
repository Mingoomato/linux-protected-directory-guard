# Linux Protected Directory Guard

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

The YAML reader intentionally accepts a small subset: plain scalar values, protected-root lists, and simple rule entries. Quoted scalars, aliases, custom tags, subject selectors other than any, and policy hot reload are unsupported. Run `ctest --test-dir build --output-on-failure` for policy validation, explain, and explicit unsupported-enforcement checks. It does not start fanotify or run a privileged mount-mark test; see `docs/TEST_RESULTS.md`.
