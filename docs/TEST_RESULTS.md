# Test results

Status: build and unprivileged policy smoke test passed on the current Linux host.

- Release configure/build: passed with C17.
- `ctest --test-dir build --output-on-failure`: 1/1 passed.
- Separate AddressSanitizer/UndefinedBehaviorSanitizer debug build and the same smoke test: passed.
- The smoke test checks policy validation, status, disable, explain, and the explicit unsupported-enforcement result. Its parser cases reject duplicate fields/IDs/roots, unknown keys, an aliased broad root, overlong lines, cumulative-size overflow, and conflicting overlapping actions; it also checks most-specific same-action explanation.
- `dirguardctl doctor --json` returned `fanotify_api_available:false`, `bpf_lsm_active:true`, and `enforcement:"unsupported in this build"` (exit 3). The doctor does not expose errno, and this result does not distinguish missing privilege from a kernel/API limitation.

Not run: fanotify audit, mount marking, BPF LSM checks, privileged scope isolation, VM hook behavior, parser fuzzing, extended sanitizer cases, or performance measurements. No enforcement behavior is implemented or claimed.
