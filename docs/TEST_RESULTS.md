# Test results

Status: build and unprivileged policy smoke test passed on the current Linux host.

- Release configure/build: passed with C17.
- `ctest --test-dir build --output-on-failure`: 1/1 passed.
- Separate AddressSanitizer/UndefinedBehaviorSanitizer debug build and the same smoke test: passed.
- The smoke test validates an isolated audit policy, checks the explain result and its `enforced:false` field, and confirms that `enforce` returns the explicit unsupported result.
- `dirguardctl doctor --json` returned `fanotify_api_available:false`, `bpf_lsm_active:true`, and `enforcement:"unsupported in this build"` (exit 3). The doctor does not expose errno, and this result does not distinguish missing privilege from a kernel/API limitation.

Not run: fanotify audit, mount marking, BPF LSM checks, privileged scope isolation, VM hook behavior, parser fuzzing, extended sanitizer cases, or performance measurements. No enforcement behavior is implemented or claimed.
