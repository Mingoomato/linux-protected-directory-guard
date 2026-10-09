# Engineering Study Guide — Linux Protected Directory Guard

## Learning objective and implementation status

This project teaches policy validation, policy explanation, and audit-only filesystem observation. It deliberately keeps policy evaluation separate from enforcement: a displayed `deny` is a policy result, not evidence that Linux blocked an operation. The build always returns an explicit unsupported result for `enforce`.

The Release build and unprivileged policy smoke test passed on the current Linux host; the separate ASan/UBSan smoke run is recorded as passed. New parser cases cover repeated fields, duplicate IDs/roots, canonical broad-root aliases, overlong lines, cumulative-byte limits, conflicting overlapping actions, and most-specific same-action scope selection. Privileged fanotify audit, mount marking, BPF LSM checks, VM scope isolation, parser fuzzing, and performance tests remain unverified. The current parser and audit backend are a partial SRS-03 implementation. Some SRS wording permits an audit-only release when enforcement mode is unsupported, but this does not establish hook coverage or runtime verification.

## Why each subsystem exists

| Subsystem | Why it exists | Main implementation |
|---|---|---|
| Narrow YAML parser | Makes the accepted policy language small enough to inspect and rejects unknown syntax rather than guessing. | `parse_policy`, `trim`, `copy_value` |
| Root/scope validation | Prevents broad roots and requires rule scopes to remain under an explicitly declared root. | `safe_scope`, `path_within` |
| Deterministic policy evaluator | Lets an operator inspect allow/deny reasoning without claiming the action was enforced. | `evaluate`, `cmd_explain` |
| Host capability probe | Reports whether a basic fanotify group can be created and whether BPF LSM appears in active LSMs. | `cmd_doctor` |
| Audit-only fanotify observer | Demonstrates kernel notification records without permission-response events. | `cmd_audit` |
| Decision journal | Preserves policy revision, event mask, path and attribution label for later inspection. | `json_escape`, `cmd_audit` |

## Data and control flow

1. `main` selects `doctor`, `policy`, `status`, `audit`, `enforce`, or `disable`.
2. Commands using a policy call `parse_policy`. The parser opens with `O_NOFOLLOW`, reads into a fixed line buffer and enforces a total-byte limit, rejects repeated/unknown fields and unsupported indentation, requires unique rule IDs and non-overlapping roots, canonicalizes roots/scopes, and verifies each rule scope is within one declared root. Conflicting actions on overlapping scopes fail validation.
3. `policy explain` canonicalizes the requested path, checks it is inside a protected root, validates the operation, and calls `evaluate`. The result includes `policy_revision`, action, `enforced:false`, `hook_verified:false`, and `coverage:audit_only`.
4. `audit` requires an exact declared root. It calls `fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK)` and marks the containing mount for `FAN_OPEN` and `FAN_CLOSE_WRITE` notifications. Because a mount mark is wider than the configured subdirectory, each event FD is resolved through `/proc/self/fd/N`; only a path under the exact canonical root is logged.
5. The audit loop checks metadata version and event length, writes one JSON line, closes each event FD, and stops on signal or duration. It never writes permission responses.
6. `enforce` is an explicit unsupported path. `disable` reports that no persistent hook exists in this build.

## Resource ownership and concurrency

- The `policy` object is stack-owned by `main`; root/rule arrays are fixed-size and need no heap cleanup.
- `parse_policy` owns the FD/`FILE*` and a fixed-size line buffer; `fclose` closes the stream and line input cannot allocate based on an untrusted line length.
- `cmd_audit` owns the fanotify FD and event-log FD. For every `meta->fd >= 0`, the code must close the notification FD even when path resolution fails or the event is filtered. The current loop does so in its expected paths.
- `readlink` returns a byte count; code appends NUL before string operations. Output buffers are fixed and event serialization checks the final length.
- The audit loop is single-threaded; signal handling only sets a `sig_atomic_t` flag. Kernel event queue pressure and a slow log write can still make observations incomplete.
- The policy is parsed once per process. Hot reload and atomic policy revision swaps are not implemented.

## Security assumptions and failure modes

Policy text and CLI paths are untrusted. The parser has byte/line/root/rule bounds, rejects tabs, repeated/unknown fields, and unsupported indentation, and restricts scope. Canonicalization checks the resolved broad-root path, not only the original spelling. A path can still be renamed after the check. The YAML subset does not provide full YAML semantics or robust quoting.

fanotify permission to create a group and permission to mark a mount are separate checks. The observer uses `FAN_CLASS_NOTIF`, not a permission-event class, so it cannot block an open. Mount-wide observation is filtered after the event; event loss, queue overflow, unsupported filesystems, inaccessible `/proc/self/fd`, path renames, and output errors must not be interpreted as complete audit coverage. The current implementation does not expose all such failures as a durable degraded status and does not test them on a privileged VM.

BPF LSM is only diagnosed through `/sys/kernel/security/lsm`; no BPF program is loaded. The active-LSM list is not a probe of every hook's attachability or enforcement semantics.

## Alternative implementations

- **fanotify permission events** can answer an access request, but add fail-open/fail-closed, timeout, queue-stall, privilege, and filesystem-support decisions. One event class cannot guarantee complete write/rename/unlink protection.
- **BPF LSM** can hook selected kernel security operations, but requires supported kernel config, BTF/attachment support, active LSM integration, verifier-safe code, and a tested operation matrix.
- **Landlock** can constrain a process's own future filesystem access, but it is not a general policy daemon that blocks arbitrary processes system-wide.
- **Audit-only userspace explanation** is portable and safe for learning but cannot enforce policy.
- **Mount mark vs directory mark** trades broader observation coverage for tighter scope; mount marks require post-filtering and may expose metadata for unrelated paths to the process.

## Study route

Read `docs/HOOK_COVERAGE.md` before reading `cmd_audit`. Compare `policy explain` with a real kernel event and explain why their `decision` fields have different evidentiary meaning. Then study `docs/CODE_WALKTHROUGH.md`, `docs/LINUX_INTERNALS_EXPLAINED.md`, and attempt one unsolved exercise.

## Official references

- [`fanotify(7)`](https://man7.org/linux/man-pages/man7/fanotify.7.html), [`fanotify_init(2)`](https://man7.org/linux/man-pages/man2/fanotify_init.2.html), [`fanotify_mark(2)`](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)
- [Linux BPF LSM documentation](https://docs.kernel.org/bpf/prog_lsm.html) and [Linux Security Module usage](https://docs.kernel.org/admin-guide/LSM/index.html)
- [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [Linux `procfs` documentation](https://docs.kernel.org/filesystems/proc.html)
