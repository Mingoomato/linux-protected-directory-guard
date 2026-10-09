# Code Walkthrough — Linux Protected Directory Guard

## 1. Policy parsing and validation

`main` chooses the command. Commands needing policy data call `parse_policy` into a fixed-size stack structure. `open(..., O_NOFOLLOW)` prevents the policy file's final component from being followed as a symlink. `getline` reads each line while cumulative bytes and line length are checked. The parser accepts a deliberately narrow syntax: schema version, revision, `mode:audit`, default action, protected roots, and simple rules.

`safe_scope` requires an absolute existing path, rejects broad root paths, then canonicalizes it with `realpath`. `path_within` uses a path-boundary check so `/lab/a` is not considered a parent of `/lab/ab`. After all rules are parsed, each rule scope must be inside a declared root. Unknown keys, duplicate rule IDs, unsupported subject values, or missing fields fail validation.

## 2. Policy explanation

`cmd_explain` canonicalizes the requested path, ensures it lies beneath a protected root, checks the operation name, then calls `evaluate`. The evaluator scans rules matching both operation and scope. Explicit deny takes priority over allow; otherwise the policy default applies. The JSON result explicitly says `enforced:false`, `hook_verified:false`, and `coverage:audit_only`.

That output is a policy explanation only. It must not be presented as a kernel access decision.

## 3. Audit event flow

`cmd_audit` validates that its root is exactly one declared protected root. `fanotify_init` creates a nonblocking notification group. `fanotify_mark` attaches a mount mark for `FAN_OPEN | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD`; the observed mount can be broader than the requested subdirectory.

After `poll` indicates activity, `read` fills a byte buffer with one or more `fanotify_event_metadata` records. The loop verifies `vers` and `event_len`, builds `/proc/self/fd/<event-fd>`, calls `readlink`, canonicalizes only by the kernel-provided resolved target, filters outside-root events, escapes the path, and appends JSON. For a notification event, the receiver owns the event file descriptor and must close it. No permission response is written.

## 4. Doctor, enforcement, and disable

`cmd_doctor` creates a basic fanotify notification group and reads `/sys/kernel/security/lsm` to see whether `bpf` is listed. It does not test a privileged mount mark or attach a BPF hook. `enforce` immediately returns the stable unsupported error; this is a safety property. `disable` is a no-op status because this build does not install persistent hooks.

## 5. Failure paths and resource lifetimes

The policy struct is stack-owned. The parser owns a stream and `getline` buffer. The audit path owns a fanotify FD, log FD, read buffer, and each event FD. Review the paths where metadata is invalid, `readlink` fails, an event is out of scope, output is short, or `poll/read` errors occur; each event FD must still be closed and incomplete coverage must not be called healthy.

The current audit loop is single-threaded. `signal` sets a stop flag and ordinary control flow closes the log and fanotify FDs. The policy revision is immutable for the process lifetime; no policy reload or atomic swap exists.
