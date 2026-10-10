# Architecture

`dirguardctl` has three layers: a bounded policy parser and canonical scope checks; a deterministic explanation command that reports policy results without claiming enforcement; and an audit-only fanotify observer. The parsed `struct policy` is owned by `main` for one invocation. No daemon reload or policy swap exists.

The observer creates a `FAN_CLASS_NOTIF` group and marks the containing mount for open and close-after-write notifications. A mount mark can see outside the configured directory, so the observer resolves each event descriptor through `/proc/self/fd`, filters the resolved path to the exact canonical root, and records the event descriptor's `st_dev` major/minor and inode separately from its path. PID is labeled as a PID value supplied in `fanotify_event_metadata`, not as a verified long-lived process identity. UID attribution is not available in this implementation.

The audit journal uses a no-follow, append-only, owner-checked regular file, restricts its mode to `0600`, escapes pathname bytes for valid JSON, and handles partial writes. Metadata version/length errors, fanotify queue overflow, path resolution failures, and read/poll/log failures stop the run with a nonzero result and explicit degraded coverage. Actual privileged runtime behavior is not yet verified on this host.

There is no BPF loader, permission event, or enforcement hook. BPF LSM appears in diagnostics only. `enforce` always reports unsupported; no command in this build blocks a filesystem operation.
