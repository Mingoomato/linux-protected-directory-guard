# Architecture

The policy loader reads a bounded YAML subset and rejects unknown keys, duplicate rule IDs, broad roots, non-canonical or out-of-root scopes, and unsupported mode values. Policy explain applies explicit deny over allow over default and always reports enforced=false.

The live backend uses fanotify_init(FAN_CLASS_NOTIF) plus a mount mark for observation only. Because mount marks are broader than the configured path, event descriptors are resolved through /proc/self/fd and filtered against the exact canonical root before logging. Actor PID is included only when fanotify provides one and is labeled kernel_observed; otherwise attribution is unknown.

No BPF loader or permission hook exists. A fanotify permission event and a BPF LSM hook are separate enforcement surfaces and neither is silently substituted for the other.
