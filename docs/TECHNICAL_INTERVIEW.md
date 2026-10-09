# Technical Defense — Linux Protected Directory Guard

Questions only. There is no answer key. Separate a policy decision, an observed event, and an enforced kernel result in every defense.

## Code reading and flow

1. Trace a policy file from `open(O_NOFOLLOW)` through `parse_policy` to a `policy explain` response.
2. Why does `safe_scope` reject broad roots and call `realpath`? Which race remains after canonicalization?
3. How does `path_within` distinguish a directory from a sibling path with the same textual prefix?
4. Describe the parser's state machine for root and rule lists. Which YAML syntax is intentionally unsupported?
5. What precedence does `evaluate` apply when allow and deny rules overlap? Which rule ID is returned?
6. Trace a fanotify event from `read` to `/proc/self/fd` resolution and output filtering.
7. Which file descriptors are owned by `cmd_audit`, and who must close each event FD?

## Debugging and runtime

8. `doctor` reports fanotify available but `audit` reports unsupported hook. Why are those results compatible?
9. A nested event path is outside the configured subdirectory but inside its mount. What should the observer do, and why?
10. What can happen if `event_len` is corrupt or larger than the bytes returned by `read`?
11. How should short writes, log `ENOSPC`, `poll` errors, and event-FD resolution failures affect coverage?
12. How would you test the audit path without requiring root in the normal CI job?

## Security reasoning

13. Why is `policy explain` returning `deny` not evidence that an open was blocked?
14. What is the functional difference between `FAN_CLASS_NOTIF` and permission-event handling?
15. Why can a mount mark observe more than a protected directory, and what does post-filtering fail to solve?
16. Why is a PID from fanotify labeled observed rather than a durable verified actor identity?
17. What does the active LSM list prove about BPF LSM, and what does it not prove?

## Design tradeoffs

18. Compare fanotify permission events, BPF LSM, Landlock, and audit-only observation for this product boundary.
19. Which operation matrix is required before claiming any enforcement coverage for write, rename, unlink, or mmap?
20. How should policy reload preserve the last valid revision when parsing or applying a new one fails?
21. What behavior should be chosen for daemon exit or event-queue overflow: fail-open, fail-closed, or explicit unsupported? Defend the choice per mode.
22. Which next gate would reduce the most uncertainty: privileged mount-mark test, parser fuzzing, namespace isolation, or queue-overflow injection?

Do not claim owner mastery from CTest success. Direct evidence must come from an independently completed exercise and a reasoned technical defense.
