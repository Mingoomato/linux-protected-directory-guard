# ADR-001: audit-only baseline

- Status: accepted.
- Decision: implement fanotify notification observation, policy explanation, and capability diagnostics; refuse enforcement in this build.
- Reason: permission-event behavior and BPF LSM hook coverage must be verified on an isolated supported kernel before any block claim is safe.
- Consequence: the requested policy can be explained, but live fanotify records remain unknown and enforced=false.
