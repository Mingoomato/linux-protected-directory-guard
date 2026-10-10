# Changelog

## Unreleased — 2026-10-10

- Hardened fanotify metadata bounds, JSONL path encoding, journal permissions, partial writes, queue-overflow reporting, and degraded exit status.
- Added path/device/inode identity, PID source, event IDs, policy identity, errno, and monitor-stop records to audit decisions.
- Added retrospective `FAN_CLOSE_WRITE` policy evaluation and explicit event/evaluation fields to the JSON contract; this new path is not verified and does not block the completed write.
- Expanded GCC/Clang, sanitizer, metadata, duration, decision-contract, and path-escaping verification.
- Updated Korean/English README, study package, traceability, and verification evidence; live privileged hooks remain unverified and enforcement remains unsupported.

## 0.1.0 — 2026-10-10

- Initial educational implementation based on the associated SRS.
- Added bounded CLI functionality, security and architecture notes, and isolated smoke validation.
- Runtime and enforcement claims remain limited to the evidence recorded in `docs/TEST_RESULTS.md`.
