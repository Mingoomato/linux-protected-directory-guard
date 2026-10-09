# Debugging and Independent Reproduction Exercises

These exercises are unsolved; no implementation or patch is included. Use a private temporary lab directory. Do not try enforcement on a shared host.

## Exercise 1 — Enforcing parser bounds before allocation

**Goal:** Make the policy reader stop oversized input before an unbounded line allocation occurs.

**Starting points:** `parse_policy`, `MAX_POLICY_BYTES`, `MAX_LINE`, the `getline` buffer, and `tests/policy_validation.py`.

Replace or wrap the current line read with a bounded reader. Test a line exactly at the limit, a line one byte over, cumulative size overflow, a final line without a newline, and an I/O error. Confirm failures include a useful line number and happen before policy application.

**Constraints:** Keep the parser subset explicit. Unknown syntax must fail closed. Do not add an unrestricted YAML dependency or allocate based on attacker-controlled line length.

**Acceptance:** Oversized input is rejected without retaining an oversized line buffer; boundary and error tests are deterministic.

## Exercise 2 — Safe fanotify audit event lifetime

**Goal:** Audit each exit path for the event FD returned in `fanotify_event_metadata`.

**Starting points:** `cmd_audit`, metadata validation, `/proc/self/fd` resolution, and `fanotify(7)`.

Build a review table for invalid metadata, `readlink` error, out-of-root event, path truncation, partial log write, signal shutdown, and poll/read error. Add a test seam or small parsing unit that proves every supplied event FD is closed exactly once and output failure cannot be labeled as complete coverage.

**Constraints:** Do not enable permission events or reply allow/deny. Run real mount-mark checks only in a disposable VM.

**Acceptance:** The code and tests account for all acquired FDs; error cases produce an explicit failure/degraded result.

## Exercise 3 — Atomic policy revision swap

**Goal:** Design a reloadable policy owner that never exposes a partially validated revision.

**Starting points:** `parse_policy`, `struct policy`, `policy_revision`, `docs/ADR/ADR-001-audit-only-baseline.md`, and the validate→dry-run→swap SRS requirement.

Build a small isolated policy-holder abstraction that parses into a candidate, validates it, runs a dry-run against fixtures, and swaps the active immutable object only after every step succeeds. Test a malformed candidate, a dry-run failure, and a successful higher revision. Do not connect the abstraction to live fanotify enforcement.

**Constraints:** A policy decision must retain `enforced:false`. No hot-reload path may partially replace the active policy.

**Acceptance:** Failed parse or dry-run leaves the old policy pointer/revision intact; a successful swap exposes the new revision as one atomic state change.

## Owner attempt record

Write down the exercise attempted, test evidence, security boundary, and remaining uncertainty. Owner reproduction status is **not yet evidenced**; automated tests do not establish personal mastery.
