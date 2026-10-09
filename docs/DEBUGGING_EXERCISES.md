# Debugging and Independent Reproduction Exercises

These exercises are unsolved; no implementation or patch is included. Use a private temporary lab directory. Do not try enforcement on a shared host.

## Exercise 1 — Policy parser boundary cases

**Goal:** Reproduce parser behavior for duplicate keys, missing fields, long lines, too many rules, and scope escape.

**Starting points:** `parse_policy`, `safe_scope`, `path_within`, `tests/smoke.sh`.

Create one policy per invalid case, assert stable error status and message category, and add tests for path-boundary confusion (for example, a sibling whose name shares the root prefix). Decide which cases should be rejected before any audit descriptor is opened.

**Constraints:** Keep the parser subset explicit. Unknown syntax must fail closed. Tests must not depend on a real protected system directory.

**Acceptance:** Every malformed policy is rejected, and a valid nested scope is accepted only beneath a declared root.

## Exercise 2 — Safe fanotify audit event lifetime

**Goal:** Audit each exit path for the event FD returned in `fanotify_event_metadata`.

**Starting points:** `cmd_audit`, metadata validation, `/proc/self/fd` resolution, and `fanotify(7)`.

Build a review table for invalid metadata, `readlink` error, out-of-root event, path truncation, partial log write, signal shutdown, and poll/read error. Add a test seam or small parsing unit that proves every supplied event FD is closed exactly once and output failure cannot be labeled as complete coverage.

**Constraints:** Do not enable permission events or reply allow/deny. Run real mount-mark checks only in a disposable VM.

**Acceptance:** The code and tests account for all acquired FDs; error cases produce an explicit failure/degraded result.

## Exercise 3 — Policy precedence and immutable revision

**Goal:** Make overlapping allow/deny rules and policy revision behavior auditable.

**Starting points:** `evaluate`, `policy explain`, policy revision field, `docs/ADR/ADR-001-audit-only-baseline.md`.

Add table-driven cases for no match, default action, allow-only, deny-only, and overlapping rules. Specify how a winning rule ID is selected when several denies match. Sketch and test a validate→dry-run→atomic revision swap for a future reload mode without enabling enforcement.

**Constraints:** A policy decision must retain `enforced:false`. No hot-reload path may partially replace the active policy.

**Acceptance:** Every explain response identifies a deterministic rule/reason and policy revision; failed validation leaves the prior revision active.

## Owner attempt record

Write down the exercise attempted, test evidence, security boundary, and remaining uncertainty. Owner reproduction status is **not yet evidenced**; automated tests do not establish personal mastery.
