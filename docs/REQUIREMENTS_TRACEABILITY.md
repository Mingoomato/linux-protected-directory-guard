# Requirements traceability (SRS-03)

Code presence is not full requirement verification. The unprivileged policy smoke test passed; privileged fanotify and VM checks remain unverified. See `docs/TEST_RESULTS.md`.

| Requirement | Source / artifact | Verification | Status |
|---|---|---|---|
| PDG-FR-001 | safe_scope canonical broad-root recheck, roots/scope validation | `tests/policy_validation.py` broad alias case | IMPLEMENTED |
| PDG-FR-002 | audit-only default; enforce refuses | tests/smoke.sh (audit-only explain) | IMPLEMENTED |
| PDG-FR-003 | parse_policy field masks, root/rule collision checks, explicit scope precedence | `tests/policy_validation.py` duplicate/unknown/overlap cases; fuzzing pending | IN_PROGRESS |
| PDG-FR-004 | CLI dispatch | smoke covers policy validate/explain, status, disable, enforce | IN_PROGRESS |
| PDG-FR-005 | fanotify metadata PID or unknown | PDG-T-005 pending | IN_PROGRESS |
| PDG-FR-006 | root canonicalization and mount filtering | PDG-T-007 pending | IN_PROGRESS |
| PDG-FR-007 | revision and reason fields | PDG-T-005 pending | IMPLEMENTED |
| PDG-FR-008 | doctor + mount mark probe during audit | PDG-T-003 pending | IN_PROGRESS |
| PDG-FR-009 | docs and audit-only decision | PDG-T-006 pending | IMPLEMENTED |
| PDG-FR-010 | enforce explicit unsupported error | tests/smoke.sh (unsupported enforcement) | IMPLEMENTED |
| PDG-FR-011 | subject any; no recursive event source | PDG-T-007 pending | IN_PROGRESS |
| PDG-FR-012 | policy immutable per process; no hot swap | PDG-T-009 pending | NOT_STARTED |
| PDG-FR-013 | error return on registration/read failure | PDG-T-008 pending | IN_PROGRESS |
| PDG-FR-014 | active LSM report in doctor | PDG-T-004 pending | IN_PROGRESS |
| PDG-FR-015 | docs/HOOK_COVERAGE.md | privileged hook tests pending | IN_PROGRESS |
| PDG-FR-016 | no enforcement in this build | PDG-T-010 pending | NOT_STARTED |
| PDG-FR-017 | event decision fields | PDG-T-005 pending | IN_PROGRESS |
| PDG-FR-018 | docs/HOOK_COVERAGE.md | documentation review pending | IMPLEMENTED |
| PDG-FR-019 | — | no hot reload | NOT_STARTED |
| PDG-FR-020 | fixed input bounds | resource tests pending | IN_PROGRESS |
| PDG-FR-021 | — | not applicable | NOT_APPLICABLE |
| PDG-NFR-01..07 | docs/TEST_PLAN.md | not run | NOT_STARTED |
