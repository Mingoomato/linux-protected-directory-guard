# Requirements Traceability — SRS-03

Latest scoped evidence: [2026-10-11 validation checkpoint](VALIDATION_CHECKPOINT.md). Historical pending/unverified rows below remain applicable to gates not exercised by that checkpoint.

The branch contains a previously verified unprivileged audit-only checkpoint plus a newer retrospective `FAN_CLOSE_WRITE` policy-evaluation change that has not been verified. It is not full SRS completion. Code presence and earlier unprivileged tests do not establish the new decision contract or privileged hook behavior.

| Requirement | Source / artifact | Verification | Status |
|---|---|---|---|
| PDG-FR-001 | `safe_scope`, canonical-root check | Broad alias and parser rejection cases | IMPLEMENTED (tested subset) |
| PDG-FR-002 | Audit default; explicit unsupported `enforce` | Smoke checks explain and enforce contract | IMPLEMENTED (audit only) |
| PDG-FR-003 | Bounded policy subset, duplicate/unknown/conflict checks | Parser regressions plus 2,000 seeded Clang libFuzzer iterations under ASan/UBSan; sustained fuzzing and coverage review pending | IN_PROGRESS |
| PDG-FR-004 | validate/explain/status/audit/enforce/disable commands | Smoke covers all except live audit | IN_PROGRESS |
| PDG-FR-005 | fanotify PID or unknown attribution in journal | Live event capture unavailable on host; newly added close-write policy decision is also unverified | IN_PROGRESS |
| PDG-FR-006 | path plus `st_dev` major/minor and inode from event FD | Code review; namespace, bind-mount and alias tests pending | IN_PROGRESS |
| PDG-FR-007 | event ID, policy ID/revision, reason, hook and mode fields | Prior explain contract checked; new `observed_event`, `policy_operation`, and `policy_evaluation` close-write fields and live journal remain unverified | IN_PROGRESS |
| PDG-FR-008 | `doctor` basic group probe; audit mount mark errors explicit | Host group probe unavailable; supported filesystem/capability matrix missing | IN_PROGRESS |
| PDG-FR-009 | Hook coverage limitations | `docs/HOOK_COVERAGE.md` | IMPLEMENTED (documentation) |
| PDG-FR-010 | `PDG_UNSUPPORTED_ENFORCEMENT`, `coverage=unsupported` | Smoke test confirms explicit unsupported result | IMPLEMENTED |
| PDG-FR-011 | Subject `any` only; self-event recursion guard | Journal event identity is filtered by device+inode; comparator unit-tested; privileged self-event path and administrator exception controls remain pending | IN_PROGRESS |
| PDG-FR-012 | Validate, dry-run, then swap one policy revision; keep last good state on error | Candidate parse/root compatibility/dry-run/swap helper tested for valid update, malformed update, changed roots, and duplicate revision; SIGHUP event-loop path remains VM-unverified | IN_PROGRESS |
| PDG-FR-013 | Overflow gap record; read/poll/write/path failures return degraded status | Metadata structural tests pass; live fault injection pending | IN_PROGRESS |
| PDG-FR-014 | `cmd_doctor` reports active LSM, `CONFIG_BPF_LSM`, kernel BTF, `bpftool` availability, preflight result, and whether a hook probe ran | `tests/smoke.sh` validates output types/enums; current host reported config enabled, BPF LSM active, BTF present, bpftool absent, preflight incomplete; hook probe explicitly not run because none selected | IMPLEMENTED_DIAGNOSTIC_PREFLIGHT_ONLY |
| PDG-FR-015 | Fanotify/BPF supported-operation matrix | `docs/HOOK_COVERAGE.md`; privileged positive/negative cases pending | IN_PROGRESS |
| PDG-FR-016 | Audit path filters event paths to exact root | 100 synthetic outside-root `policy explain` requests rejected; live event filtering and 100 real workload gate pending | IN_PROGRESS |
| PDG-FR-017 | Unknown audit decision, PID source, errno, hook, policy identity | Prior explain contract tested; new retrospective close-write allow/deny and schema contract are unverified; actual journal unavailable | IN_PROGRESS |
| PDG-FR-018 | mmap, kernel I/O, remote-change gaps | `docs/HOOK_COVERAGE.md` | IMPLEMENTED (documentation) |
| PDG-FR-019 | Optional atomic hot reload and rollback | Audit-only SIGHUP reload transaction implemented; no kernel policy/map application exists | IMPLEMENTED_AUDIT_ONLY |
| PDG-FR-020 | Input/event/log bounds and recovery procedure | Parser and duration bounds tested; latency and resource gates pending | IN_PROGRESS |
| PDG-FR-021 | Existing LSM coexistence experiment | Optional experiment not run | NOT_APPLICABLE_YET |
| PDG-NFR-01..07 | `docs/TEST_PLAN.md` | See `docs/TEST_RESULTS.md`; privileged and performance gates remain open | IN_PROGRESS |

## 한국어 상태 요약

정책 회귀와 2,000회 seeded parser fuzz smoke(ASan/UBSan), 비특권 메타데이터 테스트, reload candidate rollback 검사 및 100개 synthetic out-of-root CLI 거부는 통과했습니다. 이 100개는 실제 프로그램 workload나 fanotify event 검증이 아닙니다. fanotify 실이벤트와 log self-event 제외, 특권 mount mark, SIGHUP reload loop, 이벤트 오버플로 주입, namespace/alias 격리, BPF hook 부착, 200개 positive/negative fixture, 지속 fuzzing/coverage 및 성능 수치는 아직 확인하지 않았습니다. 관리자 test-tool 예외와 SRS 전체 MUST도 모두 구현된 상태가 아니므로 현재 구현과 SRS 전체 검증 상태는 부분 완료입니다. 감사 결과가 파일 차단을 뜻하지 않으며 `enforce`는 지원되지 않습니다.
