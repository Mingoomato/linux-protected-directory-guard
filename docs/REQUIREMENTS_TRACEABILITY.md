# Requirements Traceability — SRS-03

The current branch is a verified unprivileged audit-only checkpoint, not full SRS completion. Code presence and unprivileged tests do not establish privileged hook behavior.

| Requirement | Source / artifact | Verification | Status |
|---|---|---|---|
| PDG-FR-001 | `safe_scope`, canonical-root check | Broad alias and parser rejection cases | IMPLEMENTED (tested subset) |
| PDG-FR-002 | Audit default; explicit unsupported `enforce` | Smoke checks explain and enforce contract | IMPLEMENTED (audit only) |
| PDG-FR-003 | Bounded policy subset, duplicate/unknown/conflict checks | Parser regression cases; fuzz still pending | IN_PROGRESS |
| PDG-FR-004 | validate/explain/status/audit/enforce/disable commands | Smoke covers all except live audit | IN_PROGRESS |
| PDG-FR-005 | fanotify PID or unknown attribution in journal | Live event capture unavailable on host | IN_PROGRESS |
| PDG-FR-006 | path plus `st_dev` major/minor and inode from event FD | Code review; namespace, bind-mount and alias tests pending | IN_PROGRESS |
| PDG-FR-007 | event ID, policy ID/revision, reason, hook and mode fields | Explain contract checked; live event contract untested | IN_PROGRESS |
| PDG-FR-008 | `doctor` basic group probe; audit mount mark errors explicit | Host group probe unavailable; supported filesystem/capability matrix missing | IN_PROGRESS |
| PDG-FR-009 | Hook coverage limitations | `docs/HOOK_COVERAGE.md` | IMPLEMENTED (documentation) |
| PDG-FR-010 | `PDG_UNSUPPORTED_ENFORCEMENT`, `coverage=unsupported` | Smoke test confirms explicit unsupported result | IMPLEMENTED |
| PDG-FR-011 | Subject `any` only; no recursion/exception controls | Recursive self-event and exception behavior not implemented | NOT_STARTED |
| PDG-FR-012 | Policy parsed into a candidate object before command use; no live reload | No reload/swap or rollback path exists | NOT_STARTED |
| PDG-FR-013 | Overflow gap record; read/poll/write/path failures return degraded status | Metadata structural tests pass; live fault injection pending | IN_PROGRESS |
| PDG-FR-014 | Active LSM name reported by `doctor` | Local LSM list observed; CONFIG/BTF/tooling preflight missing | IN_PROGRESS |
| PDG-FR-015 | Fanotify/BPF supported-operation matrix | `docs/HOOK_COVERAGE.md`; privileged positive/negative cases pending | IN_PROGRESS |
| PDG-FR-016 | Audit path filters event paths to exact root | No 100-workload outside-scope negative gate run | IN_PROGRESS |
| PDG-FR-017 | Unknown audit decision, PID source, errno, hook, policy identity | Explain contract tested; actual journal unavailable | IN_PROGRESS |
| PDG-FR-018 | mmap, kernel I/O, remote-change gaps | `docs/HOOK_COVERAGE.md` | IMPLEMENTED (documentation) |
| PDG-FR-019 | Optional atomic hot reload and rollback | No hot reload implemented | NOT_IMPLEMENTED |
| PDG-FR-020 | Input/event/log bounds and recovery procedure | Parser and duration bounds tested; latency and resource gates pending | IN_PROGRESS |
| PDG-FR-021 | Existing LSM coexistence experiment | Optional experiment not run | NOT_APPLICABLE_YET |
| PDG-NFR-01..07 | `docs/TEST_PLAN.md` | See `docs/TEST_RESULTS.md`; privileged and performance gates remain open | IN_PROGRESS |

## 한국어 상태 요약

정책 검증과 비특권 메타데이터 테스트는 통과했습니다. fanotify 실이벤트, 특권 mount mark, 이벤트 오버플로 주입, namespace/alias 격리, BPF hook 부착, 200개 positive/negative fixture, 성능 수치는 아직 확인하지 않았습니다. 따라서 현재 구현과 SRS 전체 검증 상태는 모두 부분 완료입니다. 감사 결과가 파일 차단을 뜻하지 않으며 `enforce`는 지원되지 않습니다.
