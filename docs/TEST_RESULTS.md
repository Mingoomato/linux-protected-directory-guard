# Verification Results — Linux Protected Directory Guard

## 한국어

현재 호스트에서 비특권 정책 처리와 메타데이터 검사 단위 테스트를 실행했습니다. 이 결과는 SRS-03 전체 완료나 파일 접근 차단의 증거가 아닙니다.

아래 실행 기록은 `FAN_CLOSE_WRITE` 사후 policy-evaluation 코드와 schema 필드를 추가하기 전에 생성되었습니다. 최신 코드 변경은 요청에 따라 재검증하지 않았으며, 새 경로는 미검증입니다.

- GCC Release 구성·빌드: 통과.
- Release CTest: 3/3 통과 (`policy-audit-smoke`, `fanotify-metadata-validation`, `policy-reload-transaction`).
- Clang libFuzzer + ASan/UBSan 구성·빌드와 CTest: 4/4 통과. `policy-parser-fuzz-smoke`는 임시 corpus directory의 정상 seed에서 2,000회 변이 실행했습니다.
- Clang Release 구성·빌드와 CTest: 3/3 통과.
- Clang AddressSanitizer/UndefinedBehaviorSanitizer Debug 빌드와 CTest: 3/3 통과.
- `clang --analyze`: CLI, reload test, parser fuzz target, metadata test translation unit에서 진단 없이 완료.
- 정책 회귀: 중복 필드/ID/root, 알 수 없는 키, 정규화 후 광범위 root, 길이/누적 크기 초과, 충돌 범위, 가장 구체적인 동일 action 규칙 선택을 점검.
- `tests/policy_parser_fuzz.c`는 production parser translation unit을 직접 호출하는 선택형 libFuzzer target입니다. `@ROOT@` seed marker를 실행 시 임시 canonical 경로로 치환하고 입력마다 제한된 임시 policy 파일을 다시 씁니다. 2,000회 smoke는 crash/ASan/UBSan 탐지용이며 parser grammar의 전체 정확성이나 fuzz coverage 목표 달성을 뜻하지 않습니다.
- 정확히 100개의 기존 보호 root 밖 경로에 대해 `policy explain`이 JSON 결정을 내보내지 않고 거부하는 것을 확인했습니다. 이 synthetic CLI gate는 실제 정상 프로그램 100개의 fanotify false-deny 측정이나 kernel event path filter 시험을 대체하지 않습니다.
- 정책 reload transaction 단위 테스트: 유효 새 revision 적용 후 정책 결과가 바뀌는지, malformed policy·보호 root 변경·동일 revision이 현재 revision과 결과를 유지하는지 확인했습니다. 이 테스트는 SIGHUP 신호 전달, fanotify event loop, journal에 쓰는 reload record를 실행하지 않습니다.
- Journal self-event 방지 기준인 `(st_dev, st_ino)` 동일성 함수를 unit test했습니다. 실제 fanotify가 수집한 journal 이벤트를 억제하는 실행 경로는 privileged runtime에서 아직 확인하지 않았습니다.
- CLI 회귀: audit duration에 음수, 문자가 섞인 값, 정수 초과 값을 주면 fanotify를 열기 전에 `PDG_INVALID_ARGUMENT`를 반환.
- Draft 2020-12 JSON Schema 자체가 유효하고, 실제 `policy explain` 결과가 schema를 통과. CTest에서도 필수 키, `coverage` enum, `reason_code`, unknown actor, null errno, 따옴표가 포함된 경로 escape를 확인.
- 메타데이터 단위 테스트: 짧은 버퍼, 버전/길이 불일치, 잘못된 예약 필드와 주요 이벤트 마스크 분류를 확인.
- `doctor --json`: CTest가 fanotify errno, BPF 상태 필드의 타입/열거값, 미실행 hook probe, unsupported enforcement 계약을 검사합니다. 이 호스트에서는 group 생성 실패와 errno `EPERM`(종료 코드 3), `CONFIG_BPF_LSM=enabled`, active LSM의 `bpf` token, kernel BTF present, `bpftool` absent, preflight `incomplete`, probe `not_run_no_hook_selected`를 관찰했습니다. 이는 fanotify mount mark나 BPF hook attach를 검증하지 않습니다.

실행하지 않은 검증: 실제 fanotify 이벤트 수집과 mount mark, 큐 오버플로 주입, 로그 디스크 오류, 보호 경로 밖 실제 workload 100개, symlink/hardlink/bind mount 및 namespace 격리, BPF hook preflight/attach, privileged VM 테스트, 장시간 parser fuzzing/coverage 분석, 성능(P50/P95/P99·CPU·RSS). 권한이 필요한 항목은 SRS의 VM 격리 조건에 따라 이 호스트에서 실행하지 않았습니다.

`enforce`는 항상 `PDG_UNSUPPORTED_ENFORCEMENT`를 반환합니다. 프로젝트는 audit-only 부분 구현이며 SRS 전체 완료 상태가 아닙니다.

## English

Unprivileged policy processing and metadata validation tests ran on the current host. These results do not establish full SRS-03 completion or file-access blocking.

The execution record below predates the addition of retrospective `FAN_CLOSE_WRITE` policy evaluation and its schema fields. The latest code change was not re-verified, as requested; that path remains unverified.

- GCC Release configure/build: passed.
- Release CTest: 3/3 passed (`policy-audit-smoke`, `fanotify-metadata-validation`, `policy-reload-transaction`).
- Clang libFuzzer + ASan/UBSan configure/build and CTest: 4/4 passed. `policy-parser-fuzz-smoke` ran 2,000 mutations from a checked-in valid seed copied into a temporary corpus directory.
- Clang Release configure/build and CTest: 3/3 passed.
- Clang Debug build with AddressSanitizer/UndefinedBehaviorSanitizer and CTest: 3/3 passed.
- `clang --analyze`: completed without warnings, including event metadata length, version, and reserved-field checks.
- `clang --analyze` also completed without diagnostics for the CLI, reload test, parser fuzz target, and metadata test translation units.
- Policy regressions cover duplicate fields/IDs/roots, unknown keys, canonical broad-root aliases, line and total-size bounds, conflicting scopes, and most-specific same-action selection.
- `tests/policy_parser_fuzz.c` is an opt-in libFuzzer target that calls the production parser translation unit. It substitutes a temporary canonical path for `@ROOT@` and rewrites a bounded temporary policy file for each input. The 2,000-run smoke checks for crashes and sanitizer findings; it does not establish grammar completeness or a fuzz coverage target.
- Exactly 100 synthetic paths outside the protected root were rejected by `policy explain` without emitting a decision. This CLI check is not 100 real processes, a fanotify false-deny measurement, or a live kernel path-filter test.
- The policy reload transaction test applies a valid new revision, then verifies that a malformed policy, changed protected roots, or duplicate revision leaves the current revision and evaluation result intact. It does not exercise SIGHUP delivery, the fanotify event loop, or reload journal output.
- The `(st_dev, st_ino)` file-identity comparator used to suppress journal self-events has unit coverage. The live fanotify event suppression path remains unverified.
- CLI regressions reject negative, mixed-character, and overflowing audit durations with `PDG_INVALID_ARGUMENT` before opening fanotify.
- The Draft 2020-12 JSON Schema is valid, and an actual `policy explain` result passes it. CTest also checks required fields, coverage enum, reason code, unknown actor, null errno, and escaping of a quoted path.
- Metadata unit tests cover short buffers, version/length mismatches, invalid reserved fields, and key event-mask classifications.
- `doctor --json`: CTest checks the fanotify errno, BPF-state field types/enums, no-hook-probe state, and unsupported-enforcement contract. This host reported group-creation failure `EPERM` (exit 3), `CONFIG_BPF_LSM=enabled`, active `bpf` LSM, kernel BTF present, bpftool absent, preflight `incomplete`, and probe `not_run_no_hook_selected`. This does not verify a fanotify mount mark or BPF hook attachment.

Not run: the new close-write policy-evaluation and schema contract; live fanotify events and mount marks, journal self-event suppression at runtime, SIGHUP reload loop and journal output, queue-overflow injection, log disk errors, 100 real out-of-scope workloads, symlink/hardlink/bind-mount and namespace isolation, BPF hook preflight/attach, privileged VM tests, sustained parser fuzzing/coverage analysis, or P50/P95/P99/CPU/RSS measurements. Privileged cases were not run on this host under the SRS disposable-VM requirement.

`enforce` always returns `PDG_UNSUPPORTED_ENFORCEMENT`. This is a partial audit-only implementation, not full SRS completion.
