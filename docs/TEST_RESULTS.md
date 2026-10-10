# Verification Results — Linux Protected Directory Guard

## 한국어

현재 호스트에서 비특권 정책 처리와 메타데이터 검사 단위 테스트를 실행했습니다. 이 결과는 SRS-03 전체 완료나 파일 접근 차단의 증거가 아닙니다.

- GCC Release 구성·빌드: 통과.
- Release CTest: 2/2 통과 (`policy-audit-smoke`, `fanotify-metadata-validation`).
- Clang Release 구성·빌드와 CTest: 2/2 통과.
- Clang AddressSanitizer/UndefinedBehaviorSanitizer Debug 빌드와 CTest: 2/2 통과.
- `clang --analyze`: 메타데이터 길이 경계, 버전, 예약 필드 검증을 포함해 경고 없이 완료.
- 정책 회귀: 중복 필드/ID/root, 알 수 없는 키, 정규화 후 광범위 root, 길이/누적 크기 초과, 충돌 범위, 가장 구체적인 동일 action 규칙 선택을 점검.
- CLI 회귀: audit duration에 음수, 문자가 섞인 값, 정수 초과 값을 주면 fanotify를 열기 전에 `PDG_INVALID_ARGUMENT`를 반환.
- Draft 2020-12 JSON Schema 자체가 유효하고, 실제 `policy explain` 결과가 schema를 통과. CTest에서도 필수 키, `coverage` enum, `reason_code`, unknown actor, null errno, 따옴표가 포함된 경로 escape를 확인.
- 메타데이터 단위 테스트: 짧은 버퍼, 버전/길이 불일치, 잘못된 예약 필드와 주요 이벤트 마스크 분류를 확인.
- `doctor --json`: 이 호스트에서 fanotify group 생성은 불가능(종료 코드 3), BPF LSM은 활성 목록에 나타났습니다. 이는 개별 fanotify mount mark나 BPF hook을 검증하지 않습니다.

실행하지 않은 검증: 실제 fanotify 이벤트 수집과 mount mark, 큐 오버플로 주입, 로그 디스크 오류, 보호 경로 밖 100개 workload, symlink/hardlink/bind mount 및 namespace 격리, BPF hook preflight/attach, privileged VM 테스트, parser fuzzing, 성능(P50/P95/P99·CPU·RSS). 권한이 필요한 항목은 SRS의 VM 격리 조건에 따라 이 호스트에서 실행하지 않았습니다.

`enforce`는 항상 `PDG_UNSUPPORTED_ENFORCEMENT`를 반환합니다. 프로젝트는 audit-only 부분 구현이며 SRS 전체 완료 상태가 아닙니다.

## English

Unprivileged policy processing and metadata validation tests ran on the current host. These results do not establish full SRS-03 completion or file-access blocking.

- GCC Release configure/build: passed.
- Release CTest: 2/2 passed (`policy-audit-smoke`, `fanotify-metadata-validation`).
- Clang Release configure/build and CTest: 2/2 passed.
- Clang Debug build with AddressSanitizer/UndefinedBehaviorSanitizer and CTest: 2/2 passed.
- `clang --analyze`: completed without warnings, including event metadata length, version, and reserved-field checks.
- Policy regressions cover duplicate fields/IDs/roots, unknown keys, canonical broad-root aliases, line and total-size bounds, conflicting scopes, and most-specific same-action selection.
- CLI regressions reject negative, mixed-character, and overflowing audit durations with `PDG_INVALID_ARGUMENT` before opening fanotify.
- The Draft 2020-12 JSON Schema is valid, and an actual `policy explain` result passes it. CTest also checks required fields, coverage enum, reason code, unknown actor, null errno, and escaping of a quoted path.
- Metadata unit tests cover short buffers, version/length mismatches, invalid reserved fields, and key event-mask classifications.
- `doctor --json`: fanotify group creation was unavailable on this host (exit 3); BPF LSM appeared in the active list. This does not verify a particular fanotify mount mark or BPF hook.

Not run: live fanotify events and mount marks, queue-overflow injection, log disk errors, 100 out-of-scope workloads, symlink/hardlink/bind-mount and namespace isolation, BPF hook preflight/attach, privileged VM tests, parser fuzzing, or P50/P95/P99/CPU/RSS measurements. Privileged cases were not run on this host under the SRS disposable-VM requirement.

`enforce` always returns `PDG_UNSUPPORTED_ENFORCEMENT`. This is a partial audit-only implementation, not full SRS completion.
