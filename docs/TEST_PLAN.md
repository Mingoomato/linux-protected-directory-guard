# Test Plan

## 한국어

### 자동 실행 가능한 비특권 게이트

- GCC Release와 Clang 빌드, CTest 전체 실행.
- 정상 정책 설명, JSON decision 계약, 우선순위와 잘못된 정책 거부 확인.
- 음수·문자 혼합·범위 초과 audit duration 거부 확인.
- fanotify metadata 버전, 길이, 예약 필드, 잘못된 버퍼 경계 단위 테스트.
- `doctor --json`의 fanotify errno, BPF 설정/활성 LSM/BTF/tooling 타입과 열거값을 검사하고 hook probe 미실행을 명시하는지 확인.
- ASan/UBSan 및 정적 분석.
- Clang libFuzzer를 임시 corpus directory에서 실행해 bounded policy parser crash/UB를 탐색.
- SIGHUP candidate reload helper에서 새 revision 적용, malformed candidate, root 변경, 중복 revision의 active-state rollback 확인.
- journal self-event identity comparator의 device/inode 경계 확인.

### 격리된 VM에서만 실행할 게이트

- fanotify group 및 mount mark, 권한/파일시스템별 오류 taxonomy 확인.
- 실이벤트 open/close 관찰, 이벤트 FD 수명, 보호 범위 밖 100 workload의 false-deny 0 확인.
- 이벤트 큐 오버플로, daemon 종료, log ENOSPC/권한 변경 주입 후 coverage gap/degraded 확인.
- symlink, hardlink, bind mount, mount/pid namespace 격리와 rename race 확인.
- protected root 안의 journal 자체 이벤트 억제와 실제 SIGHUP reload/journal 기록을 privileged event loop에서 검증.
- `CONFIG_BPF_LSM`, active LSM, BTF, bpftool을 읽기 전용으로 사전 점검. 아직 hook을 선정하지 않았으므로 실제 hook probe/attach는 미실행; enforcement를 구현한다면 hook마다 positive/negative 테스트.
- 각각 100개 allow/deny fixture와 지연(P50/P95/P99), CPU, RSS 측정.
- 재부팅/정지/복구 콘솔을 포함한 VM 복원 절차 확인.

### 실행 상태

현재 GCC/Clang Release와 Clang ASan/UBSan 빌드·CTest, 2,000회 seeded libFuzzer smoke, reload transaction unit test, 100개 synthetic out-of-root CLI 거부 및 정적 분석이 통과했습니다. `doctor`의 JSON 계약도 테스트했으며 현재 호스트는 bpftool 부재로 BPF 사전 점검이 incomplete입니다. 실제 privileged VM/fanotify event loop, parser 장시간 fuzzing/coverage, 이벤트 오류 주입, scope 격리 및 성능 게이트는 미실행입니다. hook probe는 선택된 hook이 없어 실행하지 않았습니다. 자세한 결과는 `docs/TEST_RESULTS.md`에 기록합니다.

## English

### Unprivileged gates

- Build with GCC Release and Clang; run the complete CTest suite.
- Check normal policy explanation, decision JSON contract, precedence, and malformed-policy rejection.
- Reject negative, mixed-character, and out-of-range audit durations.
- Unit-test fanotify metadata versions, lengths, reserved fields, and buffer boundaries.
- Check the `doctor --json` fanotify errno and BPF config/active-LSM/BTF/tooling types and enums, including its explicit no-hook-probe state.
- Run ASan/UBSan and static analysis.
- Run Clang libFuzzer against a temporary corpus directory to explore parser crashes and undefined behavior.
- Verify reload-transaction behavior for new revisions, malformed candidates, root changes, duplicate revisions, and active-state rollback.
- Check the journal self-event identity comparator's device/inode boundaries.

### Disposable-VM-only gates

- Check fanotify group creation and mount marking across privilege/filesystem conditions.
- Observe live open/close events, verify event-FD lifetimes, and confirm zero false denies for 100 out-of-scope workloads.
- Inject queue overflow, daemon exit, log ENOSPC, and permission changes; verify explicit coverage gap/degraded status.
- Exercise symlink, hardlink, bind mount, mount/pid namespace isolation, and rename races.
- Verify journal self-event suppression and real SIGHUP reload/journal output in the privileged event loop.
- Read-only preflight of `CONFIG_BPF_LSM`, active LSM, BTF, and bpftool. No hook is selected yet, so no hook probe or attach ran. If enforcement is implemented, add positive/negative tests per hook.
- Measure 100 allow/deny fixtures, P50/P95/P99 latency, CPU, and RSS.
- Verify VM restore after reboot/stop using the recovery console.

### Current status

GCC/Clang Release and Clang ASan/UBSan builds/CTest, a 2,000-run seeded libFuzzer smoke, reload-transaction unit test, 100 synthetic out-of-root CLI rejections, and static analysis passed. The `doctor` JSON contract is tested; the current host's BPF preflight is incomplete because bpftool is absent. Live privileged fanotify/SIGHUP behavior, sustained fuzzing/coverage, event fault injection, scope isolation, and performance gates have not run. No hook was selected, so hook probing did not run. See `docs/TEST_RESULTS.md`.
