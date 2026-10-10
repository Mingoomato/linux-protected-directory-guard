# Test Plan

## 한국어

### 자동 실행 가능한 비특권 게이트

- GCC Release와 Clang 빌드, CTest 전체 실행.
- 정상 정책 설명, JSON decision 계약, 우선순위와 잘못된 정책 거부 확인.
- 음수·문자 혼합·범위 초과 audit duration 거부 확인.
- fanotify metadata 버전, 길이, 예약 필드, 잘못된 버퍼 경계 단위 테스트.
- ASan/UBSan 및 정적 분석.

### 격리된 VM에서만 실행할 게이트

- fanotify group 및 mount mark, 권한/파일시스템별 오류 taxonomy 확인.
- 실이벤트 open/close 관찰, 이벤트 FD 수명, 보호 범위 밖 100 workload의 false-deny 0 확인.
- 이벤트 큐 오버플로, daemon 종료, log ENOSPC/권한 변경 주입 후 coverage gap/degraded 확인.
- symlink, hardlink, bind mount, mount/pid namespace 격리와 rename race 확인.
- `CONFIG_BPF_LSM`, active LSM, BTF, bpftool 및 선정 hook의 실제 사전 점검. enforcement를 구현한다면 hook마다 positive/negative 테스트.
- 각각 100개 allow/deny fixture와 지연(P50/P95/P99), CPU, RSS 측정.
- 재부팅/정지/복구 콘솔을 포함한 VM 복원 절차 확인.

### 실행 상태

현재 비특권 빌드·회귀·메타데이터 경계 테스트는 통과했습니다. privileged VM, parser fuzz, 이벤트 오류 주입, scope 격리 및 성능 게이트는 미실행입니다. 자세한 결과는 `docs/TEST_RESULTS.md`에 기록합니다.

## English

### Unprivileged gates

- Build with GCC Release and Clang; run the complete CTest suite.
- Check normal policy explanation, decision JSON contract, precedence, and malformed-policy rejection.
- Reject negative, mixed-character, and out-of-range audit durations.
- Unit-test fanotify metadata versions, lengths, reserved fields, and buffer boundaries.
- Run ASan/UBSan and static analysis.

### Disposable-VM-only gates

- Check fanotify group creation and mount marking across privilege/filesystem conditions.
- Observe live open/close events, verify event-FD lifetimes, and confirm zero false denies for 100 out-of-scope workloads.
- Inject queue overflow, daemon exit, log ENOSPC, and permission changes; verify explicit coverage gap/degraded status.
- Exercise symlink, hardlink, bind mount, mount/pid namespace isolation, and rename races.
- Preflight `CONFIG_BPF_LSM`, active LSM, BTF, bpftool, and selected hooks. If enforcement is implemented, add positive/negative tests per hook.
- Measure 100 allow/deny fixtures, P50/P95/P99 latency, CPU, and RSS.
- Verify VM restore after reboot/stop using the recovery console.

### Current status

Unprivileged build, regression, and metadata-boundary tests passed. Privileged VM, parser fuzzing, event fault injection, scope isolation, and performance gates have not run. See `docs/TEST_RESULTS.md`.
