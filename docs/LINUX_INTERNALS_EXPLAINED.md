# Linux Internals Explained — Linux Protected Directory Guard

## 한국어

### fanotify 알림과 permission event

`fanotify_init(2)`는 kernel notification group을 만들고 file descriptor를 반환합니다. `fanotify_mark(2)`는 파일/디렉터리/mount/filesystem과 event mask를 연결합니다. `read(2)`는 `fanotify_event_metadata` 레코드 묶음을 전달합니다. `FAN_CLASS_NOTIF`는 관찰용입니다. permission class의 `FAN_OPEN_PERM` 등은 요청을 대기시키고 listener가 response를 써야 합니다. 이 프로젝트는 permission class도 response도 사용하지 않습니다.

따라서 `policy explain`의 `decision:"deny"`는 rule 평가 결과에 불과합니다. 실 이벤트는 정책 집행 의미의 allow/deny를 계산하지 않으며 `decision:"unknown"`, `enforced:false`로 저널링합니다.

### mount mark, event FD, path와 identity

`FAN_MARK_MOUNT`는 설정한 하위 디렉터리보다 넓은 mount를 관찰할 수 있습니다. event metadata가 준 event FD에 `/proc/self/fd/N`을 사용해 kernel이 가리키는 당시의 이름을 읽고 문자열 기준 root filter를 적용합니다. 이 filter는 로그 범위를 줄이지만 rename race, hardlink 별칭, bind mount, mount namespace 해석 또는 경로 변화를 막지는 않습니다.

`fstat(event_fd)`에서 나온 `st_dev` major/minor와 inode는 file object identity에 가까운 순간 관측값으로 path와 별도 필드에 기록합니다. 이는 영구 ID가 아닙니다. 삭제/재생성으로 inode가 재사용될 수 있습니다. `readlink` 경로는 관측 시점의 이름이며 파일 identity가 아닙니다.

`fanotify_event_metadata.pid`는 이벤트를 유발한 프로세스 PID 필드입니다. 로그는 이를 `fanotify_event_metadata.pid` 출처와 함께 기록하며 verified actor 또는 영구 프로세스 신원으로 부르지 않습니다. PID namespace, 재사용, UID 부재, 시작 시간 부재를 고려해야 합니다.

### metadata 경계와 FD 수명

한 번의 `read`에는 packed metadata record 여러 개가 들어올 수 있습니다. 각 record의 `vers`, 예약 필드, `event_len`, `metadata_len`을 남은 read 길이와 비교하지 않으면 범위 밖 접근이나 무한 반복이 생길 수 있습니다. 구현의 `metadata_record_valid`는 이 구조적 조건을 검사하고 단위 테스트가 잘못된 길이를 거부합니다.

fanotify가 제공한 유효한 `meta->fd`는 수신 프로그램이 소유합니다. root 밖 이벤트를 필터링하거나 `readlink`/`fstat`/저널 쓰기에 실패해도 반드시 닫아야 합니다. `FAN_Q_OVERFLOW`는 파일 FD 대신 queue gap을 나타내므로, 저널에 `coverage:"gap"`을 쓰고 monitor를 degraded 상태로 끝냅니다.

### 권한, filesystem 및 BPF LSM 진단

group 생성 성공과 mount mark 성공은 별개의 capability/권한 및 filesystem 지원 단계입니다. `doctor`의 기본 group probe는 mount mark나 실 이벤트를 증명하지 않습니다. `FAN_MARK_MOUNT`가 지원되는지와 어떤 filesystem에서 이벤트가 오는지는 privileged VM에서 확인해야 합니다.

`/sys/kernel/security/lsm`에 `bpf`가 있어도 특정 BPF program이 verifier를 통과하거나 hook에 attach/작동한다는 뜻은 아닙니다. `CONFIG_BPF_LSM`, BTF, bpftool/probe 결과, hook signature 및 실제 positive/negative workload가 필요합니다. 이 저장소는 BPF를 load하지 않습니다.

### 오류와 coverage 의미

fanotify group/mount mark 거부는 unsupported 또는 insufficient privilege입니다. queue overflow, malformed metadata, event path 불가, poll/read/log 실패는 이미 관찰 누락이 발생했거나 가능하므로 0 종료의 정상 complete로 처리하지 않습니다. 로그를 쓸 수 없는 디스크 오류는 stderr와 비정상 종료로 나타내며, 그 오류를 journal에 쓰겠다고 보장할 수 없습니다. Audit 종료 시 이유를 journal에 남기지만 시스템 종료나 강제 kill은 종료 레코드를 쓸 기회가 없을 수 있습니다.

### 공식 문서

- [`fanotify(7)`](https://man7.org/linux/man-pages/man7/fanotify.7.html), [`fanotify_init(2)`](https://man7.org/linux/man-pages/man2/fanotify_init.2.html), [`fanotify_mark(2)`](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)
- [Linux kernel fanotify guide](https://docs.kernel.org/6.15/admin-guide/filesystem-monitoring.html), [kernel procfs guide](https://docs.kernel.org/filesystems/proc.html)
- [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html), [`read(2)`](https://man7.org/linux/man-pages/man2/read.2.html), [`fstat(2)`](https://man7.org/linux/man-pages/man2/stat.2.html), [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html), [Linux LSM usage](https://docs.kernel.org/admin-guide/LSM/index.html), [Landlock](https://docs.kernel.org/userspace-api/landlock.html), [procfs](https://docs.kernel.org/filesystems/proc.html)

## English

`fanotify_init(2)` creates a notification group; `fanotify_mark(2)` associates a mask with an object or mount; `read(2)` returns packed `fanotify_event_metadata` records. `FAN_CLASS_NOTIF` is informational. Permission events require a response and have separate failure semantics. This repository uses notification events only and never replies allow/deny.

A policy `deny` is not an access denial. Live notification records use `decision:"unknown"` and `enforced:false`. Mount marks can observe a wider scope than the configured directory. The observer resolves the event FD through `/proc/self/fd/N` and filters the path, which reduces extra logging but does not solve rename races, hard links, bind mounts, mount namespace identity, or path ambiguity.

The journal records path separately from event-FD `fstat` device major/minor and inode. These values identify the observed file object at that moment, not a permanent ID. The PID is recorded with its `fanotify_event_metadata.pid` source; it is not a verified durable process identity and UID is not collected.

The event loop checks metadata version, reserved fields, `event_len`, and `metadata_len` against bytes remaining after `read`. Valid event FDs are closed by the receiver on success, filtering, and error paths. `FAN_Q_OVERFLOW` means coverage was lost: the monitor records a `coverage:"gap"` reason and exits degraded. Poll/read/path/log failures likewise cannot be called a complete successful audit.

Basic fanotify group creation does not prove mount-mark permission or filesystem event support. Seeing `bpf` in `/sys/kernel/security/lsm` does not prove a specific BPF hook is attachable or effective; `CONFIG_BPF_LSM`, BTF, tools, hook signatures, and workload tests matter. No BPF program is loaded here. See the Korean section for official references, also linked by system-call and kernel topic.
