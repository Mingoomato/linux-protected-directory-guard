# Linux Internals Explained — Linux Protected Directory Guard

## fanotify notification vs permission events

`fanotify_init` creates a kernel notification group and returns a file descriptor. `fanotify_mark` associates a file, directory, mount, or filesystem with a mask of events. `read` returns packed `fanotify_event_metadata` records. A notification event is informational; if the kernel supplies an event FD, the receiving process must close it. A permission event is different: the listener must write an explicit allow/deny response. This repository uses `FAN_CLASS_NOTIF` and never sends permission responses.

Consequently, the `decision:"deny"` from `policy explain` is not an actual denial. Audit records use `decision:"unknown"` and `enforced:false`; this distinction is central to the safety model.

## Mount marks, event FDs, and path races

The implementation marks the containing mount because it is the supported observed scope in this prototype. That mark may be broader than the user-selected directory. The code resolves the supplied event FD through `/proc/self/fd/N`, then checks that the resolved path is equal to or beneath the canonical root before logging. This filtering reduces out-of-scope output but cannot eliminate rename races, bind mounts, namespaces, hard-link aliasing, or all path identity ambiguity.

The kernel event metadata can include a PID, but PID reuse and PID namespaces complicate long-term attribution. The log labels it `kernel_observed`, not verified identity. The implementation does not capture process start time or a pidfd.

## Privilege and support probes

Creating a fanotify group can succeed while adding a mount mark fails. The required capability and support vary with the event class, mount operation, user namespace, filesystem, and kernel configuration. `doctor` checks only basic group creation and reads the active LSM list; it does not prove that a particular hook can be attached or that a specific filesystem event is covered.

BPF LSM is a separate hook system. Listing `bpf` in `/sys/kernel/security/lsm` indicates the LSM is active, not that a program was loaded or that a selected hook is enforced. A safe BPF extension needs kernel config, BTF, a considered hook matrix, and VM tests.

## Failure and coverage semantics

Queue overflow, unsupported filesystems, permission errors, unmounts, log write errors, and event FD resolution failure can all create gaps. The service must report coverage as degraded or unsupported instead of silently continuing as though every operation was observed. The current implementation has only basic unsupported errors; it has not been verified under privileged fault cases.

## Official references

- [`fanotify(7)`](https://man7.org/linux/man-pages/man7/fanotify.7.html), [`fanotify_init(2)`](https://man7.org/linux/man-pages/man2/fanotify_init.2.html), [`fanotify_mark(2)`](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)
- [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [BPF LSM programs](https://docs.kernel.org/bpf/prog_lsm.html) and [LSM usage](https://docs.kernel.org/admin-guide/LSM/index.html)
- [Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html)
- [procfs documentation](https://docs.kernel.org/filesystems/proc.html)
