# Hook coverage

| Operation | Current backend | Decision data | Enforced |
|---|---|---|---|
| Open notification | fanotify FAN_OPEN | path, `st_dev` major/minor, inode, event mask, PID value and PID source if supplied; policy decision remains unknown | No |
| Close after write | fanotify FAN_CLOSE_WRITE | path, device/inode identity, and event mask | No |
| Queue overflow | fanotify `FAN_Q_OVERFLOW` | explicit `coverage:gap`, unknown actor, and overflow reason; audit exits degraded | No |
| Monitor stop | signal or requested duration | policy revision and explicit stop reason in the journal | No |
| Open permission | not implemented | unsupported | No |
| Write authorization | not implemented | unsupported | No |
| Rename/unlink authorization | not implemented | unsupported | No |
| mmap and kernel-internal I/O | not covered | coverage gap | No |
| BPF LSM | read-only `doctor` preflight; no program loaded | active LSM, `CONFIG_BPF_LSM`, `/sys/kernel/btf/vmlinux`, `bpftool` availability, preflight status; hook probe is `not_run_no_hook_selected` | No |

`doctor` may report an incomplete preflight when any kernel config, active-LSM, BTF, or tooling evidence is missing. A ready preflight still does not prove a specific hook is attachable; hook selection and privileged disposable-VM operation tests remain separate gates.
