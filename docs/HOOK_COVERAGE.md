# Hook coverage

| Operation | Current backend | Decision data | Enforced |
|---|---|---|---|
| Open notification | fanotify FAN_OPEN | observed path, event mask, PID if supplied; policy decision remains unknown | No |
| Close after write | fanotify FAN_CLOSE_WRITE | observed path and event mask | No |
| Open permission | not implemented | unsupported | No |
| Write authorization | not implemented | unsupported | No |
| Rename/unlink authorization | not implemented | unsupported | No |
| mmap and kernel-internal I/O | not covered | coverage gap | No |
| BPF LSM | diagnostic probe only | active-LSM indicator | No |
