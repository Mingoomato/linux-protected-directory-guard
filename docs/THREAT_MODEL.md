# Threat model

## Policy inputs

Policy files are untrusted. The parser limits total bytes, line length, root/rule count, rejects tabs and unsupported syntax, requires absolute existing roots, rejects broad roots, and checks each scope remains inside a declared root.

## Runtime controls

- Default policy mode is audit. Enforcement is explicitly unsupported.
- Audit does not request permission decisions and cannot block file operations.
- Mount-level notifications are filtered to the exact configured root before the path is written to the log.
- The append-only audit journal refuses a final-component symlink, requires a regular file owned by the current UID, and applies mode `0600`.
- Path/device/inode and fanotify PID source remain distinct fields; PID and pathname are observations, not durable identity proofs.
- Events and decisions distinguish unknown/audit_only from an enforced outcome.
- Queue overflow, malformed event metadata, path/read/poll failures, and journal failures stop the run with an explicit gap or degraded result.

## Residual risks

Fanotify requires privileges and may not be supported on all filesystems. The mount mark has broader observation scope than the lab path, although emitted events are filtered. A path can be renamed between observation and path resolution. This version does not handle all namespace, hardlink, bind-mount, mmap, unlink, or rename semantics. A privileged attacker can alter the binary, policy, or logs.

The filename returned through `/proc/self/fd` can change between event delivery and lookup. `st_dev`/inode values can be reused and do not encode a mount-namespace-stable identity. Fanotify event PID does not include this implementation's UID or process start-time evidence. If the log filesystem is full or becomes unwritable, coverage is degraded but the error itself may only reach stderr because the journal cannot be updated.
