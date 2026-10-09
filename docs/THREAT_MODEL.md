# Threat model

## Policy inputs

Policy files are untrusted. The parser limits total bytes, line length, root/rule count, rejects tabs and unsupported syntax, requires absolute existing roots, rejects broad roots, and checks each scope remains inside a declared root.

## Runtime controls

- Default policy mode is audit. Enforcement is explicitly unsupported.
- Audit does not request permission decisions and cannot block file operations.
- Mount-level notifications are filtered to the exact configured root before the path is written to the log.
- Logs use restrictive file mode and are local by default.
- Events and decisions distinguish unknown/audit_only from an enforced outcome.

## Residual risks

Fanotify requires privileges and may not be supported on all filesystems. The mount mark has broader observation scope than the lab path, although emitted events are filtered. A path can be renamed between observation and path resolution. This version does not handle all namespace, hardlink, bind-mount, mmap, unlink, or rename semantics. A privileged attacker can alter the binary, policy, or logs.
