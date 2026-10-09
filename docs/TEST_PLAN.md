# Test plan

- Compile with GCC and Clang; verify policy sample validation and policy explain precedence.
- Reject broad roots, duplicate IDs, unknown YAML keys, malformed entries, and out-of-root scopes.
- Exercise doctor on fanotify/BPF LSM available and unavailable kernels.
- In a disposable VM, confirm audit produces observations without blocking; confirm unsupported permission mediation and enforce never claim success.
- Use an out-of-scope path on the same mount and confirm it is not written to the audit log.
- Exercise daemon termination, queue/disk errors, path rename races, bind mounts, and policy parser fuzz inputs.

The build and unprivileged policy smoke test have been run. Fanotify/runtime, hook, fuzz, sanitizer, and performance tests remain pending. Privileged tests require a disposable VM and recovery console.
