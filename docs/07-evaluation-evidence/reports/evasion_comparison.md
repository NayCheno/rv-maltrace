# Evasion Comparison Summary

Status: `PASS_HARDWARE_BACKED_ANTI_DEBUG_EVASION_COMPARISON`

| Sample | Software baseline outcome | RV-MalTrace reconstruction | Verdict |
| --- | --- | --- | --- |
| `anti_debug_like` | strace visible / ptrace perturbed | clock_gettime, ptrace, openat, read, close; hardware ARG_MEM: /proc/self/status | `PASS_SOFTWARE_TRACER_FAILS_RVMT_RECONSTRUCTS` |
| `process_chain` | no software failure demonstrated | clone, execve, waitid | `PASS_RVMT_RECONSTRUCTS_NO_SOFTWARE_FAILURE_DEMONSTRATED` |
| `dynamic_executable_memory` | no software failure demonstrated | mmap, mprotect, munmap | `PASS_RVMT_RECONSTRUCTS_NO_SOFTWARE_FAILURE_DEMONSTRATED` |

## Claim Boundary

- This summary supports one complete hardware-backed failure row: `anti_debug_like`.
- Other rows are supporting reconstruction evidence, not software-tracer failure claims.
- QEMU and strace outputs are comparison oracles only.
- This is controlled safe-workload evidence, not real-malware validation or malware detection accuracy.
