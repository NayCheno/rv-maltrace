# Behavior Audit Report

- Source semantic artifact: `results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610/illegal_trap/hardware_trace/trace.jsonl`
- Behavior graph nodes: 43
- Behavior graph edges: 43
- Sample: `illegal_trap`
- Expected behaviors: illegal_instruction_trap
- Expected behaviors matched: none
- Weak expected evidence: illegal_instruction_trap
- Weak expected behavior shapes: none
- Expected behaviors missing: illegal_instruction_trap
- Unexpected matched behaviors: none
- All expected matched: False

| Rule | Family | Matched | Strength | Expected | Weak shape | Missing | Limitations | Unexpected |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `abnormal_syscall_sequence` | abnormal_sequence | False | none | False | none | close, openat, read, write, trace_proven_failed_syscall_return | none | False |
| `anti_analysis_indicator` | anti_analysis | False | none | False | none | ptrace | none | False |
| `batch_file_read_write` | collection_staging | False | none | False | none | openat, read, write, close | none | False |
| `direct_syscall_file_access` | direct_syscall | False | none | False | none | openat, read, close, write | none | False |
| `dynamic_executable_memory` | memory_permission | False | none | False | none | mmap, mprotect | none | False |
| `dynamic_executable_memory_variant` | memory_permission | False | none | False | none | mmap, mprotect, munmap | none | False |
| `illegal_instruction_trap` | trap_behavior | False | weak | True | none | write | none | False |
| `many_file_scan` | file_discovery | False | none | False | none | openat, getdents64, close | none | False |
| `mirai_encoded_table_access` | configuration_discovery | False | none | False | none | openat, read, close | none | False |
| `mirai_loopback_c2_probe` | network_loopback | False | none | False | none | socket, connect, close, write | none | False |
| `mirai_proc_scan_simulation` | process_discovery | False | none | False | none | openat, read, close | none | False |
| `mirai_watchdog_probe` | environment_probe | False | none | False | none | openat, read, close, trace_proven_failed_syscall_return | none | False |
| `multi_level_process_creation_chain` | process_chain | False | none | False | none | clone, execve, waitid | none | False |
| `non_destructive_file_encryption_simulation` | collection_staging | False | none | False | none | openat, read, close, write | none | False |
| `obfuscated_syscall_sequence` | direct_syscall | False | none | False | none | openat, read, close, write | none | False |
| `proc_status_anti_debug_check` | anti_analysis | False | none | False | none | openat, read, close | none | False |
| `process_creation_chain` | process_chain | False | none | False | none | clone, execve, waitid | none | False |
| `self_copy_simulation` | dropper_like | False | none | False | none | openat, read, write, close | none | False |
| `self_modifying_memory_simulation` | memory_permission | False | none | False | none | mmap, mprotect, munmap | none | False |
| `surrogate_elf_header_probe` | surrogate_elf_inspection | False | none | False | none | openat, read, close | none | False |
| `surrogate_rootkit_device_probe` | surrogate_kernel_environment_probe | False | none | False | none | openat, getdents64, close, trace_proven_failed_syscall_return | none | False |
| `surrogate_virus_file_activity` | surrogate_file_infection_simulation | False | none | False | none | openat, getdents64, read, write, close | none | False |
| `timing_anti_analysis_indicator` | anti_analysis | False | none | False | none | clock_gettime, openat, read, close | none | False |

This report is derived from trace semantic artifacts. It is not malware detection quality evidence.
