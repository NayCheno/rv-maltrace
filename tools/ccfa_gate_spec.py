from __future__ import annotations

P0_SAMPLES = ["hello_write", "file_open_read_write", "fork_exec", "illegal_instruction"]
P0_BRAM_MARKERS = {
    "hello_write": ("0xb0000a01", "0xe0000a01"),
    "file_open_read_write": ("0xb0000a02", "0xe0000a02"),
    "fork_exec": ("0xb0000a03", "0xe0000a03"),
    "illegal_instruction": ("0xb0000a04", "0xe0000a04"),
}
SAFE_SURROGATE_SAMPLES = [
    "file_scan",
    "batch_open_read_write",
    "self_copy_sim",
    "abnormal_syscall_sequence",
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
    "anti_debug_like",
]
ALL_CCFA_SAMPLES = P0_SAMPLES + SAFE_SURROGATE_SAMPLES

BASELINES = [
    "rv_maltrace_event_only",
    "rv_maltrace_pointer_snapshot",
    "rv_maltrace_kernel_helper",
    "strace",
    "qemu_strace",
    "software_instrumentation",
]

ABLATIONS = [
    "event_only",
    "pointer_snapshot",
    "kernel_helper_companion",
]

PRIORITY_SYSCALLS = [
    "openat",
    "read",
    "write",
    "close",
    "execve",
    "clone",
    "wait4",
    "waitid",
    "mmap",
    "mprotect",
    "ptrace",
    "clock_gettime",
    "getdents64",
]
