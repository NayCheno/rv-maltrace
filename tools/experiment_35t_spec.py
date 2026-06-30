from __future__ import annotations

import re
from pathlib import Path

BENIGN_MANIFEST = Path("experiments/linux_behavior/benign/manifest.json")
MALWARE_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
MALWARE_EXTENSION_PLAN = Path("experiments/linux_behavior/malware_like/extension_plan.json")
SURROGATE_MANIFEST = Path("experiments/linux_behavior/real_malware_surrogate/manifest.json")
RULES_PATH = Path("experiments/linux_behavior/behavior_audit_rules.json")
ROOTFS_EXP_BIN_DIR = Path("build/board/artix7_35t/rootfs_exp_overlay/usr/bin")
TRACE_OFF = "trace-off"
TRACE_ON = "trace-on"
RUNTIME_CLASSIC = "classic"
RUNTIME_ABBA = "abba"
TRACE_PROFILE_POLICY_UNIFORM = "uniform"
TRACE_PROFILE_POLICY_35T_SMALL_CAPACITY = "35t_small_capacity"
TRACE_PROFILE_POLICY_CHOICES = (TRACE_PROFILE_POLICY_UNIFORM, TRACE_PROFILE_POLICY_35T_SMALL_CAPACITY)
TRACE_PROFILE_POLICY_35T_TRAP_SAMPLES = frozenset({"illegal_trap"})
REQUIRED_BASELINES = ("host_native", "host_strace", "qemu_native", "qemu_strace")
OPTIONAL_BASELINES = ("ebpf_only", "qemu_plugin", "software_instrumentation")
BEHAVIOR_AUDIT_SAMPLE_CLASSES = frozenset({"malware_like_synthetic", "real_malware_surrogate"})
UART_TIMESTAMP_RE = re.compile(r"\[[0-9]+(?:\.[0-9]+)?\]\s*")
UART_MARKERS = (
    "RVMT_EXP_REP_BEGIN",
    "RVMT_EXP_REP_RESULT",
    "RVMT_EXP_REP_END",
    "RVMT_EXP_END",
    "RVMT_RUNTIME_PROCESS_MAP_BEGIN",
    "RVMT_RUNTIME_PROCESS_MAP_ENTRY",
    "RVMT_RUNTIME_PROCESS_PROVENANCE",
    "RVMT_RUNTIME_PROCESS_MAP_END",
    "RVMT_RUNTIME_PROCESS",
    "RVMT_SYSCALL_OBS",
    "RVMT_TRACE_DUMP_BEGIN",
    "RVMT_TRACE_DUMP_END",
    "RVMT_TRACE_RECORD",
)
UART_MARKER_PATTERNS = tuple((re.compile(r"\s*".join(re.escape(char) for char in marker)), marker) for marker in UART_MARKERS)
UART_FIELD_KEYS = (
    "class",
    "sample",
    "mode",
    "rep",
    "order_index",
    "warmup",
    "exit",
    "runtime_ns",
    "trace_count",
    "drop",
    "schema",
    "role",
    "pid",
    "tgid",
    "status",
    "comm_hex",
    "exe_hex",
    "start",
    "end",
    "perms",
    "offset",
    "dev",
    "inode",
    "path_hex",
    "collector",
    "method",
    "proc_sample_time",
    "warnings_hex",
    "phase",
    "seq",
    "nr",
    "name",
    "a0",
    "a1",
    "a2",
    "a3",
    "a4",
    "a5",
    "a6",
    "a7",
    "ret",
)
UART_FIELD_KEY_PATTERN = "|".join(re.escape(key) for key in UART_FIELD_KEYS)
UART_FIELD_RE = re.compile(
    rf"\b({UART_FIELD_KEY_PATTERN})=([^\s]*?)(?=(?:{UART_FIELD_KEY_PATTERN})=|\s+(?:{UART_FIELD_KEY_PATTERN})=|$)"
)
