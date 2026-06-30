from __future__ import annotations

import argparse
import hashlib
import shutil
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    repo_rel_from,
    write_json,
)

from build_genesys2_safe_syscall_elf import (
    BASE_VADDR,
    DATA_OFFSET,
    DATA_SIZE,
    TEXT_OFFSET,
    ProgramBuilder,
    add_rodata,
    align,
    c_string_table,
    elf_header,
    program_header,
    section_header,
    symbol,
)


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = "/tmp/rvmt_benign_syscall"
BENIGN_SAMPLE_CLASS = "benign"
DEFAULT_MANIFEST = Path("experiments/linux_behavior/benign/manifest.json")
DEFAULT_OUT_ROOT = Path("results/board/genesys2_trace_validation/20260613-board-benign-control/00_benign_syscall_elves")
DEFAULT_BEGIN_MARKER = 0xB0000B10
DEFAULT_END_MARKER = 0xE0000B10
BENIGN_SAMPLES = (
    "hello",
    "ls",
    "cat",
    "cp",
    "sha256sum",
    "pid_status",
    "clock_status",
    "write_twice",
    "open_tmp_close",
    "getdents_only",
    "read_twice",
    "mmap_rw",
    "readlink_self",
    "prctl_get_name",
    "pid_clock_mix",
    "cat_small",
    "getpid_only",
    "getppid_only",
    "clock_twice",
    "prctl_set_name",
    "prctl_set_get_name",
    "open_read_close",
    "open_write_close",
    "read_zero",
    "mmap_double",
    "mmap_munmap_only",
    "readlink_twice",
    "open_proc_status",
    "open_proc_cmdline",
    "tmpdir_open_close_twice",
)


def parse_marker(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value, 10)


repo_rel = repo_rel_from(ROOT)


def samples_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest.get("samples")
    if not isinstance(rows, list):
        return {}
    return {row["id"]: row for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)}


def fallback_sample_row(sample_id: str) -> dict[str, Any]:
    if sample_id not in BENIGN_SAMPLES:
        raise ValueError(f"{sample_id}: not present in manifest")
    return {
        "id": sample_id,
        "class": BENIGN_SAMPLE_CLASS,
        "status": "BOARD_BENIGN_SCALEUP_TEMPLATE",
        "provenance": "board_benign_scaleup_builtin",
        "network_required": False,
        "default_enabled": False,
        "source": "board/artix7_35t/linux/rvmt_benign_workload.c",
        "expected_behavior": [],
        "expected_syscalls": syscall_sequence_for(sample_id)[2:-2],
    }


def rodata_for_sample(sample_id: str) -> dict[str, bytes]:
    values: dict[str, bytes] = {
        "hello_msg": b"rvmt benign hello\n",
        "ls_msg": b"rvmt benign ls\n",
        "input_path": b"/tmp/rvmt_benign_input.txt\x00",
        "copy_path": b"/tmp/rvmt_benign_copy.txt\x00",
        "tmp_dir": b"/tmp\x00",
        "self_path": b"/proc/self/exe\x00",
        "proc_status_path": b"/proc/self/status\x00",
        "proc_cmdline_path": b"/proc/self/cmdline\x00",
        "tmp_out_path": b"/tmp/rvmt_benign_out.txt\x00",
        "sha_msg": (
            b"376727353c8f4e11d279d4e65573c8b3b7f5be3f7dcc59965bb047a321d6710f  "
            b"/tmp/rvmt_benign_input.txt\n"
        ),
        "pid_msg": b"rvmt benign pid status\n",
        "clock_msg": b"rvmt benign clock status\n",
        "write2_a": b"rvmt benign write twice A\n",
        "write2_b": b"rvmt benign write twice B\n",
        "open_msg": b"rvmt benign open tmp close\n",
        "getdents_msg": b"rvmt benign getdents only\n",
        "read2_msg": b"rvmt benign read twice\n",
        "mmap_msg": b"rvmt benign mmap rw\n",
        "readlink_msg": b"rvmt benign readlink self\n",
        "prctl_msg": b"rvmt benign prctl get name\n",
        "pid_clock_msg": b"rvmt benign pid clock mix\n",
        "cat_small_msg": b"rvmt benign cat small\n",
        "getpid_only_msg": b"rvmt benign getpid only\n",
        "getppid_only_msg": b"rvmt benign getppid only\n",
        "clock_twice_msg": b"rvmt benign clock twice\n",
        "prctl_set_msg": b"rvmt benign prctl set name\n",
        "prctl_set_get_msg": b"rvmt benign prctl set get name\n",
        "open_write_msg": b"rvmt benign open write close\n",
        "mmap_double_msg": b"rvmt benign mmap double\n",
        "readlink_twice_msg": b"rvmt benign readlink twice\n",
        "tmpdir_twice_msg": b"rvmt benign tmpdir open close twice\n",
        "prctl_name": b"rvmt_benign\x00",
    }
    if sample_id not in BENIGN_SAMPLES:
        raise ValueError(f"unsupported benign sample: {sample_id}")
    return values


def labels_for_rodata(rodata_offsets: dict[str, int], rodata_vaddr: int) -> dict[str, int]:
    labels = {name: rodata_vaddr + offset for name, offset in rodata_offsets.items()}
    labels["buffer"] = BASE_VADDR + DATA_OFFSET
    return labels


def generate_text(sample_id: str, text_vaddr: int, labels: dict[str, int], begin_marker: int, end_marker: int) -> bytes:
    b = ProgramBuilder(text_vaddr, labels)
    # If a previous capture ended with the BRAM ring frozen, the first begin marker
    # clears/unfreezes the ring but is not written. If the ring is already active,
    # the second begin marker clears the first, leaving one visible begin marker.
    b.marker(begin_marker)
    b.marker(begin_marker)

    if sample_id == "hello":
        b.syscall("write", [("a0", 1), ("a1", "hello_msg"), ("a2", len("rvmt benign hello\n"))])
    elif sample_id == "ls":
        b.syscall("openat", [("a0", -100), ("a1", "tmp_dir"), ("a2", 0x90000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("getdents64", [("a0", "s0"), ("a1", "buffer"), ("a2", 256)])
        b.syscall("write", [("a0", 1), ("a1", "ls_msg"), ("a2", len("rvmt benign ls\n"))])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "cat":
        b.syscall("openat", [("a0", -100), ("a1", "input_path"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 64)])
        b.syscall("write", [("a0", 1), ("a1", "buffer"), ("a2", len("rvmt benign fixture\n"))])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "cp":
        b.syscall("openat", [("a0", -100), ("a1", "input_path"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 64)])
        b.syscall("openat", [("a0", -100), ("a1", "copy_path"), ("a2", 0x80241), ("a3", 0o600)])
        b.emit_mv("s1", "a0")
        b.syscall("write", [("a0", "s1"), ("a1", "buffer"), ("a2", len("rvmt benign fixture\n"))])
        b.syscall("close", [("a0", "s0")])
        b.syscall("close", [("a0", "s1")])
    elif sample_id == "sha256sum":
        b.syscall("openat", [("a0", -100), ("a1", "input_path"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 64)])
        b.syscall("close", [("a0", "s0")])
        b.syscall("write", [("a0", 1), ("a1", "sha_msg"), ("a2", len(rodata_for_sample(sample_id)["sha_msg"]))])
    elif sample_id == "pid_status":
        b.syscall("getpid", [])
        b.syscall("getppid", [])
        b.syscall("write", [("a0", 1), ("a1", "pid_msg"), ("a2", len(rodata_for_sample(sample_id)["pid_msg"]))])
    elif sample_id == "clock_status":
        b.syscall("clock_gettime", [("a0", 1), ("a1", "buffer")])
        b.syscall("write", [("a0", 1), ("a1", "clock_msg"), ("a2", len(rodata_for_sample(sample_id)["clock_msg"]))])
    elif sample_id == "write_twice":
        b.syscall("write", [("a0", 1), ("a1", "write2_a"), ("a2", len(rodata_for_sample(sample_id)["write2_a"]))])
        b.syscall("write", [("a0", 1), ("a1", "write2_b"), ("a2", len(rodata_for_sample(sample_id)["write2_b"]))])
    elif sample_id == "open_tmp_close":
        b.syscall("openat", [("a0", -100), ("a1", "tmp_dir"), ("a2", 0x90000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("close", [("a0", "s0")])
        b.syscall("write", [("a0", 1), ("a1", "open_msg"), ("a2", len(rodata_for_sample(sample_id)["open_msg"]))])
    elif sample_id == "getdents_only":
        b.syscall("openat", [("a0", -100), ("a1", "tmp_dir"), ("a2", 0x90000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("getdents64", [("a0", "s0"), ("a1", "buffer"), ("a2", 256)])
        b.syscall("close", [("a0", "s0")])
        b.syscall("write", [("a0", 1), ("a1", "getdents_msg"), ("a2", len(rodata_for_sample(sample_id)["getdents_msg"]))])
    elif sample_id == "read_twice":
        b.syscall("openat", [("a0", -100), ("a1", "input_path"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 8)])
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 8)])
        b.syscall("write", [("a0", 1), ("a1", "read2_msg"), ("a2", len(rodata_for_sample(sample_id)["read2_msg"]))])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "mmap_rw":
        b.syscall("mmap", [("a0", 0), ("a1", 4096), ("a2", 0x3), ("a3", 0x22), ("a4", -1), ("a5", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("write", [("a0", 1), ("a1", "mmap_msg"), ("a2", len(rodata_for_sample(sample_id)["mmap_msg"]))])
        b.syscall("munmap", [("a0", "s0"), ("a1", 4096)])
    elif sample_id == "readlink_self":
        b.syscall("readlinkat", [("a0", -100), ("a1", "self_path"), ("a2", "buffer"), ("a3", 128)])
        b.syscall("write", [("a0", 1), ("a1", "readlink_msg"), ("a2", len(rodata_for_sample(sample_id)["readlink_msg"]))])
    elif sample_id == "prctl_get_name":
        b.syscall("prctl", [("a0", 16), ("a1", "buffer"), ("a2", 0), ("a3", 0), ("a4", 0)])
        b.syscall("write", [("a0", 1), ("a1", "prctl_msg"), ("a2", len(rodata_for_sample(sample_id)["prctl_msg"]))])
    elif sample_id == "pid_clock_mix":
        b.syscall("getpid", [])
        b.syscall("clock_gettime", [("a0", 1), ("a1", "buffer")])
        b.syscall("write", [("a0", 1), ("a1", "pid_clock_msg"), ("a2", len(rodata_for_sample(sample_id)["pid_clock_msg"]))])
    elif sample_id == "cat_small":
        b.syscall("openat", [("a0", -100), ("a1", "input_path"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 16)])
        b.syscall("write", [("a0", 1), ("a1", "cat_small_msg"), ("a2", len(rodata_for_sample(sample_id)["cat_small_msg"]))])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "getpid_only":
        b.syscall("getpid", [])
        b.syscall("write", [("a0", 1), ("a1", "getpid_only_msg"), ("a2", len(rodata_for_sample(sample_id)["getpid_only_msg"]))])
    elif sample_id == "getppid_only":
        b.syscall("getppid", [])
        b.syscall("write", [("a0", 1), ("a1", "getppid_only_msg"), ("a2", len(rodata_for_sample(sample_id)["getppid_only_msg"]))])
    elif sample_id == "clock_twice":
        b.syscall("clock_gettime", [("a0", 1), ("a1", "buffer")])
        b.syscall("clock_gettime", [("a0", 1), ("a1", "buffer")])
        b.syscall("write", [("a0", 1), ("a1", "clock_twice_msg"), ("a2", len(rodata_for_sample(sample_id)["clock_twice_msg"]))])
    elif sample_id == "prctl_set_name":
        b.syscall("prctl", [("a0", 15), ("a1", "prctl_name"), ("a2", 0), ("a3", 0), ("a4", 0)])
        b.syscall("write", [("a0", 1), ("a1", "prctl_set_msg"), ("a2", len(rodata_for_sample(sample_id)["prctl_set_msg"]))])
    elif sample_id == "prctl_set_get_name":
        b.syscall("prctl", [("a0", 15), ("a1", "prctl_name"), ("a2", 0), ("a3", 0), ("a4", 0)])
        b.syscall("prctl", [("a0", 16), ("a1", "buffer"), ("a2", 0), ("a3", 0), ("a4", 0)])
        b.syscall("write", [("a0", 1), ("a1", "prctl_set_get_msg"), ("a2", len(rodata_for_sample(sample_id)["prctl_set_get_msg"]))])
    elif sample_id == "open_read_close":
        b.syscall("openat", [("a0", -100), ("a1", "input_path"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 32)])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "open_write_close":
        b.syscall("openat", [("a0", -100), ("a1", "tmp_out_path"), ("a2", 0x80241), ("a3", 0o600)])
        b.emit_mv("s0", "a0")
        b.syscall("write", [("a0", "s0"), ("a1", "open_write_msg"), ("a2", len(rodata_for_sample(sample_id)["open_write_msg"]))])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "read_zero":
        b.syscall("openat", [("a0", -100), ("a1", "input_path"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 0)])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "mmap_double":
        b.syscall("mmap", [("a0", 0), ("a1", 4096), ("a2", 0x3), ("a3", 0x22), ("a4", -1), ("a5", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("mmap", [("a0", 0), ("a1", 4096), ("a2", 0x1), ("a3", 0x22), ("a4", -1), ("a5", 0)])
        b.emit_mv("s1", "a0")
        b.syscall("write", [("a0", 1), ("a1", "mmap_double_msg"), ("a2", len(rodata_for_sample(sample_id)["mmap_double_msg"]))])
        b.syscall("munmap", [("a0", "s0"), ("a1", 4096)])
        b.syscall("munmap", [("a0", "s1"), ("a1", 4096)])
    elif sample_id == "mmap_munmap_only":
        b.syscall("mmap", [("a0", 0), ("a1", 4096), ("a2", 0x3), ("a3", 0x22), ("a4", -1), ("a5", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("munmap", [("a0", "s0"), ("a1", 4096)])
    elif sample_id == "readlink_twice":
        b.syscall("readlinkat", [("a0", -100), ("a1", "self_path"), ("a2", "buffer"), ("a3", 128)])
        b.syscall("readlinkat", [("a0", -100), ("a1", "self_path"), ("a2", "buffer"), ("a3", 128)])
        b.syscall("write", [("a0", 1), ("a1", "readlink_twice_msg"), ("a2", len(rodata_for_sample(sample_id)["readlink_twice_msg"]))])
    elif sample_id == "open_proc_status":
        b.syscall("openat", [("a0", -100), ("a1", "proc_status_path"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 64)])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "open_proc_cmdline":
        b.syscall("openat", [("a0", -100), ("a1", "proc_cmdline_path"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 64)])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "tmpdir_open_close_twice":
        b.syscall("openat", [("a0", -100), ("a1", "tmp_dir"), ("a2", 0x90000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("close", [("a0", "s0")])
        b.syscall("openat", [("a0", -100), ("a1", "tmp_dir"), ("a2", 0x90000), ("a3", 0)])
        b.emit_mv("s1", "a0")
        b.syscall("close", [("a0", "s1")])
        b.syscall("write", [("a0", 1), ("a1", "tmpdir_twice_msg"), ("a2", len(rodata_for_sample(sample_id)["tmpdir_twice_msg"]))])
    else:
        raise ValueError(f"unsupported benign sample: {sample_id}")

    b.marker(end_marker)
    b.exit_zero()
    return bytes(b.code)


def syscall_sequence_for(sample_id: str) -> list[str]:
    if sample_id == "hello":
        return ["rvmt_marker", "rvmt_marker", "write", "rvmt_marker", "exit"]
    if sample_id == "ls":
        return ["rvmt_marker", "rvmt_marker", "openat", "getdents64", "write", "close", "rvmt_marker", "exit"]
    if sample_id == "cat":
        return ["rvmt_marker", "rvmt_marker", "openat", "read", "write", "close", "rvmt_marker", "exit"]
    if sample_id == "cp":
        return ["rvmt_marker", "rvmt_marker", "openat", "read", "openat", "write", "close", "close", "rvmt_marker", "exit"]
    if sample_id == "sha256sum":
        return ["rvmt_marker", "rvmt_marker", "openat", "read", "close", "write", "rvmt_marker", "exit"]
    if sample_id == "pid_status":
        return ["rvmt_marker", "rvmt_marker", "getpid", "getppid", "write", "rvmt_marker", "exit"]
    if sample_id == "clock_status":
        return ["rvmt_marker", "rvmt_marker", "clock_gettime", "write", "rvmt_marker", "exit"]
    if sample_id == "write_twice":
        return ["rvmt_marker", "rvmt_marker", "write", "write", "rvmt_marker", "exit"]
    if sample_id == "open_tmp_close":
        return ["rvmt_marker", "rvmt_marker", "openat", "close", "write", "rvmt_marker", "exit"]
    if sample_id == "getdents_only":
        return ["rvmt_marker", "rvmt_marker", "openat", "getdents64", "close", "write", "rvmt_marker", "exit"]
    if sample_id == "read_twice":
        return ["rvmt_marker", "rvmt_marker", "openat", "read", "read", "write", "close", "rvmt_marker", "exit"]
    if sample_id == "mmap_rw":
        return ["rvmt_marker", "rvmt_marker", "mmap", "write", "munmap", "rvmt_marker", "exit"]
    if sample_id == "readlink_self":
        return ["rvmt_marker", "rvmt_marker", "readlinkat", "write", "rvmt_marker", "exit"]
    if sample_id == "prctl_get_name":
        return ["rvmt_marker", "rvmt_marker", "prctl", "write", "rvmt_marker", "exit"]
    if sample_id == "pid_clock_mix":
        return ["rvmt_marker", "rvmt_marker", "getpid", "clock_gettime", "write", "rvmt_marker", "exit"]
    if sample_id == "cat_small":
        return ["rvmt_marker", "rvmt_marker", "openat", "read", "write", "close", "rvmt_marker", "exit"]
    if sample_id == "getpid_only":
        return ["rvmt_marker", "rvmt_marker", "getpid", "write", "rvmt_marker", "exit"]
    if sample_id == "getppid_only":
        return ["rvmt_marker", "rvmt_marker", "getppid", "write", "rvmt_marker", "exit"]
    if sample_id == "clock_twice":
        return ["rvmt_marker", "rvmt_marker", "clock_gettime", "clock_gettime", "write", "rvmt_marker", "exit"]
    if sample_id == "prctl_set_name":
        return ["rvmt_marker", "rvmt_marker", "prctl", "write", "rvmt_marker", "exit"]
    if sample_id == "prctl_set_get_name":
        return ["rvmt_marker", "rvmt_marker", "prctl", "prctl", "write", "rvmt_marker", "exit"]
    if sample_id == "open_read_close":
        return ["rvmt_marker", "rvmt_marker", "openat", "read", "close", "rvmt_marker", "exit"]
    if sample_id == "open_write_close":
        return ["rvmt_marker", "rvmt_marker", "openat", "write", "close", "rvmt_marker", "exit"]
    if sample_id == "read_zero":
        return ["rvmt_marker", "rvmt_marker", "openat", "read", "close", "rvmt_marker", "exit"]
    if sample_id == "mmap_double":
        return ["rvmt_marker", "rvmt_marker", "mmap", "mmap", "write", "munmap", "munmap", "rvmt_marker", "exit"]
    if sample_id == "mmap_munmap_only":
        return ["rvmt_marker", "rvmt_marker", "mmap", "munmap", "rvmt_marker", "exit"]
    if sample_id == "readlink_twice":
        return ["rvmt_marker", "rvmt_marker", "readlinkat", "readlinkat", "write", "rvmt_marker", "exit"]
    if sample_id == "open_proc_status":
        return ["rvmt_marker", "rvmt_marker", "openat", "read", "close", "rvmt_marker", "exit"]
    if sample_id == "open_proc_cmdline":
        return ["rvmt_marker", "rvmt_marker", "openat", "read", "close", "rvmt_marker", "exit"]
    if sample_id == "tmpdir_open_close_twice":
        return ["rvmt_marker", "rvmt_marker", "openat", "close", "openat", "close", "write", "rvmt_marker", "exit"]
    raise ValueError(f"unsupported benign sample: {sample_id}")


def build_elf(sample_id: str, begin_marker: int, end_marker: int) -> tuple[bytes, dict[str, Any]]:
    rodata_values = rodata_for_sample(sample_id)
    rodata, rodata_offsets = add_rodata(rodata_values)
    text_vaddr = BASE_VADDR + TEXT_OFFSET

    rodata_vaddr_guess = align(text_vaddr + 512, 8)
    labels = labels_for_rodata(rodata_offsets, rodata_vaddr_guess)
    text = generate_text(sample_id, text_vaddr, labels, begin_marker, end_marker)
    rodata_offset = align(TEXT_OFFSET + len(text), 8)
    rodata_vaddr = BASE_VADDR + rodata_offset
    labels = labels_for_rodata(rodata_offsets, rodata_vaddr)
    text = generate_text(sample_id, text_vaddr, labels, begin_marker, end_marker)
    rodata_offset = align(TEXT_OFFSET + len(text), 8)
    rodata_vaddr = BASE_VADDR + rodata_offset
    labels = labels_for_rodata(rodata_offsets, rodata_vaddr)
    text = generate_text(sample_id, text_vaddr, labels, begin_marker, end_marker)

    text_offset = TEXT_OFFSET
    text_size = len(text)
    data = bytearray(DATA_SIZE)

    strtab, str_offsets = c_string_table(["_start", "buffer"])
    shstrtab, shstr_offsets = c_string_table([".text", ".rodata", ".data", ".symtab", ".strtab", ".shstrtab"])
    symtab = b"".join(
        [
            b"\x00" * 24,
            symbol(str_offsets["_start"], 0x12, 1, text_vaddr, text_size),
            symbol(str_offsets["buffer"], 0x11, 3, BASE_VADDR + DATA_OFFSET, DATA_SIZE),
        ]
    )

    content = bytearray()
    content.extend(b"\x00" * TEXT_OFFSET)
    content[text_offset : text_offset + text_size] = text
    if len(content) < rodata_offset:
        content.extend(b"\x00" * (rodata_offset - len(content)))
    content.extend(rodata)
    if len(content) < DATA_OFFSET:
        content.extend(b"\x00" * (DATA_OFFSET - len(content)))
    content.extend(data)
    symtab_offset = align(len(content), 8)
    content.extend(b"\x00" * (symtab_offset - len(content)))
    content.extend(symtab)
    strtab_offset = len(content)
    content.extend(strtab)
    shstrtab_offset = len(content)
    content.extend(shstrtab)
    shoff = align(len(content), 8)
    content.extend(b"\x00" * (shoff - len(content)))

    headers = [
        b"\x00" * 64,
        program_header(1, 0x5, 0, BASE_VADDR, DATA_OFFSET, DATA_OFFSET, 0x1000),
        program_header(1, 0x6, DATA_OFFSET, BASE_VADDR + DATA_OFFSET, DATA_SIZE, DATA_SIZE, 0x1000),
    ]
    content[0 : len(b"".join(headers))] = b"".join(headers)

    section_headers = [
        b"\x00" * 64,
        section_header(shstr_offsets[".text"], 1, 0x6, text_vaddr, text_offset, text_size, 0, 0, 4, 0),
        section_header(shstr_offsets[".rodata"], 1, 0x2, rodata_vaddr, rodata_offset, len(rodata), 0, 0, 8, 0),
        section_header(shstr_offsets[".data"], 1, 0x3, BASE_VADDR + DATA_OFFSET, DATA_OFFSET, DATA_SIZE, 0, 0, 8, 0),
        section_header(shstr_offsets[".symtab"], 2, 0, 0, symtab_offset, len(symtab), 5, 1, 8, 24),
        section_header(shstr_offsets[".strtab"], 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0),
        section_header(shstr_offsets[".shstrtab"], 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0),
    ]
    content.extend(b"".join(section_headers))
    content[0:64] = elf_header(text_vaddr, shoff, len(section_headers), 6)

    metadata = {
        "schema": "rvmt.genesys2.benign_syscall_elf_build.v1",
        "sample_id": sample_id,
        "sample_class": BENIGN_SAMPLE_CLASS,
        "real_malware": False,
        "binary_role": "linux_user_benign_syscall_only",
        "builder": "tools/build_genesys2_benign_syscall_elf.py",
        "entry": f"0x{text_vaddr:016x}",
        "text_size": text_size,
        "data_size": DATA_SIZE,
        "syscall_sequence": syscall_sequence_for(sample_id),
        "marker_scope": {
            "enabled": True,
            "syscall_nr": 1023,
            "begin_value_low32": f"0x{begin_marker & 0xFFFFFFFF:08x}",
            "end_value_low32": f"0x{end_marker & 0xFFFFFFFF:08x}",
        },
        "source_relation": "syscall-only benign control generated from repository benign manifest shape",
        "non_claims": [
            "No real malware validation is demonstrated.",
            "This binary is a benign control workload and is not a detection-quality claim by itself.",
        ],
    }
    return bytes(content), metadata


def build_one(root: Path, manifest: dict[str, Any], sample_id: str, out_dir: Path, code_map_dir: Path | None, begin_marker: int, end_marker: int) -> Path:
    samples = samples_by_id(manifest)
    row = samples.get(sample_id) or fallback_sample_row(sample_id)
    if row.get("class") != BENIGN_SAMPLE_CLASS:
        raise ValueError(f"{sample_id}: manifest row is not benign")
    out_dir.mkdir(parents=True, exist_ok=True)
    elf, metadata = build_elf(sample_id, begin_marker, end_marker)
    binary = out_dir / f"{sample_id}.riscv64"
    binary.write_bytes(elf)
    digest = hashlib.sha256(elf).hexdigest()
    source_path = root / str(row.get("source"))
    metadata.update(
        {
            "reference_manifest": repo_rel(root / DEFAULT_MANIFEST),
            "reference_manifest_row_present": sample_id in samples,
            "reference_source": row.get("source"),
            "reference_source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest() if source_path.is_file() else None,
            "binary": repo_rel(binary),
            "binary_sha256": digest,
            "runtime_path": f"{RUNTIME_ROOT}/{sample_id}",
            "expected_behavior": row.get("expected_behavior", []),
            "expected_syscalls": row.get("expected_syscalls", []),
            "network_required": False,
        }
    )
    write_json(out_dir / "build_manifest.json", metadata)
    (out_dir / "riscv64_elf.sha256").write_text(f"{digest}  {binary.name}\n", encoding="utf-8", newline="\n")
    if source_path.is_file():
        source_digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        (out_dir / "source.sha256").write_text(f"{source_digest}  {repo_rel(source_path)}\n", encoding="utf-8", newline="\n")
    if code_map_dir is not None:
        from build_code_map import build_code_map, write_outputs

        code_map = build_code_map(
            binary,
            sample_id,
            str(row.get("source")),
            "linux_user_benign_syscall_only",
            f"{RUNTIME_ROOT}/{sample_id}",
        )
        code_map.setdefault("notes", []).append(
            "Generated by tools/build_genesys2_benign_syscall_elf.py as a benign syscall-only control workload."
        )
        code_map_path = write_outputs(code_map, code_map_dir, sample_id)
        shutil.copy2(code_map_path, code_map_dir / "code_map.json")
    return binary


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source_dir = root / "board/artix7_35t/linux"
        source_dir.mkdir(parents=True)
        (source_dir / "rvmt_benign_workload.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        manifest = {
            "samples": [
                {
                    "id": sample_id,
                    "class": "benign",
                    "source": "board/artix7_35t/linux/rvmt_benign_workload.c",
                    "expected_behavior": [],
                    "expected_syscalls": [],
                }
                for sample_id in BENIGN_SAMPLES
            ]
        }
        out_root = root / "out"
        for index, sample_id in enumerate(BENIGN_SAMPLES, start=1):
            begin = 0xB0000B10 + index
            end = 0xE0000B10 + index
            binary = build_one(root, manifest, sample_id, out_root / sample_id, None, begin, end)
            elf = binary.read_bytes()
            if elf[:4] != b"\x7fELF":
                print(f"[FAIL] {sample_id}: missing ELF magic", file=sys.stderr)
                return 1
            meta = load_json(out_root / sample_id / "build_manifest.json")
            if meta.get("sample_class") != "benign" or meta.get("marker_scope", {}).get("begin_value_low32") != f"0x{begin:08x}":
                print(f"[FAIL] {sample_id}: incomplete metadata", file=sys.stderr)
                return 1
    print("[PASS] Genesys2 benign syscall-only ELF builder self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build marker-scoped syscall-only benign control ELFs for Genesys2/CVA6.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--sample-id", action="append", choices=BENIGN_SAMPLES)
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--code-map", action="store_true")
    parser.add_argument("--begin-marker", type=parse_marker, default=DEFAULT_BEGIN_MARKER)
    parser.add_argument("--end-marker", type=parse_marker, default=DEFAULT_END_MARKER)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    manifest = load_json(root / args.manifest)
    sample_ids = args.sample_id or list(BENIGN_SAMPLES)
    if args.out is not None and len(sample_ids) != 1:
        parser.error("--out requires exactly one --sample-id")
    out_root = args.out_root if args.out_root.is_absolute() else root / args.out_root
    for sample_id in sample_ids:
        if args.out is not None:
            out_dir = args.out.parent.resolve()
            binary = build_one(root, manifest, sample_id, out_dir, out_dir / "code_map" if args.code_map else None, args.begin_marker, args.end_marker)
            target = args.out.resolve()
            if binary != target:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(binary, target)
                binary = target
            print(binary)
            continue
        out_dir = out_root / sample_id
        code_map_dir = out_dir / "code_map" if args.code_map else None
        binary = build_one(root, manifest, sample_id, out_dir, code_map_dir, args.begin_marker, args.end_marker)
        print(binary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
