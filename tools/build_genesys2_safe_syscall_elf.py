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


ROOT = Path(__file__).resolve().parents[1]
BASE_VADDR = 0x10000
TEXT_OFFSET = 0x100
DATA_OFFSET = 0x2000
DATA_SIZE = 1024
RUNTIME_ROOT = "/tmp/rvmt_p2"
SAFE_SAMPLE_CLASS = "malware_like_synthetic"
DEFAULT_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
DEFAULT_RUN_ROOT = Path("results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610")
RVMT_MARKER_PAYLOAD = 0x00000A11
RVMT_MARKER_BEGIN = 0xB0000000 | RVMT_MARKER_PAYLOAD
RVMT_MARKER_END = 0xE0000000 | RVMT_MARKER_PAYLOAD
ILLEGAL_TRAP_WARMUP_ITERATIONS = 80_000_000
RUNTIME_MAP_WARMUP_ITERATIONS = 80_000_000

REG = {
    "zero": 0,
    "ra": 1,
    "sp": 2,
    "gp": 3,
    "tp": 4,
    "t0": 5,
    "t1": 6,
    "t2": 7,
    "s0": 8,
    "s1": 9,
    "a0": 10,
    "a1": 11,
    "a2": 12,
    "a3": 13,
    "a4": 14,
    "a5": 15,
    "a6": 16,
    "a7": 17,
}

SYSCALL_NUMBERS = {
    "read": 63,
    "write": 64,
    "openat": 56,
    "close": 57,
    "clone": 220,
    "execve": 221,
    "waitid": 95,
    "mmap": 222,
    "mprotect": 226,
    "munmap": 215,
    "getdents64": 61,
    "ptrace": 117,
    "clock_gettime": 113,
    "rt_sigaction": 134,
    "exit": 93,
    "rvmt_marker": 1023,
    "getpid": 172,
    "getppid": 173,
    "readlinkat": 78,
    "prctl": 167,
    "socket": 198,
    "bind": 200,
    "listen": 201,
    "connect": 203,
}


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


repo_rel = repo_rel_from(ROOT)


def samples_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest.get("samples")
    if not isinstance(rows, list):
        return {}
    return {row["id"]: row for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)}


def encode_i(imm: int, rs1: int, funct3: int, rd: int, opcode: int) -> bytes:
    if not -2048 <= imm <= 2047:
        raise ValueError(f"I-type immediate out of range: {imm}")
    imm12 = imm & 0xFFF
    return u32((imm12 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode)


def encode_b(imm: int, rs1: int, rs2: int, funct3: int, opcode: int) -> bytes:
    if imm % 2:
        raise ValueError(f"B-type immediate must be 2-byte aligned: {imm}")
    if not -4096 <= imm <= 4094:
        raise ValueError(f"B-type immediate out of range: {imm}")
    imm13 = imm & 0x1FFF
    return u32(
        ((imm13 >> 12) & 0x1) << 31
        | ((imm13 >> 5) & 0x3F) << 25
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((imm13 >> 1) & 0xF) << 8
        | ((imm13 >> 11) & 0x1) << 7
        | opcode
    )


def encode_u(imm20: int, rd: int, opcode: int) -> bytes:
    return u32(((imm20 & 0xFFFFF) << 12) | (rd << 7) | opcode)


def inst_addi(rd: str, rs1: str, imm: int) -> bytes:
    return encode_i(imm, REG[rs1], 0, REG[rd], 0x13)


def inst_bne(rs1: str, rs2: str, imm: int) -> bytes:
    return encode_b(imm, REG[rs1], REG[rs2], 1, 0x63)


def inst_lui(rd: str, imm20: int) -> bytes:
    return encode_u(imm20, REG[rd], 0x37)


def inst_auipc(rd: str, imm20: int) -> bytes:
    return encode_u(imm20, REG[rd], 0x17)


def inst_ecall() -> bytes:
    return u32(0x00000073)


def inst_ebreak() -> bytes:
    return u32(0x00100073)


def inst_illegal() -> bytes:
    return u32(0xFFFFFFFF)


def li(rd: str, value: int) -> list[bytes]:
    if -2048 <= value <= 2047:
        return [inst_addi(rd, "zero", value)]
    hi = (value + 0x800) >> 12
    lo = value - (hi << 12)
    return [inst_lui(rd, hi), inst_addi(rd, rd, lo)]


def la(rd: str, pc: int, target: int) -> list[bytes]:
    offset = target - pc
    hi = (offset + 0x800) >> 12
    lo = offset - (hi << 12)
    return [inst_auipc(rd, hi), inst_addi(rd, rd, lo)]


class ProgramBuilder:
    def __init__(self, text_vaddr: int, labels: dict[str, int]):
        self.text_vaddr = text_vaddr
        self.labels = labels
        self.code = bytearray()

    @property
    def pc(self) -> int:
        return self.text_vaddr + len(self.code)

    def emit(self, *instructions: bytes) -> None:
        for instruction in instructions:
            self.code.extend(instruction)

    def emit_li(self, rd: str, value: int) -> None:
        self.emit(*li(rd, value))

    def emit_la(self, rd: str, label: str) -> None:
        current_pc = self.pc
        self.emit(*la(rd, current_pc, self.labels[label]))

    def emit_mv(self, rd: str, rs: str) -> None:
        self.emit(inst_addi(rd, rs, 0))

    def emit_bne(self, rs1: str, rs2: str, target_pc: int) -> None:
        self.emit(inst_bne(rs1, rs2, target_pc - self.pc))

    def busy_wait(self, iterations: int) -> None:
        if iterations <= 0:
            return
        self.emit_li("t0", iterations)
        loop_pc = self.pc
        self.emit(inst_addi("t0", "t0", -1))
        self.emit_bne("t0", "zero", loop_pc)

    def syscall(self, name: str, args: list[tuple[str, int | str]]) -> None:
        for reg, value in args:
            if isinstance(value, str):
                if value in REG:
                    self.emit_mv(reg, value)
                else:
                    self.emit_la(reg, value)
            else:
                self.emit_li(reg, value)
        self.emit_li("a7", SYSCALL_NUMBERS[name])
        self.emit(inst_ecall())

    def exit_zero(self) -> None:
        self.syscall("exit", [("a0", 0)])
        self.emit(inst_ebreak())

    def marker(self, value: int) -> None:
        self.syscall("rvmt_marker", [("a0", value), ("a1", 0), ("a2", 0), ("a3", 0)])


def add_rodata(strings: dict[str, bytes]) -> tuple[bytes, dict[str, int]]:
    blob = bytearray()
    offsets: dict[str, int] = {}
    for name, value in strings.items():
        while len(blob) % 8:
            blob.append(0)
        offsets[name] = len(blob)
        blob.extend(value)
    return bytes(blob), offsets

def rodata_for_sample(sample_id: str) -> dict[str, bytes]:
    values: dict[str, bytes] = {
        "msg": f"rvmt_p2:{sample_id}\n".encode("ascii"),
        "missing": b"/path/that/does/not/exist\x00",
        "tmp_out": f"{RUNTIME_ROOT}/{sample_id}.tmp\x00".encode("ascii"),
        "bin_true": b"/bin/true\x00",
        "proc_status": b"/proc/self/status\x00",
        "scan_root": b"experiments/linux_behavior/malware_like/fixtures/scan_root\x00",
        "self_path": f"{RUNTIME_ROOT}/{sample_id}\x00".encode("ascii"),
        "copy_path": b"/tmp/rvmt_self_copy_sim.bin\x00",
    }
    if sample_id == "illegal_trap":
        values["sigill_msg"] = b"synthetic SIGILL\n"
    if sample_id in ("mirai_comprehensive", "mirai_prctl_probe"):
        values["prctl_name"] = b"rvmt-mirai\x00"
    if sample_id == "mirai_comprehensive":
        values.update({
            "proc_self_status": b"/proc/self/status\x00",
            "proc_pid_max": b"/proc/sys/kernel/pid_max\x00",
            "proc_1_exe": b"/proc/1/exe\x00",
            "proc_1_status": b"/proc/1/status\x00",
            "safe_watchdog": b"/tmp/rvmt_safe_dev_watchdog\x00",
            "safe_misc_watchdog": b"/tmp/rvmt_safe_dev_misc_watchdog\x00",
            "real_watchdog": b"/dev/watchdog\x00",
        })
    return values


def labels_for_rodata(rodata_offsets: dict[str, int], rodata_vaddr: int) -> dict[str, int]:
    labels = {name: rodata_vaddr + offset for name, offset in rodata_offsets.items()}
    labels["buffer"] = BASE_VADDR + DATA_OFFSET
    labels["argv_true"] = BASE_VADDR + DATA_OFFSET + 0x100
    labels["bind_addr"] = BASE_VADDR + DATA_OFFSET + 0x200
    labels["connect_addr"] = BASE_VADDR + DATA_OFFSET + 0x210
    labels["sigaction"] = BASE_VADDR + DATA_OFFSET + 0x300
    return labels


def generate_text(sample_id: str, text_vaddr: int, labels: dict[str, int]) -> bytes:
    b = ProgramBuilder(text_vaddr, labels)
    if sample_id != "illegal_trap":
        b.busy_wait(RUNTIME_MAP_WARMUP_ITERATIONS)
        b.marker(RVMT_MARKER_BEGIN)
    if sample_id == "file_scan":
        b.syscall("openat", [("a0", -100), ("a1", "scan_root"), ("a2", 0x90000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        for _ in range(4):
            b.syscall("getdents64", [("a0", "s0"), ("a1", "buffer"), ("a2", 256)])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "batch_open_read_write":
        b.syscall("openat", [("a0", -100), ("a1", "missing"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 64)])
        b.syscall("close", [("a0", "s0")])
        b.syscall("openat", [("a0", -100), ("a1", "tmp_out"), ("a2", 0x80041), ("a3", 0o600)])
        b.emit_mv("s0", "a0")
        b.syscall("write", [("a0", "s0"), ("a1", "msg"), ("a2", len(f"rvmt_p2:{sample_id}\n"))])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "self_copy_sim":
        b.syscall("openat", [("a0", -100), ("a1", "self_path"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 64)])
        b.syscall("openat", [("a0", -100), ("a1", "copy_path"), ("a2", 0x80241), ("a3", 0o600)])
        b.emit_mv("s1", "a0")
        b.syscall("write", [("a0", "s1"), ("a1", "msg"), ("a2", len(f"rvmt_p2:{sample_id}\n"))])
        b.syscall("close", [("a0", "s0")])
        b.syscall("close", [("a0", "s1")])
    elif sample_id == "abnormal_syscall_sequence":
        b.syscall("close", [("a0", 200)])
        b.syscall("close", [("a0", 201)])
        b.syscall("close", [("a0", 202)])
        b.syscall("openat", [("a0", -100), ("a1", "missing"), ("a2", 0x80000), ("a3", 0)])
        b.syscall("read", [("a0", -1), ("a1", "buffer"), ("a2", 16)])
        b.syscall("write", [("a0", -1), ("a1", "msg"), ("a2", 1)])
    elif sample_id == "process_chain":
        b.syscall("clone", [("a0", 17), ("a1", 0), ("a2", 0), ("a3", 0), ("a4", 0)])
        b.syscall("execve", [("a0", "missing"), ("a1", "argv_true"), ("a2", 0)])
        b.syscall("waitid", [("a0", 1), ("a1", 1), ("a2", "buffer"), ("a3", 4), ("a4", 0)])
    elif sample_id == "dynamic_executable_memory":
        b.syscall("mmap", [("a0", 0), ("a1", 4096), ("a2", 3), ("a3", 0x22), ("a4", -1), ("a5", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("mprotect", [("a0", "s0"), ("a1", 4096), ("a2", 5)])
        b.syscall("munmap", [("a0", "s0"), ("a1", 4096)])
    elif sample_id == "anti_debug_like":
        b.syscall("clock_gettime", [("a0", 1), ("a1", "buffer")])
        b.syscall("ptrace", [("a0", 0), ("a1", 0), ("a2", 0), ("a3", 0)])
        b.syscall("openat", [("a0", -100), ("a1", "proc_status"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 128)])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "illegal_trap":
        b.busy_wait(ILLEGAL_TRAP_WARMUP_ITERATIONS)
        b.marker(RVMT_MARKER_BEGIN)
        b.syscall("rt_sigaction", [("a0", 4), ("a1", "sigaction"), ("a2", 0), ("a3", 8)])
        b.emit(inst_illegal())
        b.syscall("exit", [("a0", 1)])

        handler_pc = b.pc
        expected_handler = labels.get("sigill_handler")
        if expected_handler is not None and handler_pc != expected_handler:
            raise ValueError(f"sigill handler label mismatch: expected 0x{expected_handler:x}, got 0x{handler_pc:x}")
        labels["sigill_handler"] = handler_pc
        b.syscall("write", [("a0", 1), ("a1", "sigill_msg"), ("a2", len("synthetic SIGILL\n"))])
        b.marker(RVMT_MARKER_END)
        b.exit_zero()
    elif sample_id == "mirai_comprehensive":
        # Behavior 1: Encoded table — /proc/self/status read
        b.syscall("openat", [("a0", -100), ("a1", "proc_self_status"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 256)])
        b.syscall("close", [("a0", "s0")])
        # Behavior 1b: /proc/sys/kernel/pid_max read
        b.syscall("openat", [("a0", -100), ("a1", "proc_pid_max"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 64)])
        b.syscall("close", [("a0", "s0")])
        # Behavior 2: Process enumeration — getpid, getppid
        b.syscall("getpid", [])
        b.syscall("getppid", [])
        # readlinkat /proc/1/exe
        b.syscall("readlinkat", [("a0", -100), ("a1", "proc_1_exe"), ("a2", "buffer"), ("a3", 255)])
        # open /proc/1/status
        b.syscall("openat", [("a0", -100), ("a1", "proc_1_status"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 128)])
        b.syscall("close", [("a0", "s0")])
        # Behavior 3: Watchdog probe — 3 failed opens
        b.syscall("openat", [("a0", -100), ("a1", "safe_watchdog"), ("a2", 0x80000), ("a3", 0)])
        b.syscall("openat", [("a0", -100), ("a1", "safe_misc_watchdog"), ("a2", 0x80000), ("a3", 0)])
        b.syscall("openat", [("a0", -100), ("a1", "real_watchdog"), ("a2", 0x80000), ("a3", 0)])
        # Read pid_max again as sanity check
        b.syscall("openat", [("a0", -100), ("a1", "proc_pid_max"), ("a2", 0x80000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 64)])
        b.syscall("close", [("a0", "s0")])
        # Behavior 4: prctl PR_SET_NAME
        b.syscall("prctl", [("a0", 15), ("a1", "prctl_name"), ("a2", 0), ("a3", 0), ("a4", 0)])
        # Behavior 5: Singleton bind — socket + bind(loopback:48101) + listen + close
        b.syscall("socket", [("a0", 2), ("a1", 0x80001), ("a2", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("bind", [("a0", "s0"), ("a1", "bind_addr"), ("a2", 16)])
        b.syscall("listen", [("a0", "s0"), ("a1", 1)])
        b.syscall("close", [("a0", "s0")])
        # Behavior 6: Loopback C2 — socket + connect (fails) + close
        b.syscall("socket", [("a0", 2), ("a1", 0x80001), ("a2", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("connect", [("a0", "s0"), ("a1", "connect_addr"), ("a2", 16)])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "mirai_prctl_probe":
        b.syscall("prctl", [("a0", 15), ("a1", "prctl_name"), ("a2", 0), ("a3", 0), ("a4", 0)])
    elif sample_id == "mirai_socket_probe":
        b.syscall("socket", [("a0", 2), ("a1", 0x80001), ("a2", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("bind", [("a0", "s0"), ("a1", "bind_addr"), ("a2", 16)])
        b.syscall("listen", [("a0", "s0"), ("a1", 1)])
        b.syscall("close", [("a0", "s0")])
    elif sample_id == "mirai_connect_probe":
        b.syscall("socket", [("a0", 2), ("a1", 0x80001), ("a2", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("connect", [("a0", "s0"), ("a1", "connect_addr"), ("a2", 16)])
        b.syscall("close", [("a0", "s0")])
    else:
        raise ValueError(f"unsupported sample for deterministic syscall-only builder: {sample_id}")
    if sample_id != "illegal_trap":
        b.marker(RVMT_MARKER_END)
        b.exit_zero()
    return bytes(b.code)


def c_string_table(names: list[str]) -> tuple[bytes, dict[str, int]]:
    blob = bytearray(b"\x00")
    offsets: dict[str, int] = {"": 0}
    for name in names:
        offsets[name] = len(blob)
        blob.extend(name.encode("utf-8") + b"\x00")
    return bytes(blob), offsets


def section_header(name: int, sh_type: int, flags: int, addr: int, offset: int, size: int, link: int, info: int, addralign: int, entsize: int) -> bytes:
    return struct.pack("<IIQQQQIIQQ", name, sh_type, flags, addr, offset, size, link, info, addralign, entsize)


def symbol(name: int, info: int, shndx: int, value: int, size: int) -> bytes:
    return struct.pack("<IBBHQQ", name, info, 0, shndx, value, size)


def elf_header(entry: int, shoff: int, shnum: int, shstrndx: int) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    return ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        243,
        1,
        entry,
        64,
        shoff,
        0,
        64,
        56,
        2,
        64,
        shnum,
        shstrndx,
    )


def program_header(p_type: int, flags: int, offset: int, vaddr: int, filesz: int, memsz: int, align_value: int) -> bytes:
    return struct.pack("<IIQQQQQQ", p_type, flags, offset, vaddr, vaddr, filesz, memsz, align_value)


def build_elf(sample_id: str) -> tuple[bytes, dict[str, Any]]:
    rodata_values = rodata_for_sample(sample_id)
    rodata, rodata_offsets = add_rodata(rodata_values)
    text_vaddr = BASE_VADDR + TEXT_OFFSET
    # First generate a conservative text size to place rodata, then regenerate
    # with the final rodata address so PC-relative addresses are exact.
    rodata_vaddr_guess = align(text_vaddr + 512, 8)
    labels = labels_for_rodata(rodata_offsets, rodata_vaddr_guess)
    text = generate_text(sample_id, text_vaddr, labels)
    rodata_offset = align(TEXT_OFFSET + len(text), 8)
    rodata_vaddr = BASE_VADDR + rodata_offset
    labels = labels_for_rodata(rodata_offsets, rodata_vaddr)
    text = generate_text(sample_id, text_vaddr, labels)
    rodata_offset = align(TEXT_OFFSET + len(text), 8)
    rodata_vaddr = BASE_VADDR + rodata_offset
    labels = labels_for_rodata(rodata_offsets, rodata_vaddr)
    text = generate_text(sample_id, text_vaddr, labels)

    text_offset = TEXT_OFFSET
    text_size = len(text)
    data = bytearray(DATA_SIZE)
    # argv_true contains a pointer to /bin/true followed by a NULL pointer.
    struct.pack_into("<QQ", data, 0x100, labels.get("bin_true", 0), 0)

    # For mirai_comprehensive: pack sockaddr_in structs for bind/connect
    if sample_id == "mirai_comprehensive":
        # sockaddr_in: u16 family=2, u16 port=htons(48101), u32 addr=htonl(127.0.0.1), u8 pad[8]
        struct.pack_into("<HH", data, 0x200, 2, 0xE5BB)  # AF_INET, htons(48101)
        struct.pack_into("<I", data, 0x204, 0x0100007F)  # htonl(127.0.0.1)
        struct.pack_into("<HH", data, 0x210, 2, 0xE5BB)  # AF_INET, htons(48101)
        struct.pack_into("<I", data, 0x214, 0x0100007F)  # htonl(127.0.0.1)
    if sample_id == "illegal_trap":
        struct.pack_into("<QQQQ", data, 0x300, labels["sigill_handler"], 0, 0, 0)

    strtab_names = ["_start", "buffer", "argv_true"]
    if sample_id == "mirai_comprehensive":
        strtab_names.extend(["bind_addr", "connect_addr"])
    strtab, str_offsets = c_string_table(strtab_names)
    shstrtab, shstr_offsets = c_string_table([".text", ".rodata", ".data", ".symtab", ".strtab", ".shstrtab"])
    symtab_parts = [
        b"\x00" * 24,
        symbol(str_offsets["_start"], 0x12, 1, text_vaddr, text_size),
        symbol(str_offsets["buffer"], 0x11, 3, BASE_VADDR + DATA_OFFSET, DATA_SIZE),
        symbol(str_offsets["argv_true"], 0x11, 3, BASE_VADDR + DATA_OFFSET + 0x100, 16),
    ]
    if sample_id == "mirai_comprehensive":
        symtab_parts.extend([
            symbol(str_offsets["bind_addr"], 0x11, 3, BASE_VADDR + DATA_OFFSET + 0x200, 16),
            symbol(str_offsets["connect_addr"], 0x11, 3, BASE_VADDR + DATA_OFFSET + 0x210, 16),
        ])
    symtab = b"".join(symtab_parts)

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
        "schema": "rvmt.genesys2.safe_syscall_elf_build.v1",
        "sample_id": sample_id,
        "sample_class": SAFE_SAMPLE_CLASS,
        "real_malware": False,
        "binary_role": "linux_user_malware_like_synthetic_syscall_only",
        "builder": "tools/build_genesys2_safe_syscall_elf.py",
        "entry": f"0x{text_vaddr:016x}",
        "text_size": text_size,
        "data_size": DATA_SIZE,
        "runtime_map_warmup_iterations": RUNTIME_MAP_WARMUP_ITERATIONS,
        "syscall_sequence": syscall_sequence_for(sample_id),
        "marker_scope": {
            "enabled": True,
            "syscall_nr": SYSCALL_NUMBERS["rvmt_marker"],
            "begin_value_low32": f"0x{RVMT_MARKER_BEGIN:08x}",
            "end_value_low32": f"0x{RVMT_MARKER_END:08x}",
        },
        "source_relation": "syscall-shape surrogate generated from repository manifest; not compiled from real malware",
        "non_claims": [
            "No real malware validation is demonstrated.",
            "No real malware detection quality or efficacy is claimed.",
            "This binary is a safe syscall-only surrogate and is not current hardware trace evidence by itself.",
        ],
    }
    return bytes(content), metadata


def syscall_sequence_for(sample_id: str) -> list[str]:
    if sample_id == "file_scan":
        return ["rvmt_marker", "openat", "getdents64", "getdents64", "getdents64", "getdents64", "close", "rvmt_marker", "exit"]
    if sample_id == "batch_open_read_write":
        return ["rvmt_marker", "openat", "read", "close", "openat", "write", "close", "rvmt_marker", "exit"]
    if sample_id == "self_copy_sim":
        return ["rvmt_marker", "openat", "read", "openat", "write", "close", "close", "rvmt_marker", "exit"]
    if sample_id == "abnormal_syscall_sequence":
        return ["rvmt_marker", "close", "close", "close", "openat", "read", "write", "rvmt_marker", "exit"]
    if sample_id == "process_chain":
        return ["rvmt_marker", "clone", "execve", "waitid", "rvmt_marker", "exit"]
    if sample_id == "dynamic_executable_memory":
        return ["rvmt_marker", "mmap", "mprotect", "munmap", "rvmt_marker", "exit"]
    if sample_id == "anti_debug_like":
        return ["rvmt_marker", "clock_gettime", "ptrace", "openat", "read", "close", "rvmt_marker", "exit"]
    if sample_id == "illegal_trap":
        return ["rvmt_marker", "rt_sigaction", "write", "rvmt_marker", "exit"]
    if sample_id == "mirai_comprehensive":
        return [
            "openat", "read", "close",
            "openat", "read", "close",
            "getpid", "getppid",
            "readlinkat",
            "openat", "read", "close",
            "openat",
            "openat",
            "openat",
            "openat", "read", "close",
            "prctl",
            "socket", "bind", "listen", "close",
            "socket", "connect", "close",
            "exit",
        ]
    if sample_id == "mirai_prctl_probe":
        return ["prctl", "exit"]
    if sample_id == "mirai_socket_probe":
        return ["socket", "bind", "listen", "close", "exit"]
    if sample_id == "mirai_connect_probe":
        return ["socket", "connect", "close", "exit"]
    raise ValueError(f"unsupported sample: {sample_id}")


def build_one(root: Path, manifest: dict[str, Any], sample_id: str, out_dir: Path, code_map_dir: Path | None) -> Path:
    samples = samples_by_id(manifest)
    row = samples.get(sample_id)
    if row is None:
        raise ValueError(f"{sample_id}: not present in manifest")
    if row.get("class") != SAFE_SAMPLE_CLASS or row.get("real_malware") is not False:
        raise ValueError(f"{sample_id}: manifest row is not a safe synthetic sample")
    out_dir.mkdir(parents=True, exist_ok=True)
    elf, metadata = build_elf(sample_id)
    binary = out_dir / f"{sample_id}.riscv64"
    binary.write_bytes(elf)
    digest = hashlib.sha256(elf).hexdigest()
    source_path = root / str(row.get("source"))
    metadata.update(
        {
            "reference_manifest": repo_rel(root / DEFAULT_MANIFEST),
            "reference_source": row.get("source"),
            "reference_source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest() if source_path.is_file() else None,
            "binary": repo_rel(binary),
            "binary_sha256": digest,
            "runtime_path": f"{RUNTIME_ROOT}/{sample_id}",
            "expected_behavior": row.get("expected_behavior", []),
            "expected_syscalls": row.get("expected_syscalls", []),
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
            "linux_user_malware_like_synthetic_syscall_only",
            f"{RUNTIME_ROOT}/{sample_id}",
        )
        code_map.setdefault("notes", []).append(
            "Generated by tools/build_genesys2_safe_syscall_elf.py as a safe syscall-only surrogate; not hardware evidence."
        )
        code_map_path = write_outputs(code_map, code_map_dir, sample_id)
        shutil.copy2(code_map_path, code_map_dir / "code_map.json")
    return binary


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source_dir = root / "experiments/linux_behavior/malware_like/programs"
        source_dir.mkdir(parents=True)
        (source_dir / "file_scan.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        (source_dir / "illegal_trap.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        manifest = {
            "samples": [
                {
                    "id": "file_scan",
                    "class": SAFE_SAMPLE_CLASS,
                    "real_malware": False,
                    "source": "experiments/linux_behavior/malware_like/programs/file_scan.c",
                    "expected_syscalls": ["openat", "getdents64", "close"],
                    "expected_behavior": ["many_file_scan"],
                },
                {
                    "id": "illegal_trap",
                    "class": SAFE_SAMPLE_CLASS,
                    "real_malware": False,
                    "source": "experiments/linux_behavior/malware_like/programs/illegal_trap.c",
                    "expected_syscalls": ["write"],
                    "expected_behavior": ["illegal_instruction_trap"],
                },
                {
                    "id": "abnormal_syscall_sequence",
                    "class": SAFE_SAMPLE_CLASS,
                    "real_malware": False,
                    "source": "experiments/linux_behavior/malware_like/programs/file_scan.c",
                    "expected_syscalls": ["close", "openat", "read", "write"],
                    "expected_behavior": ["abnormal_syscall_sequence"],
                }
            ]
        }
        binary = build_one(root, manifest, "file_scan", root / "out", root / "code")
        if binary.read_bytes()[:4] != b"\x7fELF":
            print("[FAIL] self-test did not produce an ELF", file=sys.stderr)
            return 1
        code_map = load_json(root / "code/code_map.json")
        syscall_count = len(code_map.get("syscall_sites", []))
        if syscall_count != 9:
            print(f"[FAIL] self-test expected 9 syscall sites, got {syscall_count}", file=sys.stderr)
            return 1
        manifest_out = load_json(root / "out/build_manifest.json")
        if manifest_out.get("real_malware") is not False or "No real malware detection" not in " ".join(manifest_out.get("non_claims", [])):
            print("[FAIL] self-test missed claim boundary metadata", file=sys.stderr)
            return 1
        illegal_binary = build_one(root, manifest, "illegal_trap", root / "illegal_out", root / "illegal_code")
        illegal_manifest = load_json(root / "illegal_out/build_manifest.json")
        if illegal_manifest.get("syscall_sequence") != ["rvmt_marker", "rt_sigaction", "write", "rvmt_marker", "exit"]:
            print("[FAIL] illegal_trap self-test missed marker-aware syscall sequence", file=sys.stderr)
            return 1
        marker_scope = illegal_manifest.get("marker_scope", {})
        if marker_scope.get("enabled") is not True or marker_scope.get("syscall_nr") != 1023:
            print("[FAIL] illegal_trap self-test missed marker metadata", file=sys.stderr)
            return 1
        illegal_code_map = load_json(root / "illegal_code/code_map.json")
        illegal_syscall_count = len(illegal_code_map.get("syscall_sites", []))
        illegal_trap_count = len(illegal_code_map.get("trap_sites", []))
        if illegal_syscall_count != 6 or illegal_trap_count != 1:
            print(
                f"[FAIL] illegal_trap self-test expected 6 syscall sites and 1 trap site, "
                f"got {illegal_syscall_count} and {illegal_trap_count}",
                file=sys.stderr,
            )
            return 1
        if illegal_binary.read_bytes()[:4] != b"\x7fELF":
            print("[FAIL] illegal_trap self-test did not produce an ELF", file=sys.stderr)
            return 1
        abnormal_binary = build_one(root, manifest, "abnormal_syscall_sequence", root / "abnormal_out", root / "abnormal_code")
        abnormal_manifest = load_json(root / "abnormal_out/build_manifest.json")
        if abnormal_manifest.get("syscall_sequence") != [
            "rvmt_marker", "close", "close", "close", "openat", "read", "write", "rvmt_marker", "exit"
        ]:
            print("[FAIL] abnormal syscall self-test missed syscall sequence", file=sys.stderr)
            return 1
        abnormal_code_map = load_json(root / "abnormal_code/code_map.json")
        abnormal_syscall_count = len(abnormal_code_map.get("syscall_sites", []))
        if abnormal_syscall_count != 9:
            print(f"[FAIL] abnormal syscall self-test expected 9 syscall sites, got {abnormal_syscall_count}", file=sys.stderr)
            return 1
        if abnormal_binary.read_bytes()[:4] != b"\x7fELF":
            print("[FAIL] abnormal syscall self-test did not produce an ELF", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 safe syscall ELF builder self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build deterministic RISC-V Linux syscall-only safe surrogate ELFs for Genesys2 P2 prep.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--sample-id", action="append", default=[])
    parser.add_argument("--missing-from-coverage", type=Path)
    parser.add_argument("--out-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--code-map", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    try:
        root = args.root.resolve()
        manifest_path = args.manifest if args.manifest.is_absolute() else root / args.manifest
        manifest = load_json(manifest_path)
        samples = samples_by_id(manifest)
        sample_ids = list(args.sample_id)
        if args.missing_from_coverage:
            coverage_path = args.missing_from_coverage if args.missing_from_coverage.is_absolute() else root / args.missing_from_coverage
            coverage = load_json(coverage_path)
            sample_ids.extend(str(item) for item in coverage.get("missing_samples", []) if isinstance(item, str))
        if not sample_ids:
            sample_ids = sorted(samples)
        seen: set[str] = set()
        built: list[str] = []
        for sample_id in sample_ids:
            if sample_id in seen:
                continue
            seen.add(sample_id)
            sample_dir = args.out_root / sample_id
            if not sample_dir.is_absolute():
                sample_dir = root / sample_dir
            build_dir = sample_dir / "00_build_syscall_only"
            code_map_dir = sample_dir / "local_code_analysis" if args.code_map else None
            binary = build_one(root, manifest, sample_id, build_dir, code_map_dir)
            built.append(repo_rel(binary))
    except Exception as exc:
        print(f"build_genesys2_safe_syscall_elf: error: {exc}", file=sys.stderr)
        return 2
    for path in built:
        print(f"[PASS] built safe syscall-only surrogate ELF: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
