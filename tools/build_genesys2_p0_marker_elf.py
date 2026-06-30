from __future__ import annotations

import argparse
import json
import shutil
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    repo_rel_from,
    sha256_file,
    write_json,
)

from build_code_map import build_code_map, write_outputs
from build_genesys2_safe_syscall_elf import (
    REG,
    align,
    c_string_table,
    elf_header,
    encode_b,
    inst_addi,
    inst_auipc,
    inst_ecall,
    inst_illegal,
    inst_lui,
    program_header,
    section_header,
    symbol,
    u32,
)


ROOT = Path(__file__).resolve().parents[1]
BASE_VADDR = 0x10000
TEXT_OFFSET = 0x100
DATA_OFFSET = 0x2000
DATA_SIZE = 4096
RUNTIME_ROOT = "/tmp/rvmt_p0"
DEFAULT_OUT_ROOT = Path("build/board/genesys2_cva6_p0_marker")
P0_SAMPLE_IDS = ("hello_write", "file_open_read_write", "fork_exec", "illegal_instruction")

RVMT_MARKER_SYSCALL_NR = 1023
MARKER_PAYLOADS = {
    "hello_write": 0x00000A01,
    "file_open_read_write": 0x00000A02,
    "fork_exec": 0x00000A03,
    "illegal_instruction": 0x00000A04,
}
WARMUP_ITERATIONS = 80_000_000

SYSCALL_NUMBERS = {
    "read": 63,
    "write": 64,
    "openat": 56,
    "close": 57,
    "clone": 220,
    "execve": 221,
    "wait4": 260,
    "rt_sigaction": 134,
    "exit": 93,
    "rvmt_marker": RVMT_MARKER_SYSCALL_NR,
}


repo_rel = repo_rel_from(ROOT)



def inst_beq(rs1: str, rs2: str, imm: int) -> bytes:
    return encode_b(imm, REG[rs1], REG[rs2], 0, 0x63)


def inst_jal(rd: str, imm: int) -> bytes:
    if imm % 2:
        raise ValueError(f"J-type immediate must be 2-byte aligned: {imm}")
    if not -(1 << 20) <= imm <= (1 << 20) - 2:
        raise ValueError(f"J-type immediate out of range: {imm}")
    imm21 = imm & 0x1FFFFF
    return u32(
        (((imm21 >> 20) & 0x1) << 31)
        | (((imm21 >> 1) & 0x3FF) << 21)
        | (((imm21 >> 11) & 0x1) << 20)
        | (((imm21 >> 12) & 0xFF) << 12)
        | (REG[rd] << 7)
        | 0x6F
    )


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


class P0Builder:
    def __init__(self, text_vaddr: int, labels: dict[str, int]):
        self.text_vaddr = text_vaddr
        self.labels = labels
        self.code = bytearray()
        self.fixups: list[tuple[int, str, str, tuple[str, str] | None]] = []

    @property
    def pc(self) -> int:
        return self.text_vaddr + len(self.code)

    def label(self, name: str) -> None:
        self.labels[name] = self.pc

    def emit(self, *instructions: bytes) -> None:
        for instruction in instructions:
            self.code.extend(instruction)

    def emit_li(self, rd: str, value: int) -> None:
        self.emit(*li(rd, value))

    def emit_la(self, rd: str, label: str) -> None:
        self.emit(*la(rd, self.pc, self.labels[label]))

    def emit_mv(self, rd: str, rs: str) -> None:
        self.emit(inst_addi(rd, rs, 0))

    def emit_beq_label(self, rs1: str, rs2: str, label: str) -> None:
        offset = len(self.code)
        self.fixups.append((offset, "beq", label, (rs1, rs2)))
        self.emit(u32(0))

    def emit_jump_label(self, label: str) -> None:
        offset = len(self.code)
        self.fixups.append((offset, "jal", label, None))
        self.emit(u32(0))

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

    def marker(self, value: int) -> None:
        self.syscall("rvmt_marker", [("a0", value), ("a1", 0), ("a2", 0), ("a3", 0)])

    def exit(self, status: int) -> None:
        self.syscall("exit", [("a0", status)])
        self.emit(u32(0x00100073))

    def warmup(self) -> None:
        self.emit_li("t0", WARMUP_ITERATIONS)
        loop_pc = self.pc
        self.emit(inst_addi("t0", "t0", -1))
        self.emit(encode_b(loop_pc - self.pc, REG["t0"], REG["zero"], 1, 0x63))

    def finalize(self) -> bytes:
        for offset, kind, label, regs in self.fixups:
            if label not in self.labels:
                raise ValueError(f"undefined label: {label}")
            pc = self.text_vaddr + offset
            target = self.labels[label]
            if kind == "beq":
                assert regs is not None
                patch = inst_beq(regs[0], regs[1], target - pc)
            elif kind == "jal":
                patch = inst_jal("zero", target - pc)
            else:
                raise ValueError(f"unknown fixup kind: {kind}")
            self.code[offset : offset + 4] = patch
        return bytes(self.code)


def marker_begin(sample_id: str) -> int:
    return 0xB0000000 | MARKER_PAYLOADS[sample_id]


def marker_end(sample_id: str) -> int:
    return 0xE0000000 | MARKER_PAYLOADS[sample_id]


def rodata_for_sample(sample_id: str) -> dict[str, bytes]:
    values = {
        "msg": f"rvmt_p0:{sample_id}\n".encode("ascii"),
        "file_path": b"/tmp/rvmt_p0_file_open_read_write.txt\x00",
        "file_seed": b"rvmt p0 file validation\n",
        "bin_true": b"/bin/true\x00",
        "sigill_msg": b"caught P0 SIGILL\n",
    }
    return values


def labels_for_rodata(rodata_offsets: dict[str, int], rodata_vaddr: int) -> dict[str, int]:
    labels = {name: rodata_vaddr + offset for name, offset in rodata_offsets.items()}
    labels["buffer"] = BASE_VADDR + DATA_OFFSET
    labels["status_word"] = BASE_VADDR + DATA_OFFSET + 0x80
    labels["argv_true"] = BASE_VADDR + DATA_OFFSET + 0x100
    labels["sigaction"] = BASE_VADDR + DATA_OFFSET + 0x300
    return labels


def generate_text(sample_id: str, text_vaddr: int, labels: dict[str, int]) -> bytes:
    b = P0Builder(text_vaddr, labels)
    begin = marker_begin(sample_id)
    end = marker_end(sample_id)

    b.warmup()
    b.marker(begin)

    if sample_id == "hello_write":
        b.syscall("write", [("a0", 1), ("a1", "msg"), ("a2", len(f"rvmt_p0:{sample_id}\n"))])
        b.marker(end)
        b.exit(0)

    elif sample_id == "file_open_read_write":
        seed_len = len("rvmt p0 file validation\n")
        b.syscall("openat", [("a0", -100), ("a1", "file_path"), ("a2", 0x00080241), ("a3", 0o644)])
        b.emit_mv("s0", "a0")
        b.syscall("write", [("a0", "s0"), ("a1", "file_seed"), ("a2", seed_len)])
        b.syscall("close", [("a0", "s0")])
        b.syscall("openat", [("a0", -100), ("a1", "file_path"), ("a2", 0x00080000), ("a3", 0)])
        b.emit_mv("s0", "a0")
        b.syscall("read", [("a0", "s0"), ("a1", "buffer"), ("a2", 128)])
        b.syscall("write", [("a0", 1), ("a1", "buffer"), ("a2", seed_len)])
        b.syscall("close", [("a0", "s0")])
        b.marker(end)
        b.exit(0)

    elif sample_id == "fork_exec":
        b.syscall("clone", [("a0", 17), ("a1", 0), ("a2", 0), ("a3", 0), ("a4", 0)])
        b.emit_mv("s0", "a0")
        b.emit_beq_label("a0", "zero", "child_exec")
        b.syscall("wait4", [("a0", "s0"), ("a1", "status_word"), ("a2", 0), ("a3", 0)])
        b.marker(end)
        b.exit(0)
        b.label("child_exec")
        b.syscall("execve", [("a0", "bin_true"), ("a1", "argv_true"), ("a2", 0)])
        b.exit(127)

    elif sample_id == "illegal_instruction":
        b.syscall("rt_sigaction", [("a0", 4), ("a1", "sigaction"), ("a2", 0), ("a3", 8)])
        b.emit(inst_illegal())
        b.exit(1)
        b.label("sigill_handler")
        b.syscall("write", [("a0", 1), ("a1", "sigill_msg"), ("a2", len("caught P0 SIGILL\n"))])
        b.marker(end)
        b.exit(0)

    else:
        raise ValueError(f"unsupported P0 sample: {sample_id}")

    return b.finalize()


def syscall_sequence_for(sample_id: str) -> list[str]:
    if sample_id == "hello_write":
        return ["rvmt_marker", "write", "rvmt_marker", "exit"]
    if sample_id == "file_open_read_write":
        return ["rvmt_marker", "openat", "write", "close", "openat", "read", "write", "close", "rvmt_marker", "exit"]
    if sample_id == "fork_exec":
        return ["rvmt_marker", "clone", "execve", "wait4", "rvmt_marker", "exit"]
    if sample_id == "illegal_instruction":
        return ["rvmt_marker", "rt_sigaction", "write", "rvmt_marker", "exit"]
    raise ValueError(f"unsupported P0 sample: {sample_id}")


def build_elf(sample_id: str) -> tuple[bytes, dict[str, Any]]:
    if sample_id not in P0_SAMPLE_IDS:
        raise ValueError(f"unsupported P0 sample: {sample_id}")

    rodata_values = rodata_for_sample(sample_id)
    rodata = bytearray()
    rodata_offsets: dict[str, int] = {}
    for name, value in rodata_values.items():
        while len(rodata) % 8:
            rodata.append(0)
        rodata_offsets[name] = len(rodata)
        rodata.extend(value)

    text_vaddr = BASE_VADDR + TEXT_OFFSET
    labels = labels_for_rodata(rodata_offsets, align(text_vaddr + 1024, 8))
    text = generate_text(sample_id, text_vaddr, labels)
    rodata_offset = align(TEXT_OFFSET + len(text), 8)
    labels = labels_for_rodata(rodata_offsets, BASE_VADDR + rodata_offset)
    text = generate_text(sample_id, text_vaddr, labels)
    rodata_offset = align(TEXT_OFFSET + len(text), 8)
    labels = labels_for_rodata(rodata_offsets, BASE_VADDR + rodata_offset)
    text = generate_text(sample_id, text_vaddr, labels)

    data = bytearray(DATA_SIZE)
    struct.pack_into("<QQ", data, 0x100, labels["bin_true"], 0)
    if sample_id == "illegal_instruction":
        struct.pack_into("<QQQQ", data, 0x300, labels["sigill_handler"], 0, 0, 0)

    strtab_names = ["_start", "buffer", "status_word", "argv_true"]
    if sample_id == "illegal_instruction":
        strtab_names.append("sigill_handler")
    strtab, str_offsets = c_string_table(strtab_names)
    shstrtab, shstr_offsets = c_string_table([".text", ".rodata", ".data", ".symtab", ".strtab", ".shstrtab"])

    symtab_parts = [
        b"\x00" * 24,
        symbol(str_offsets["_start"], 0x12, 1, text_vaddr, len(text)),
        symbol(str_offsets["buffer"], 0x11, 3, BASE_VADDR + DATA_OFFSET, 128),
        symbol(str_offsets["status_word"], 0x11, 3, BASE_VADDR + DATA_OFFSET + 0x80, 4),
        symbol(str_offsets["argv_true"], 0x11, 3, BASE_VADDR + DATA_OFFSET + 0x100, 16),
    ]
    if sample_id == "illegal_instruction":
        handler = labels["sigill_handler"]
        symtab_parts.append(symbol(str_offsets["sigill_handler"], 0x12, 1, handler, text_vaddr + len(text) - handler))
    symtab = b"".join(symtab_parts)

    content = bytearray()
    content.extend(b"\x00" * TEXT_OFFSET)
    content[TEXT_OFFSET : TEXT_OFFSET + len(text)] = text
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
        section_header(shstr_offsets[".text"], 1, 0x6, text_vaddr, TEXT_OFFSET, len(text), 0, 0, 4, 0),
        section_header(shstr_offsets[".rodata"], 1, 0x2, BASE_VADDR + rodata_offset, rodata_offset, len(rodata), 0, 0, 8, 0),
        section_header(shstr_offsets[".data"], 1, 0x3, BASE_VADDR + DATA_OFFSET, DATA_OFFSET, DATA_SIZE, 0, 0, 8, 0),
        section_header(shstr_offsets[".symtab"], 2, 0, 0, symtab_offset, len(symtab), 5, 1, 8, 24),
        section_header(shstr_offsets[".strtab"], 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0),
        section_header(shstr_offsets[".shstrtab"], 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0),
    ]
    content.extend(b"".join(section_headers))
    content[0:64] = elf_header(text_vaddr, shoff, len(section_headers), 6)

    metadata = {
        "schema": "rvmt.genesys2.p0_marker_elf_build.v1",
        "sample_id": sample_id,
        "sample_class": "p0_safe_synthetic",
        "real_malware": False,
        "binary_role": "linux_user_p0_marker_syscall_only",
        "builder": "tools/build_genesys2_p0_marker_elf.py",
        "entry": f"0x{text_vaddr:016x}",
        "text_size": len(text),
        "data_size": DATA_SIZE,
        "runtime_path": f"{RUNTIME_ROOT}/{sample_id}",
        "syscall_sequence": syscall_sequence_for(sample_id),
        "marker_scope": {
            "enabled": True,
            "syscall_nr": RVMT_MARKER_SYSCALL_NR,
            "begin_value_low32": f"0x{marker_begin(sample_id):08x}",
            "end_value_low32": f"0x{marker_end(sample_id):08x}",
            "payload_low28": f"0x{MARKER_PAYLOADS[sample_id]:07x}",
        },
        "warmup_iterations_before_marker": WARMUP_ITERATIONS,
        "non_claims": [
            "This is a repository-authored safe synthetic P0 workload, not real malware.",
            "This binary alone is not board evidence until paired with Genesys2/CVA6 trace artifacts.",
            "No malware detection quality or real malware validation is claimed.",
        ],
    }
    return bytes(content), metadata


def build_one(sample_id: str, out_root: Path, code_map: bool) -> Path:
    sample_dir = out_root / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    elf, metadata = build_elf(sample_id)
    binary = sample_dir / f"{sample_id}.riscv64"
    binary.write_bytes(elf)
    metadata["binary"] = repo_rel(binary)
    metadata["binary_sha256"] = sha256_file(binary)
    write_json(sample_dir / "build_manifest.json", metadata)
    (sample_dir / "riscv64_elf.sha256").write_text(
        f"{metadata['binary_sha256']}  {binary.name}\n", encoding="utf-8", newline="\n"
    )
    if code_map:
        code_dir = sample_dir / "code_map"
        mapping = build_code_map(
            binary,
            sample_id,
            f"board/trace_validation/programs/{sample_id}.c",
            "linux_user_p0_marker_syscall_only",
            f"{RUNTIME_ROOT}/{sample_id}",
        )
        mapping.setdefault("notes", []).append("Generated marker-scoped P0 syscall-only ELF; safe synthetic workload.")
        code_map_path = write_outputs(mapping, code_dir, sample_id)
        shutil.copy2(code_map_path, code_dir / "code_map.json")
    return binary


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for sample_id in P0_SAMPLE_IDS:
            binary = build_one(sample_id, root / "out", code_map=True)
            if binary.read_bytes()[:4] != b"\x7fELF":
                print(f"[FAIL] {sample_id}: missing ELF magic", file=sys.stderr)
                return 1
            manifest = json.loads((binary.parent / "build_manifest.json").read_text(encoding="utf-8"))
            if manifest.get("real_malware") is not False or manifest.get("marker_scope", {}).get("enabled") is not True:
                print(f"[FAIL] {sample_id}: missing safety/marker metadata", file=sys.stderr)
                return 1
            mapping = json.loads((binary.parent / "code_map/code_map.json").read_text(encoding="utf-8"))
            if not mapping.get("syscall_sites"):
                print(f"[FAIL] {sample_id}: code map missed syscall sites", file=sys.stderr)
                return 1
            if sample_id == "illegal_instruction" and not mapping.get("trap_sites"):
                print("[FAIL] illegal_instruction: code map missed trap site", file=sys.stderr)
                return 1
    print("[PASS] Genesys2 P0 marker ELF builder self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build marker-scoped syscall-only P0 ELFs for Genesys2/CVA6 trace closure.")
    parser.add_argument("--sample-id", action="append", choices=P0_SAMPLE_IDS, default=[])
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT)
    parser.add_argument("--code-map", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        out_root = args.out_root if args.out_root.is_absolute() else ROOT / args.out_root
        sample_ids = args.sample_id or list(P0_SAMPLE_IDS)
        for sample_id in sample_ids:
            binary = build_one(sample_id, out_root, args.code_map)
            print(f"[PASS] built {sample_id}: {repo_rel(binary)}")
    except Exception as exc:
        print(f"build_genesys2_p0_marker_elf: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
