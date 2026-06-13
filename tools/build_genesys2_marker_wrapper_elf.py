from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BASE_VADDR = 0x01000000
TEXT_OFFSET = 0x100
DATA_OFFSET = 0x2000
DATA_SIZE = 4096

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
    "exit": 93,
    "waitid": 95,
    "clone": 220,
    "execve": 221,
    "rvmt_marker": 1023,
}


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def parse_marker(value: str) -> int:
    return int(value, 16 if value.lower().startswith("0x") else 10) & 0xFFFFFFFF


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

    def patch(self, offset: int, instruction: bytes) -> None:
        self.code[offset : offset + 4] = instruction

    def emit_li(self, rd: str, value: int) -> None:
        self.emit(*li(rd, value))

    def emit_la(self, rd: str, label: str) -> None:
        self.emit(*la(rd, self.pc, self.labels[label]))

    def emit_mv(self, rd: str, rs: str) -> None:
        self.emit(inst_addi(rd, rs, 0))

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

    def exit(self, code: int) -> None:
        self.syscall("exit", [("a0", code)])
        self.emit(inst_ebreak())


def c_string_table(names: list[str]) -> tuple[bytes, dict[str, int]]:
    blob = bytearray(b"\x00")
    offsets: dict[str, int] = {"": 0}
    for name in names:
        offsets[name] = len(blob)
        blob.extend(name.encode("utf-8") + b"\x00")
    return bytes(blob), offsets


def add_rodata(strings: dict[str, bytes]) -> tuple[bytes, dict[str, int]]:
    blob = bytearray()
    offsets: dict[str, int] = {}
    for name, value in strings.items():
        while len(blob) % 8:
            blob.append(0)
        offsets[name] = len(blob)
        blob.extend(value)
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


def normalize_argv(exec_path: str, args: list[str]) -> list[str]:
    return args if args else [exec_path]


def rodata_for(exec_path: str, argv: list[str]) -> tuple[bytes, dict[str, int], list[str]]:
    strings: dict[str, bytes] = {"exec_path": exec_path.encode("utf-8") + b"\x00"}
    arg_labels: list[str] = []
    for index, arg in enumerate(argv):
        label = f"arg_{index}"
        arg_labels.append(label)
        strings[label] = arg.encode("utf-8") + b"\x00"
    rodata, offsets = add_rodata(strings)
    return rodata, offsets, arg_labels


def labels_for(rodata_offsets: dict[str, int], rodata_vaddr: int) -> dict[str, int]:
    labels = {name: rodata_vaddr + offset for name, offset in rodata_offsets.items()}
    labels["argv"] = BASE_VADDR + DATA_OFFSET
    labels["waitid_info"] = BASE_VADDR + DATA_OFFSET + 0x200
    return labels


def generate_text(labels: dict[str, int], begin_marker: int, end_marker: int) -> bytes:
    b = ProgramBuilder(BASE_VADDR + TEXT_OFFSET, labels)
    # The previous marker window can leave the BRAM ring frozen at end-marker.
    # Emit begin twice: the first unfreezes/clears, the second is captured as
    # the visible begin marker for this window.
    b.marker(begin_marker)
    b.marker(begin_marker)
    b.syscall("clone", [("a0", 17), ("a1", 0), ("a2", 0), ("a3", 0), ("a4", 0)])
    branch_offset = len(b.code)
    branch_pc = b.pc
    b.emit(inst_bne("a0", "zero", 0))
    b.syscall("execve", [("a0", "exec_path"), ("a1", "argv"), ("a2", 0)])
    b.exit(127)
    parent_pc = b.pc
    b.patch(branch_offset, inst_bne("a0", "zero", parent_pc - branch_pc))
    b.emit_mv("s0", "a0")
    b.syscall("waitid", [("a0", 1), ("a1", "s0"), ("a2", "waitid_info"), ("a3", 4), ("a4", 0)])
    b.marker(end_marker)
    b.exit(0)
    return bytes(b.code)


def build_elf(sample_id: str, exec_path: str, argv: list[str], begin_marker: int, end_marker: int) -> tuple[bytes, dict[str, Any]]:
    argv = normalize_argv(exec_path, argv)
    rodata, rodata_offsets, arg_labels = rodata_for(exec_path, argv)
    text = b""
    for _ in range(3):
        rodata_offset = align(TEXT_OFFSET + max(len(text), 256), 8)
        labels = labels_for(rodata_offsets, BASE_VADDR + rodata_offset)
        text = generate_text(labels, begin_marker, end_marker)
    rodata_offset = align(TEXT_OFFSET + len(text), 8)
    labels = labels_for(rodata_offsets, BASE_VADDR + rodata_offset)
    text = generate_text(labels, begin_marker, end_marker)

    data = bytearray(DATA_SIZE)
    argv_ptrs = [labels[label] for label in arg_labels] + [0]
    if len(argv_ptrs) * 8 > 0x200:
        raise ValueError("argv is too large for wrapper data layout")
    for index, pointer in enumerate(argv_ptrs):
        struct.pack_into("<Q", data, index * 8, pointer)

    strtab_names = ["_start", "argv", "waitid_info"]
    strtab, str_offsets = c_string_table(strtab_names)
    shstrtab, shstr_offsets = c_string_table([".text", ".rodata", ".data", ".symtab", ".strtab", ".shstrtab"])
    symtab = b"".join(
        [
            b"\x00" * 24,
            symbol(str_offsets["_start"], 0x12, 1, BASE_VADDR + TEXT_OFFSET, len(text)),
            symbol(str_offsets["argv"], 0x11, 3, BASE_VADDR + DATA_OFFSET, len(argv_ptrs) * 8),
            symbol(str_offsets["waitid_info"], 0x11, 3, BASE_VADDR + DATA_OFFSET + 0x200, 128),
        ]
    )

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
        section_header(shstr_offsets[".text"], 1, 0x6, BASE_VADDR + TEXT_OFFSET, TEXT_OFFSET, len(text), 0, 0, 4, 0),
        section_header(shstr_offsets[".rodata"], 1, 0x2, BASE_VADDR + rodata_offset, rodata_offset, len(rodata), 0, 0, 8, 0),
        section_header(shstr_offsets[".data"], 1, 0x3, BASE_VADDR + DATA_OFFSET, DATA_OFFSET, DATA_SIZE, 0, 0, 8, 0),
        section_header(shstr_offsets[".symtab"], 2, 0, 0, symtab_offset, len(symtab), 5, 1, 8, 24),
        section_header(shstr_offsets[".strtab"], 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0),
        section_header(shstr_offsets[".shstrtab"], 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0),
    ]
    content.extend(b"".join(section_headers))
    content[0:64] = elf_header(BASE_VADDR + TEXT_OFFSET, shoff, len(section_headers), 6)

    metadata = {
        "schema": "rvmt.genesys2.marker_wrapper_elf.v1",
        "sample_id": sample_id,
        "binary_role": "genesys2_marker_wrapper",
        "base_vaddr": f"0x{BASE_VADDR:016x}",
        "entry": f"0x{BASE_VADDR + TEXT_OFFSET:016x}",
        "exec_path": exec_path,
        "argv": argv,
        "syscall_sequence": ["rvmt_marker", "rvmt_marker", "clone", "execve", "waitid", "rvmt_marker", "exit"],
        "marker_scope": {
            "syscall_nr": SYSCALL_NUMBERS["rvmt_marker"],
            "begin_value_low32": f"0x{begin_marker:08x}",
            "end_value_low32": f"0x{end_marker:08x}",
        },
        "non_claims": [
            "The wrapper is only a marker-window helper and is not a substitute for the target ELF.",
            "Source-line attribution must be computed against the target debug/no-PIE ELF, not this wrapper.",
        ],
    }
    return bytes(content), metadata


def build_one(out: Path, sample_id: str, exec_path: str, argv: list[str], begin_marker: int, end_marker: int) -> Path:
    binary, metadata = build_elf(sample_id, exec_path, argv, begin_marker, end_marker)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(binary)
    digest = hashlib.sha256(binary).hexdigest()
    metadata["binary"] = repo_rel(out)
    metadata["binary_sha256"] = digest
    write_json(out.with_suffix(out.suffix + ".manifest.json"), metadata)
    out.with_suffix(out.suffix + ".sha256").write_text(f"{digest}  {out.name}\n", encoding="utf-8", newline="\n")
    return out


def self_test() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "wrap.riscv64"
        build_one(out, "self", "/bin/true", ["/bin/true"], 0xB0000001, 0xE0000001)
        data = out.read_bytes()
        if data[:4] != b"\x7fELF":
            print("[FAIL] wrapper is not an ELF", file=sys.stderr)
            return 1
        manifest = json.loads(out.with_suffix(out.suffix + ".manifest.json").read_text(encoding="utf-8"))
        if manifest.get("marker_scope", {}).get("end_value_low32") != "0xe0000001":
            print("[FAIL] wrapper manifest missed marker scope", file=sys.stderr)
            return 1
        if b"/bin/true\x00" not in data:
            print("[FAIL] wrapper missing argv string", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 marker wrapper ELF builder self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a minimal RISC-V marker wrapper that execs a target under begin/end rvmt_marker syscalls.")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--sample-id", default="wrapped")
    parser.add_argument("--exec-path")
    parser.add_argument("--arg", action="append", default=[])
    parser.add_argument("--begin-marker", required=False)
    parser.add_argument("--end-marker", required=False)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    missing = [name for name in ("out", "exec_path", "begin_marker", "end_marker") if getattr(args, name) is None]
    if missing:
        parser.error("missing required arguments: " + ", ".join("--" + name.replace("_", "-") for name in missing))
    try:
        out = args.out if args.out.is_absolute() else ROOT / args.out
        build_one(out, args.sample_id, args.exec_path, args.arg, parse_marker(args.begin_marker), parse_marker(args.end_marker))
    except Exception as exc:
        print(f"build_genesys2_marker_wrapper_elf: error: {exc}", file=sys.stderr)
        return 2
    print(f"[PASS] built marker wrapper ELF: {repo_rel(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
