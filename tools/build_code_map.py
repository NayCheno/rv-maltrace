from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SHF_EXECINSTR = 0x4
SHT_SYMTAB = 2
SHT_DYNSYM = 11
PT_LOAD = 1
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4


@dataclass(frozen=True)
class ElfHeader:
    elf_class: int
    endian: str
    elf_type: int
    machine: int
    entry: int
    phoff: int
    shoff: int
    phentsize: int
    phnum: int
    shentsize: int
    shnum: int
    shstrndx: int


def repo_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def read_cstr(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", errors="replace")


def parse_header(data: bytes) -> ElfHeader:
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    elf_class = data[4]
    if data[5] != 1:
        raise ValueError("only little-endian ELF files are supported")
    endian = "<"
    if elf_class == 2:
        fields = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
        elf_type, machine, _, entry, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum, shstrndx = fields
    elif elf_class == 1:
        fields = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        elf_type, machine, _, entry, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum, shstrndx = fields
    else:
        raise ValueError(f"unsupported ELF class {elf_class}")
    return ElfHeader(
        elf_class=elf_class,
        endian=endian,
        elf_type=elf_type,
        machine=machine,
        entry=entry,
        phoff=phoff,
        shoff=shoff,
        phentsize=phentsize,
        phnum=phnum,
        shentsize=shentsize,
        shnum=shnum,
        shstrndx=shstrndx,
    )


def parse_program_headers(data: bytes, header: ElfHeader) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index in range(header.phnum):
        offset = header.phoff + index * header.phentsize
        if header.elf_class == 2:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                header.endian + "IIQQQQQQ", data, offset
            )
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
                header.endian + "IIIIIIII", data, offset
            )
        rows.append(
            {
                "index": index,
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "paddr": p_paddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
                "align": p_align,
            }
        )
    return rows


def parse_section_headers(data: bytes, header: ElfHeader) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index in range(header.shnum):
        offset = header.shoff + index * header.shentsize
        if header.elf_class == 2:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                header.endian + "IIQQQQIIQQ", data, offset
            )
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                header.endian + "IIIIIIIIII", data, offset
            )
        rows.append(
            {
                "index": index,
                "name_offset": sh_name,
                "type": sh_type,
                "flags": sh_flags,
                "addr": sh_addr,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "info": sh_info,
                "addralign": sh_addralign,
                "entsize": sh_entsize,
            }
        )
    if 0 <= header.shstrndx < len(rows):
        shstr = rows[header.shstrndx]
        blob = data[int(shstr["offset"]) : int(shstr["offset"]) + int(shstr["size"])]
        for row in rows:
            row["name"] = read_cstr(blob, int(row["name_offset"]))
    else:
        for row in rows:
            row["name"] = f"section_{row['index']}"
    return rows


def parse_symbols(data: bytes, header: ElfHeader, sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    symbols: list[dict[str, Any]] = []
    for section in sections:
        if section["type"] not in {SHT_SYMTAB, SHT_DYNSYM}:
            continue
        entsize = int(section.get("entsize") or (24 if header.elf_class == 2 else 16))
        if entsize <= 0:
            continue
        linked = int(section.get("link", 0))
        strtab = b""
        if 0 <= linked < len(sections):
            table = sections[linked]
            strtab = data[int(table["offset"]) : int(table["offset"]) + int(table["size"])]
        count = int(section["size"]) // entsize
        for index in range(count):
            offset = int(section["offset"]) + index * entsize
            if header.elf_class == 2:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(header.endian + "IBBHQQ", data, offset)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(header.endian + "IIIBBH", data, offset)
            name = read_cstr(strtab, int(st_name))
            if not name or st_value == 0:
                continue
            symbols.append(
                {
                    "name": name,
                    "start": st_value,
                    "end": st_value + st_size if st_size else st_value,
                    "size": st_size,
                    "bind": st_info >> 4,
                    "type": st_info & 0xF,
                    "section_index": st_shndx,
                    "symbol_table": section.get("name", ""),
                }
            )
    symbols.sort(key=lambda row: (int(row["start"]), int(row["end"]), str(row["name"])))
    for index, row in enumerate(symbols):
        if int(row["end"]) != int(row["start"]):
            continue
        next_start = None
        for other in symbols[index + 1 :]:
            if int(other["start"]) > int(row["start"]):
                next_start = int(other["start"])
                break
        row["end"] = next_start or (int(row["start"]) + 4)
        row["size_inferred"] = True
    return symbols


def permissions(flags: int) -> str:
    return "".join(letter for letter, mask in (("R", PF_R), ("W", PF_W), ("X", PF_X)) if flags & mask) or "-"


def elf_type_name(value: int) -> str:
    return {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(value, f"UNKNOWN_{value}")


def scan_sites(data: bytes, sections: list[dict[str, Any]], symbols: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    syscall_sites: list[dict[str, Any]] = []
    trap_sites: list[dict[str, Any]] = []

    def symbol_for(pc: int) -> tuple[str | None, int | None]:
        for symbol in symbols:
            if int(symbol["start"]) <= pc < int(symbol["end"]):
                return str(symbol["name"]), pc - int(symbol["start"])
        return None, None

    for section in sections:
        if not (int(section["flags"]) & SHF_EXECINSTR):
            continue
        blob = data[int(section["offset"]) : int(section["offset"]) + int(section["size"])]
        base = int(section["addr"])
        for offset in range(0, max(0, len(blob) - 3), 2):
            word = struct.unpack_from("<I", blob, offset)[0]
            pc = base + offset
            symbol, symbol_offset = symbol_for(pc)
            if word == 0x00000073:
                syscall_sites.append(
                    {
                        "pc": f"0x{pc:016x}",
                        "symbol": symbol,
                        "symbol_offset": f"0x{symbol_offset:x}" if symbol_offset is not None else None,
                        "section": section.get("name"),
                        "asm": "ecall",
                    }
                )
            elif word == 0xFFFFFFFF:
                trap_sites.append(
                    {
                        "pc": f"0x{pc:016x}",
                        "symbol": symbol,
                        "symbol_offset": f"0x{symbol_offset:x}" if symbol_offset is not None else None,
                        "section": section.get("name"),
                        "kind": "illegal_instruction",
                        "asm": ".word 0xffffffff",
                    }
                )
    return syscall_sites, trap_sites


def hex_range(row: dict[str, Any]) -> dict[str, Any]:
    return {
        **row,
        "start": f"0x{int(row['start']):016x}",
        "end": f"0x{int(row['end']):016x}",
    }


def build_code_map(
    elf: Path,
    sample_id: str,
    source: str | None = None,
    binary_role: str | None = None,
    runtime_path: str | None = None,
) -> dict[str, Any]:
    data = elf.read_bytes()
    header = parse_header(data)
    phdrs = parse_program_headers(data, header)
    sections_raw = parse_section_headers(data, header)
    symbols_raw = parse_symbols(data, header, sections_raw)
    syscall_sites, trap_sites = scan_sites(data, sections_raw, symbols_raw)
    load_ranges = []
    for row in phdrs:
        if row["type"] != PT_LOAD:
            continue
        load_ranges.append(
            {
                "start": int(row["vaddr"]),
                "end": int(row["vaddr"]) + int(row["memsz"]),
                "segment": "text" if int(row["flags"]) & PF_X else "data",
                "permissions": permissions(int(row["flags"])),
                "file_offset": f"0x{int(row['offset']):x}",
            }
        )
    sections = [
        {
            "name": section.get("name"),
            "start": int(section["addr"]),
            "end": int(section["addr"]) + int(section["size"]),
            "size": int(section["size"]),
            "flags": f"0x{int(section['flags']):x}",
            "type": int(section["type"]),
        }
        for section in sections_raw
        if int(section["addr"]) and int(section["size"])
    ]
    symbols = [
        {
            "name": row["name"],
            "start": int(row["start"]),
            "end": int(row["end"]),
            "size": int(row["size"]),
            "type": int(row["type"]),
            **({"size_inferred": True} if row.get("size_inferred") else {}),
        }
        for row in symbols_raw
    ]
    elf_type = elf_type_name(header.elf_type)
    load_base_assumption = "fixed_vaddr_exec" if elf_type == "EXEC" else "runtime_load_base_required"
    return {
        "schema": "rvmt.code_map.v1",
        "sample_id": sample_id,
        "source": source,
        "binary_role": binary_role,
        "runtime_path": runtime_path,
        "elf": repo_rel(elf),
        "sha256": hashlib.sha256(data).hexdigest(),
        "elf_type": elf_type,
        "load_base_assumption": load_base_assumption,
        "elf_header": {
            "class": "ELF64" if header.elf_class == 2 else "ELF32",
            "type": elf_type,
            "machine": header.machine,
            "entry": f"0x{header.entry:016x}",
        },
        "load_ranges": [hex_range(row) for row in load_ranges],
        "sections": [hex_range(row) for row in sections],
        "symbols": [hex_range(row) for row in symbols],
        "syscall_sites": syscall_sites,
        "trap_sites": trap_sites,
        "attribution_limitations": [
            "PC-in-ELF is static code-range evidence, not complete process attribution.",
            "Runtime load-base, PIE/ASLR, and exact board runtime ELF must be accounted for before strong process ownership claims.",
            "Target/process ownership still requires marker scope, PID/SATP/ASID, or runtime load-map evidence.",
        ],
        "notes": [
            "This is local ELF/code attribution metadata for synthetic behavior audit triage.",
            "It does not prove process ownership without target-scoped trace or OS context evidence.",
            "For board traces, use a code map generated from the exact board runtime ELF when available.",
            f"ELF type {elf_type}; load-base assumption: {load_base_assumption}.",
        ],
    }


def write_outputs(code_map: dict[str, Any], out_dir: Path, sample_id: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    prefix = out_dir / sample_id
    outputs = {
        "code_map": prefix.with_suffix(".code_map.json"),
        "sections": prefix.with_suffix(".sections.json"),
        "symbols": prefix.with_suffix(".symbols.json"),
        "syscall_sites": prefix.with_suffix(".syscall_sites.json"),
        "trap_sites": prefix.with_suffix(".trap_sites.json"),
    }
    outputs["code_map"].write_text(json.dumps(code_map, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    outputs["sections"].write_text(json.dumps(code_map["sections"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    outputs["symbols"].write_text(json.dumps(code_map["symbols"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    outputs["syscall_sites"].write_text(json.dumps(code_map["syscall_sites"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    outputs["trap_sites"].write_text(json.dumps(code_map["trap_sites"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return outputs["code_map"]


def self_test() -> int:
    elf = next((ROOT / "results" / "experiments" / "35t").glob("*/samples/*/*/build/*.riscv"), None)
    if elf is None:
        print("[SKIP] build_code_map self-test needs an existing .riscv artifact")
        return 0
    result = build_code_map(elf, elf.stem)
    if not result["load_ranges"] or not result["sections"]:
        print("[FAIL] code map missed load ranges or sections", file=sys.stderr)
        return 1
    if result["elf_header"]["machine"] != 243:
        print("[FAIL] code map parsed unexpected machine type", file=sys.stderr)
        return 1
    if result.get("load_base_assumption") not in {"fixed_vaddr_exec", "runtime_load_base_required"}:
        print("[FAIL] code map missed load-base attribution risk metadata", file=sys.stderr)
        return 1
    print("[PASS] build_code_map self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a target ELF code map for RV-MalTrace trace attribution.")
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--sample-id")
    parser.add_argument("--source")
    parser.add_argument("--binary-role")
    parser.add_argument("--runtime-path")
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.elf is None or args.sample_id is None or args.out_dir is None:
        parser.error("--elf, --sample-id, and --out-dir are required unless --self-test is used")
    try:
        code_map = build_code_map(args.elf, args.sample_id, args.source, args.binary_role, args.runtime_path)
        path = write_outputs(code_map, args.out_dir, args.sample_id)
    except Exception as exc:
        print(f"build_code_map: error: {exc}", file=sys.stderr)
        return 2
    print(f"[PASS] code map written: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
