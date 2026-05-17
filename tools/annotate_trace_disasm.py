from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{4}|[0-9a-fA-F]{8})\s+\s*([^\s]+)(?:\s+(.*))?$")
COMMENT_RE = re.compile(r"\s+#.*$")
DEFAULT_TOOL_PREFIX = "riscv-none-elf-"


@dataclass(frozen=True)
class DisasmEntry:
    pc: int
    instr: int
    width_bits: int
    asm: str


def parse_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 16) if text.startswith("0x") else int(text, 10)
        except ValueError:
            return None
    return None


def normalize_asm(mnemonic: str, operands: str | None) -> str:
    operand_text = COMMENT_RE.sub("", operands or "").strip()
    return " ".join(f"{mnemonic} {operand_text}".strip().split())


def parse_objdump(text: str) -> dict[int, DisasmEntry]:
    entries: dict[int, DisasmEntry] = {}
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        pc_s, instr_s, mnemonic, operands = match.groups()
        pc = int(pc_s, 16)
        entries[pc] = DisasmEntry(
            pc=pc,
            instr=int(instr_s, 16),
            width_bits=len(instr_s) * 4,
            asm=normalize_asm(mnemonic, operands),
        )
    return entries


def load_trace(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: trace event must be a JSON object")
            events.append(value)
    return events


def load_objdump(args: argparse.Namespace) -> tuple[str, str]:
    if args.objdump is not None:
        return args.objdump.read_text(encoding="utf-8", errors="replace"), str(args.objdump)
    if args.elf is None:
        raise ValueError("choose --objdump or --elf")
    tool = args.objdump_tool or f"{args.tool_prefix}objdump"
    completed = subprocess.run(
        [tool, "-d", str(args.elf)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode:
        raise RuntimeError(f"{tool} failed with exit code {completed.returncode}: {completed.stderr.strip()}")
    return completed.stdout, str(args.elf)


def annotate_events(
    events: list[dict[str, Any]],
    disasm: dict[int, DisasmEntry],
    *,
    source: str,
) -> tuple[list[dict[str, Any]], dict[str, int], list[str]]:
    annotated: list[dict[str, Any]] = []
    errors: list[str] = []
    stats = {
        "events": len(events),
        "annotated": 0,
        "missing_pc": 0,
        "missing_disasm": 0,
        "mismatched_instr": 0,
    }

    for index, event in enumerate(events):
        item = dict(event)
        pc = parse_int(event.get("pc"))
        if pc is None:
            stats["missing_pc"] += 1
            annotated.append(item)
            continue
        entry = disasm.get(pc)
        if entry is None:
            stats["missing_disasm"] += 1
            errors.append(f"event {index}: no disassembly for pc 0x{pc:016x}")
            annotated.append(item)
            continue
        item["asm"] = entry.asm
        item["asm_source"] = source
        trace_instr = parse_int(event.get("instr"))
        if trace_instr is not None:
            mask = (1 << entry.width_bits) - 1
            match = (trace_instr & mask) == entry.instr
            item["asm_match"] = match
            if not match:
                stats["mismatched_instr"] += 1
                warning = (
                    f"trace instr 0x{trace_instr:08x} does not match objdump "
                    f"0x{entry.instr:0{entry.width_bits // 4}x}"
                )
                item["asm_warning"] = warning
                errors.append(f"event {index}: {warning} at pc 0x{pc:016x}")
        stats["annotated"] += 1
        annotated.append(item)
    return annotated, stats, errors


def write_jsonl(events: list[dict[str, Any]], out: Path | None) -> None:
    lines = [json.dumps(event, separators=(",", ":"), ensure_ascii=False) for event in events]
    text = "\n".join(lines) + ("\n" if lines else "")
    if out is None:
        sys.stdout.write(text)
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8", newline="\n")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        trace = root / "trace.jsonl"
        dump = root / "program.dump"
        out = root / "trace.disasm.jsonl"
        trace.write_text(
            "\n".join(
                [
                    '{"cycle":1,"evt":"RETIRE","pc":"0x0000000080001000","instr":"0x00000513","priv":"M"}',
                    '{"cycle":2,"evt":"SYSCALL_ENTRY","pc":"0x0000000080001004","instr":"0x00000073","priv":"U"}',
                    '{"cycle":3,"evt":"JUMP","pc":"0x0000000080001008","instr":"0x0000a001","target":"0x0000000080001008"}',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        dump.write_text(
            """
0000000080001000 <main>:
    80001000: 00000513           li      a0,0
    80001004: 00000073           ecall
    80001008: a001               c.j     80001008 <main+0x8>
""",
            encoding="utf-8",
        )
        disasm = parse_objdump(dump.read_text(encoding="utf-8"))
        annotated_events, _, errors = annotate_events(load_trace(trace), disasm, source=str(dump))
        if errors:
            print(f"[FAIL] self-test strict annotation failed: {errors[0]}", file=sys.stderr)
            return 1
        write_jsonl(annotated_events, out)
        annotated = load_trace(out)
        if [event.get("asm") for event in annotated] != ["li a0,0", "ecall", "c.j 80001008 <main+0x8>"]:
            print("[FAIL] self-test produced unexpected asm fields", file=sys.stderr)
            return 1
        if not all(event.get("asm_match") is True for event in annotated):
            print("[FAIL] self-test did not mark instruction matches", file=sys.stderr)
            return 1

        bad_trace = root / "bad.trace.jsonl"
        bad_trace.write_text(
            '{"cycle":1,"evt":"RETIRE","pc":"0x0000000080001000","instr":"0x00000013","priv":"M"}\n',
            encoding="utf-8",
        )
        _, _, errors = annotate_events(load_trace(bad_trace), disasm, source=str(dump))
        if not any("does not match objdump" in error for error in errors):
            print("[FAIL] self-test missed strict instruction mismatch", file=sys.stderr)
            return 1

    print("[PASS] trace disassembly annotation self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Annotate rv-maltrace JSONL events with RISC-V disassembly.")
    parser.add_argument("--trace", type=Path, help="Input trace JSONL.")
    parser.add_argument("--objdump", type=Path, help="RISC-V objdump -d text output.")
    parser.add_argument("--elf", type=Path, help="ELF to disassemble with objdump.")
    parser.add_argument("--objdump-tool", help="Objdump executable. Defaults to <tool-prefix>objdump.")
    parser.add_argument("--tool-prefix", default=DEFAULT_TOOL_PREFIX)
    parser.add_argument("--out", type=Path, help="Output annotated JSONL. Defaults to stdout.")
    parser.add_argument("--strict", action="store_true", help="Fail if any PC is missing or any instruction word mismatches.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.trace is None:
        parser.error("--trace is required unless --self-test is used")
    try:
        objdump_text, source = load_objdump(args)
        disasm = parse_objdump(objdump_text)
        if not disasm:
            raise ValueError(f"no disassembly entries parsed from {source}")
        events = load_trace(args.trace)
        annotated, stats, errors = annotate_events(events, disasm, source=source)
        if args.strict and errors:
            for error in errors:
                print(f"[FAIL] {error}", file=sys.stderr)
            return 1
        write_jsonl(annotated, args.out)
    except Exception as exc:
        print(f"annotate_trace_disasm: error: {exc}", file=sys.stderr)
        return 2

    destination = args.out if args.out is not None else "stdout"
    print(
        "[PASS] annotated "
        f"{stats['annotated']}/{stats['events']} events with disassembly "
        f"(missing_disasm={stats['missing_disasm']}, mismatched_instr={stats['mismatched_instr']}) -> {destination}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
