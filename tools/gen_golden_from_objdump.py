from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{4}|[0-9a-fA-F]{8})\s+\s*([a-z.0-9_]+)\s*(.*)$")
TARGET_RE = re.compile(r"\b([0-9a-fA-F]+)\b(?:\s+<[^>]+>)?\s*$")
BRANCH_OPS = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez"}
COMPRESSED_BRANCH_OPS = {"c.beqz", "c.bnez"}
JUMP_OPS = {"jal", "j", "jalr", "jr", "ret", "c.j", "c.jal", "c.jalr", "c.jr", "c.ret"}


def hex64(value: int) -> str:
    return f"0x{value:016x}"


def parse_objdump(text: str) -> list[dict[str, Any]]:
    required: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        pc_s, instr_s, op, operands = match.groups()
        op = op.lower()
        pc = int(pc_s, 16)
        instr = f"0x{int(instr_s, 16):0{len(instr_s)}x}"

        if op in BRANCH_OPS or op in COMPRESSED_BRANCH_OPS:
            target_match = TARGET_RE.search(operands)
            event: dict[str, Any] = {"evt": "BRANCH", "pc": hex64(pc), "instr": instr}
            if target_match:
                event["target"] = hex64(int(target_match.group(1), 16))
            required.append(event)
        elif op in JUMP_OPS:
            event = {"evt": "JUMP", "pc": hex64(pc), "instr": instr}
            target_match = TARGET_RE.search(operands)
            if target_match and op not in {"jalr", "jr", "ret"}:
                event["target"] = hex64(int(target_match.group(1), 16))
            required.append(event)
    return required


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate branch/jump golden skeleton from RISC-V objdump output.")
    parser.add_argument("objdump", type=Path)
    parser.add_argument("--test", required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    try:
        required_events = parse_objdump(args.objdump.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        print(f"gen_golden_from_objdump: error: {exc}", file=sys.stderr)
        return 2

    payload = {
        "test": args.test,
        "mode": "objdump_skeleton",
        "required_events": required_events,
    }
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
