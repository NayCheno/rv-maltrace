from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def repo_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
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


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(value)
    return rows


def range_rows(code_map: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rows = code_map.get(key, [])
    result = []
    if not isinstance(rows, list):
        return result
    for row in rows:
        if not isinstance(row, dict):
            continue
        start = parse_int(row.get("start"))
        end = parse_int(row.get("end"))
        if start is None or end is None:
            continue
        result.append({**row, "_start": start, "_end": end})
    return result


def exact_site_rows(code_map: dict[str, Any], key: str) -> dict[int, dict[str, Any]]:
    rows = code_map.get(key, [])
    result = {}
    if not isinstance(rows, list):
        return result
    for row in rows:
        if not isinstance(row, dict):
            continue
        pc = parse_int(row.get("pc"))
        if pc is not None:
            result[pc] = row
    return result


def code_map_index(code_map: dict[str, Any]) -> dict[str, Any]:
    return {
        "load_ranges": range_rows(code_map, "load_ranges"),
        "sections": range_rows(code_map, "sections"),
        "symbols": range_rows(code_map, "symbols"),
        "syscall_sites": exact_site_rows(code_map, "syscall_sites"),
        "trap_sites": exact_site_rows(code_map, "trap_sites"),
    }


def find_range(rows: list[dict[str, Any]], pc: int) -> dict[str, Any] | None:
    for row in rows:
        if int(row["_start"]) <= pc < int(row["_end"]):
            return row
    return None


def pc_annotation(pc_value: Any, code_map: dict[str, Any], index: dict[str, Any]) -> dict[str, Any]:
    pc = parse_int(pc_value)
    if pc is None:
        return {
            "pc_owner": "unknown",
            "callsite_kind": "unknown",
            "code_confidence": "missing_pc",
        }

    load = find_range(index["load_ranges"], pc)
    section = find_range(index["sections"], pc)
    symbol = find_range(index["symbols"], pc)
    syscall_site = index["syscall_sites"].get(pc)
    trap_site = index["trap_sites"].get(pc)

    if load is not None:
        callsite_kind = "normal_code"
        if syscall_site is not None:
            callsite_kind = "syscall_site"
        elif trap_site is not None:
            callsite_kind = f"{trap_site.get('kind', 'trap')}_site"
        result = {
            "pc_owner": "target_sample",
            "elf": code_map.get("elf"),
            "section": section.get("name") if section is not None else None,
            "symbol": symbol.get("name") if symbol is not None else None,
            "symbol_offset": f"0x{pc - int(symbol['_start']):x}" if symbol is not None else None,
            "callsite_kind": callsite_kind,
            "code_confidence": "pc_in_target_elf",
        }
        if trap_site is not None:
            result["trap_site"] = trap_site.get("kind")
        return {key: value for key, value in result.items() if value is not None}

    low32 = pc & 0xFFFFFFFF
    if low32 >= 0xC0000000:
        return {
            "pc_owner": "kernel",
            "callsite_kind": "unknown",
            "code_confidence": "pc_kernel_range_not_target",
        }
    return {
        "pc_owner": "unknown",
        "callsite_kind": "unknown",
        "code_confidence": "pc_not_in_target_elf",
    }


def annotate_event(event: dict[str, Any], code_map: dict[str, Any], index: dict[str, Any]) -> dict[str, Any]:
    annotated = dict(event)
    annotated.update(pc_annotation(event.get("pc"), code_map, index))
    if "target" in event:
        target = pc_annotation(event.get("target"), code_map, index)
        annotated["target_pc_owner"] = target.get("pc_owner")
        annotated["target_code_confidence"] = target.get("code_confidence")
        if target.get("symbol"):
            annotated["target_symbol"] = target.get("symbol")
    return annotated


def annotate_events(events: list[dict[str, Any]], code_map: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    index = code_map_index(code_map)
    annotated = [annotate_event(event, code_map, index) for event in events]
    owner_counts: dict[str, int] = {}
    callsite_counts: dict[str, int] = {}
    for event in annotated:
        owner = str(event.get("pc_owner", "unknown"))
        callsite = str(event.get("callsite_kind", "unknown"))
        owner_counts[owner] = owner_counts.get(owner, 0) + 1
        callsite_counts[callsite] = callsite_counts.get(callsite, 0) + 1
    return annotated, {
        "schema": "rvmt.trace_code_join.summary.v1",
        "sample_id": code_map.get("sample_id"),
        "binary_role": code_map.get("binary_role"),
        "runtime_path": code_map.get("runtime_path"),
        "elf": code_map.get("elf"),
        "events": len(annotated),
        "pc_owner_counts": dict(sorted(owner_counts.items())),
        "callsite_kind_counts": dict(sorted(callsite_counts.items())),
        "target_attributed_events": owner_counts.get("target_sample", 0),
    }


def write_jsonl(events: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")


def self_test() -> int:
    code_map = {
        "schema": "rvmt.code_map.v1",
        "sample_id": "self",
        "elf": "self.elf",
        "load_ranges": [{"start": "0x0000000000010000", "end": "0x0000000000011000", "segment": "text"}],
        "sections": [{"name": ".text", "start": "0x0000000000010000", "end": "0x0000000000011000"}],
        "symbols": [{"name": "main", "start": "0x0000000000010000", "end": "0x0000000000010100"}],
        "syscall_sites": [{"pc": "0x0000000000010004", "symbol": "main"}],
        "trap_sites": [{"pc": "0x0000000000010008", "symbol": "main", "kind": "illegal_instruction"}],
    }
    events = [
        {"evt": "SYSCALL_ENTRY", "pc": "0x0000000000010004"},
        {"evt": "TRAP", "pc": "0x0000000000010008"},
        {"evt": "TRAP", "pc": "0x00000000c0001000"},
    ]
    annotated, summary = annotate_events(events, code_map)
    if annotated[0].get("callsite_kind") != "syscall_site":
        print("[FAIL] join_trace_code_map missed syscall site", file=sys.stderr)
        return 1
    if annotated[1].get("callsite_kind") != "illegal_instruction_site":
        print("[FAIL] join_trace_code_map missed illegal site", file=sys.stderr)
        return 1
    if annotated[2].get("pc_owner") != "kernel":
        print("[FAIL] join_trace_code_map missed kernel classification", file=sys.stderr)
        return 1
    if summary["target_attributed_events"] != 2:
        print("[FAIL] join_trace_code_map summary mismatch", file=sys.stderr)
        return 1
    print("[PASS] join_trace_code_map self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Join RV-MalTrace JSONL events with a target ELF code map.")
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--code-map", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--summary-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.trace is None or args.code_map is None or args.out is None:
        parser.error("--trace, --code-map, and --out are required unless --self-test is used")
    try:
        events = load_jsonl(args.trace)
        code_map = load_json(args.code_map)
        annotated, summary = annotate_events(events, code_map)
        summary["trace"] = repo_rel(args.trace)
        summary["code_map"] = repo_rel(args.code_map)
        write_jsonl(annotated, args.out)
        if args.summary_out is not None:
            args.summary_out.parent.mkdir(parents=True, exist_ok=True)
            args.summary_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception as exc:
        print(f"join_trace_code_map: error: {exc}", file=sys.stderr)
        return 2
    print(f"[PASS] trace/code-map join written: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
