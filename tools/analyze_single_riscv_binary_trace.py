from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from build_code_map import build_code_map
from join_trace_code_map import annotate_events, load_json
from view_trace_terminal import cell, colorize, event_name, load_jsonl, parse_int, render_timeline, use_color


RISC_V_MACHINE = 243
HEX_ADDRESS_KEYS = ("start", "end", "pc")
RANGE_TABLES = ("load_ranges", "sections", "symbols", "function_ranges")
SITE_TABLES = ("syscall_sites", "trap_sites", "source_locations")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def hex_addr(value: int) -> str:
    return f"0x{value:016x}"


def parse_address(value: Any) -> int | None:
    parsed = parse_int(value)
    if parsed is None:
        return None
    return parsed


def shift_address_fields(row: dict[str, Any], delta: int) -> dict[str, Any]:
    shifted = dict(row)
    for key in HEX_ADDRESS_KEYS:
        if key not in shifted:
            continue
        value = parse_address(shifted[key])
        if value is not None:
            shifted[key] = hex_addr(value + delta)
    return shifted


def apply_runtime_load_base(code_map: dict[str, Any], load_base: int | None) -> dict[str, Any]:
    if load_base is None:
        return code_map
    shifted = copy.deepcopy(code_map)
    shifted["runtime_load_base"] = hex_addr(load_base)
    shifted["load_base_applied"] = True
    shifted["load_base_assumption"] = f"{code_map.get('load_base_assumption', 'unknown')} + runtime_load_base"
    for table in RANGE_TABLES:
        rows = shifted.get(table)
        if isinstance(rows, list):
            shifted[table] = [shift_address_fields(row, load_base) if isinstance(row, dict) else row for row in rows]
    for table in SITE_TABLES:
        rows = shifted.get(table)
        if isinstance(rows, list):
            shifted[table] = [shift_address_fields(row, load_base) if isinstance(row, dict) else row for row in rows]
    header = shifted.get("elf_header")
    if isinstance(header, dict):
        entry = parse_address(header.get("entry"))
        if entry is not None:
            header["entry_runtime"] = hex_addr(entry + load_base)
    return shifted


def validate_riscv_code_map(code_map: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    header = code_map.get("elf_header") if isinstance(code_map.get("elf_header"), dict) else {}
    if header.get("machine") != RISC_V_MACHINE:
        errors.append(f"ELF machine is {header.get('machine')}, expected RISC-V machine {RISC_V_MACHINE}")
    if not code_map.get("load_ranges"):
        errors.append("ELF code map has no PT_LOAD ranges")
    return errors


def count_by(rows: list[dict[str, Any]], key: str, default: str = "unknown") -> Counter[str]:
    return Counter(str(row.get(key) or default) for row in rows)


def range_rows(code_map: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rows = code_map.get(key, [])
    result: list[dict[str, Any]] = []
    if not isinstance(rows, list):
        return result
    for row in rows:
        if not isinstance(row, dict):
            continue
        start = parse_address(row.get("start"))
        end = parse_address(row.get("end"))
        if start is None or end is None:
            continue
        result.append({**row, "_start": start, "_end": end})
    return result


def find_range(rows: list[dict[str, Any]], pc: int) -> dict[str, Any] | None:
    for row in rows:
        if int(row["_start"]) <= pc < int(row["_end"]):
            return row
    return None


def enrich_function_annotations(rows: list[dict[str, Any]], code_map: dict[str, Any]) -> list[dict[str, Any]]:
    functions = range_rows(code_map, "function_ranges")
    enriched: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        pc = parse_address(item.get("pc"))
        function = find_range(functions, pc) if pc is not None else None
        if function is not None:
            item["analysis_function"] = function.get("function")
            item["analysis_function_offset"] = f"0x{pc - int(function['_start']):x}" if pc is not None else None
            if function.get("source_file") and function.get("source_line") is not None:
                item.setdefault("source_file", function.get("source_file"))
                item.setdefault("source_line", function.get("source_line"))
                item.setdefault("source_function", function.get("function"))
        enriched.append(item)
    return enriched


def target_function(row: dict[str, Any]) -> str:
    if row.get("analysis_function"):
        offset = row.get("analysis_function_offset")
        return f"{row['analysis_function']}+{offset}" if offset else str(row["analysis_function"])
    if row.get("source_function"):
        return str(row["source_function"])
    if row.get("pc_owner") == "target_sample":
        return "<target_no_function>"
    if row.get("symbol"):
        offset = row.get("symbol_offset")
        return f"{row['symbol']}+{offset}" if offset else str(row["symbol"])
    owner = str(row.get("pc_owner") or "unknown")
    return f"<{owner}>"


def function_counter(rows: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for row in rows:
        if row.get("pc_owner") == "target_sample":
            counter[str(row.get("analysis_function") or row.get("source_function") or "<target_no_function>")] += 1
    return counter


def bar(count: int, max_count: int, width: int = 32) -> str:
    if max_count <= 0:
        return ""
    filled = max(1 if count else 0, round(count * width / max_count))
    return "#" * filled


def summary_from_analysis(
    *,
    trace: Path,
    elf: Path,
    code_map: dict[str, Any],
    annotated: list[dict[str, Any]],
    join_summary: dict[str, Any],
    load_base: int | None,
) -> dict[str, Any]:
    pc_events = [row for row in annotated if parse_address(row.get("pc")) is not None]
    target_events = [row for row in pc_events if row.get("pc_owner") == "target_sample"]
    source_events = [row for row in target_events if row.get("source_file") and row.get("source_line")]
    functions = function_counter(annotated)
    function_events = sum(count for name, count in functions.items() if name != "<target_no_function>")
    warnings: list[str] = []
    if code_map.get("elf_type") == "DYN" and load_base is None:
        warnings.append("ELF is DYN/PIE; pass --load-base when trace PCs are runtime relocated.")
    if pc_events and not target_events:
        warnings.append("No trace PC matched the specified ELF load ranges; check binary identity or load base.")
    if target_events and not function_events:
        warnings.append("Trace PCs matched the ELF load range but not any function range; verify this is the exact runtime ELF.")
    if not source_events and function_events:
        warnings.append("No source-line hits in the trace; function-level attribution is available for matched functions only.")
    elif not source_events:
        warnings.append("No source-line hits in the trace; verify exact runtime ELF identity and retained DWARF/debug info.")
    status = "PASS" if target_events else "WARN_NO_TARGET_PC_MATCH"
    return {
        "schema": "rvmt.single_binary_trace_analysis.v1",
        "status": status,
        "trace": str(trace),
        "elf": str(elf),
        "elf_sha256": code_map.get("sha256"),
        "elf_header": code_map.get("elf_header"),
        "elf_type": code_map.get("elf_type"),
        "load_base_assumption": code_map.get("load_base_assumption"),
        "runtime_load_base": hex_addr(load_base) if load_base is not None else None,
        "events": len(annotated),
        "pc_events": len(pc_events),
        "target_pc_events": len(target_events),
        "target_pc_rate": (len(target_events) / len(pc_events)) if pc_events else 0.0,
        "function_events": function_events,
        "function_rate": (function_events / len(target_events)) if target_events else 0.0,
        "source_line_events": len(source_events),
        "source_line_rate": (len(source_events) / len(target_events)) if target_events else 0.0,
        "event_counts": dict(sorted(count_by(annotated, "evt").items())),
        "pc_owner_counts": dict(sorted(count_by(annotated, "pc_owner").items())),
        "callsite_kind_counts": dict(sorted(count_by(annotated, "callsite_kind").items())),
        "top_functions": [{"function": name, "events": count} for name, count in functions.most_common(12)],
        "marker_scope": join_summary.get("marker_scope"),
        "source_attribution": join_summary.get("source_attribution"),
        "warnings": warnings,
        "claim_boundary": {
            "single_binary_static_attribution": True,
            "riscv_elf_machine_required": True,
            "process_ownership_claimed_without_runtime_map": False,
            "real_malware_validation_claimed": False,
        },
    }


def render_top_counter(title: str, counter: Counter[str], *, color: bool, color_evt: str | None = None, limit: int = 10) -> list[str]:
    lines = [title]
    if not counter:
        return [*lines, "  <none>"]
    max_count = max(counter.values())
    for name, count in counter.most_common(limit):
        label = colorize(name, color_evt, color)
        lines.append(f"  {cell(label, 36)} {str(count).rjust(6)} | {bar(count, max_count)}")
    return lines


def render_binary_header(summary: dict[str, Any]) -> list[str]:
    header = summary.get("elf_header") if isinstance(summary.get("elf_header"), dict) else {}
    return [
        "RV-MalTrace Single Binary Trace Analysis",
        f"ELF: {summary.get('elf')}",
        f"Trace: {summary.get('trace')}",
        f"ELF identity: {header.get('class')} {summary.get('elf_type')} machine={header.get('machine')} sha256={summary.get('elf_sha256')}",
        f"Entry: {header.get('entry')}  Runtime base: {summary.get('runtime_load_base') or 'not applied'}",
        f"Load-base assumption: {summary.get('load_base_assumption')}",
        f"Status: {summary.get('status')}",
    ]


def render_key_events(rows: list[dict[str, Any]], limit: int, color: bool) -> list[str]:
    interesting = [
        row
        for row in rows
        if str(row.get("evt") or "").upper() in {"MARKER", "SYSCALL_ENTRY", "SYSCALL_RET", "TRAP", "ARG_MEM"}
        or row.get("pc_owner") == "target_sample"
    ]
    lines = [
        f"Key Events (showing {min(limit, len(interesting))} of {len(interesting)})",
        "  "
        + " ".join(
            [
                cell("#", 5),
                cell("seq", 7),
                cell("cycle", 12),
                cell("evt", 14),
                cell("pc", 12),
                cell("owner", 14),
                cell("function", 30),
                cell("site", 18),
                "source",
            ]
        ),
    ]
    if not interesting:
        return [*lines, "  <none>"]
    for index, row in enumerate(interesting[:limit]):
        evt = str(row.get("evt") or "NONE").upper()
        source = ""
        if row.get("source_file") and row.get("source_line"):
            source = f"{row.get('source_file')}:{row.get('source_line')}"
        lines.append(
            "  "
            + " ".join(
                [
                    cell(index, 5),
                    cell(row.get("sequence_number") if row.get("sequence_number") is not None else row.get("seq"), 7),
                    cell(row.get("cycle"), 12),
                    cell(colorize(evt, evt, color), 14),
                    cell(row.get("pc"), 12),
                    cell(row.get("pc_owner"), 14),
                    cell(target_function(row), 30),
                    cell(row.get("callsite_kind"), 18),
                    source,
                ]
            ).rstrip()
        )
    if len(interesting) > limit:
        lines.append(f"  ... {len(interesting) - limit} more key events; raise --limit to show more")
    return lines


def render_console(
    trace: Path,
    annotated: list[dict[str, Any]],
    summary: dict[str, Any],
    *,
    limit: int,
    width: int,
    color: bool,
) -> str:
    functions = function_counter(annotated)
    warnings = summary.get("warnings") if isinstance(summary.get("warnings"), list) else []
    lines = [
        *render_binary_header(summary),
        "",
        "Trace Match",
        f"  events={summary.get('events')} pc_events={summary.get('pc_events')} target_pc_events={summary.get('target_pc_events')} target_pc_rate={summary.get('target_pc_rate'):.3f}",
        f"  function_events={summary.get('function_events')} function_rate={summary.get('function_rate'):.3f} source_line_events={summary.get('source_line_events')} source_line_rate={summary.get('source_line_rate'):.3f}",
        "",
        *render_timeline(annotated, width, color),
        "",
        *render_top_counter("PC Owner Mix", count_by(annotated, "pc_owner"), color=color),
        "",
        *render_top_counter("Callsite Mix", count_by(annotated, "callsite_kind"), color=color),
        "",
        *render_top_counter("Target Function Hotspots", functions, color=color, color_evt="SYSCALL_ENTRY"),
        "",
        *render_key_events(annotated, limit, color),
    ]
    if warnings:
        lines.extend(["", "Warnings", *[f"  - {warning}" for warning in warnings]])
    lines.extend(
        [
            "",
            "Claim Boundary",
            "  Static PC-in-ELF matching is single-binary attribution, not process ownership by itself.",
            "  Strong process ownership still needs marker/runtime process map context.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_markdown(summary: dict[str, Any], annotated: list[dict[str, Any]]) -> str:
    functions = function_counter(annotated)
    rows = [
        "# RV-MalTrace Single Binary Trace Analysis",
        "",
        f"- ELF: `{summary.get('elf')}`",
        f"- Trace: `{summary.get('trace')}`",
        f"- Status: `{summary.get('status')}`",
        f"- Target PC rate: `{summary.get('target_pc_rate'):.3f}`",
        f"- Function rate: `{summary.get('function_rate'):.3f}`",
        f"- Source-line rate: `{summary.get('source_line_rate'):.3f}`",
        "",
        "## Top Functions",
        "",
    ]
    if functions:
        for name, count in functions.most_common(12):
            rows.append(f"- `{name}`: {count}")
    else:
        rows.append("- `<none>`")
    warnings = summary.get("warnings") if isinstance(summary.get("warnings"), list) else []
    if warnings:
        rows.extend(["", "## Warnings", ""])
        rows.extend(f"- {warning}" for warning in warnings)
    return "\n".join(rows) + "\n"


def analyze(
    *,
    trace: Path,
    elf: Path,
    sample_id: str,
    load_base: int | None,
    runtime_process_map: Path | None,
    addr2line: str | None,
    out_dir: Path | None,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Path]]:
    code_map = build_code_map(elf, sample_id, binary_role="single_riscv_binary", addr2line_tool=addr2line)
    errors = validate_riscv_code_map(code_map)
    if errors:
        raise ValueError("; ".join(errors))
    code_map = apply_runtime_load_base(code_map, load_base)
    events = load_jsonl(trace)
    runtime_map = load_json(runtime_process_map) if runtime_process_map is not None else None
    annotated, join_summary = annotate_events(events, code_map, runtime_map)
    annotated = enrich_function_annotations(annotated, code_map)
    summary = summary_from_analysis(
        trace=trace,
        elf=elf,
        code_map=code_map,
        annotated=annotated,
        join_summary=join_summary,
        load_base=load_base,
    )
    outputs: dict[str, Path] = {}
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        code_map_path = out_dir / f"{sample_id}.code_map.json"
        annotated_path = out_dir / f"{sample_id}.annotated_trace.jsonl"
        summary_path = out_dir / f"{sample_id}.analysis_summary.json"
        write_json(code_map_path, code_map)
        write_jsonl(annotated_path, annotated)
        write_json(summary_path, summary)
        outputs = {"code_map": code_map_path, "annotated_trace": annotated_path, "summary": summary_path}
    return annotated, summary, outputs


def self_test() -> int:
    code_map = {
        "schema": "rvmt.code_map.v1",
        "sample_id": "fixture",
        "elf": "fixture.riscv64",
        "sha256": "00" * 32,
        "elf_type": "EXEC",
        "load_base_assumption": "fixed_vaddr_exec",
        "elf_header": {"class": "ELF64", "type": "EXEC", "machine": RISC_V_MACHINE, "entry": "0x0000000000010000"},
        "load_ranges": [{"start": "0x0000000000010000", "end": "0x0000000000011000", "segment": "text"}],
        "sections": [{"name": ".text", "start": "0x0000000000010000", "end": "0x0000000000011000"}],
        "symbols": [{"name": "main", "start": "0x0000000000010000", "end": "0x0000000000010100"}],
        "function_ranges": [{"function": "main", "start": "0x0000000000010000", "end": "0x0000000000010100"}],
        "syscall_sites": [{"pc": "0x0000000000010004", "symbol": "main", "asm": "ecall"}],
        "trap_sites": [{"pc": "0x0000000000010008", "symbol": "main", "kind": "illegal_instruction"}],
        "source_locations": [{"pc": "0x0000000000010004", "function": "main", "file": "fixture.c", "line": 3}],
    }
    events = [
        {"evt": "MARKER", "value": "0xb0000001", "cycle": 1, "pc": "0x0000000000010000", "sequence_number": 0},
        {"evt": "SYSCALL_ENTRY", "cycle": 2, "pc": "0x0000000000010004", "sequence_number": 1},
        {"evt": "TRAP", "cycle": 3, "pc": "0x0000000000010008", "sequence_number": 2},
        {"evt": "MARKER", "value": "0xe0000001", "cycle": 4, "pc": "0x000000000001000c", "sequence_number": 3},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        trace = root / "trace.jsonl"
        trace.write_text("".join(json.dumps(row) + "\n" for row in events), encoding="utf-8")
        annotated, join_summary = annotate_events(load_jsonl(trace), code_map)
        summary = summary_from_analysis(
            trace=trace,
            elf=root / "fixture.riscv64",
            code_map=code_map,
            annotated=annotated,
            join_summary=join_summary,
            load_base=None,
        )
        text = render_console(trace, annotated, summary, limit=8, width=32, color=False)
    if summary["status"] != "PASS" or summary["target_pc_events"] != 4:
        print("[FAIL] single-binary analysis self-test summary mismatch", file=sys.stderr)
        return 1
    for required in ("Single Binary Trace Analysis", "Target Function Hotspots", "main", "SYSCALL_ENTRY"):
        if required not in text:
            print(f"[FAIL] single-binary analysis self-test omitted {required}", file=sys.stderr)
            return 1
    print("[PASS] single RISC-V binary trace analysis self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze an RV-MalTrace JSONL trace against one specified RISC-V ELF.")
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--elf", type=Path, help="The single RISC-V ELF to use for static code attribution.")
    parser.add_argument("--sample-id", help="Analysis sample id. Defaults to ELF stem.")
    parser.add_argument("--load-base", help="Runtime load base for PIE/ET_DYN traces, for example 0x555555554000.")
    parser.add_argument("--runtime-process-map", type=Path, help="Optional runtime process map for stronger process ownership.")
    parser.add_argument("--addr2line", help="addr2line-compatible executable for source-line enrichment.")
    parser.add_argument("--out-dir", type=Path, help="Write code map, annotated trace, and summary artifacts.")
    parser.add_argument("--format", choices=("console", "json", "markdown"), default="console")
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--width", type=int, default=80)
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.trace is None or args.elf is None:
        parser.error("--trace and --elf are required unless --self-test is used")
    try:
        load_base = parse_address(args.load_base) if args.load_base else None
        annotated, summary, outputs = analyze(
            trace=args.trace,
            elf=args.elf,
            sample_id=args.sample_id or args.elf.stem,
            load_base=load_base,
            runtime_process_map=args.runtime_process_map,
            addr2line=args.addr2line,
            out_dir=args.out_dir,
        )
        if args.format == "json":
            print(json.dumps(summary, indent=2, sort_keys=True))
        elif args.format == "markdown":
            print(render_markdown(summary, annotated), end="")
        else:
            print(
                render_console(
                    args.trace,
                    annotated,
                    summary,
                    limit=args.limit,
                    width=args.width,
                    color=use_color(args.color),
                ),
                end="",
            )
        if outputs:
            print("[PASS] wrote single-binary analysis artifacts:")
            for name, path in outputs.items():
                print(f"  {name}: {path}")
    except Exception as exc:
        print(f"analyze_single_riscv_binary_trace: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
