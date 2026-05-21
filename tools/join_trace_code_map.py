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


def marker_kind(event: dict[str, Any]) -> str:
    value = parse_int(event.get("value"))
    if value is None:
        return "unknown"
    tag = value & 0xF0000000
    if tag == 0xB0000000:
        return "begin"
    if tag == 0xE0000000:
        return "end"
    return "unknown"


def marker_scope(events: list[dict[str, Any]]) -> dict[str, Any]:
    markers = [
        {"event_index": index, "kind": marker_kind(event), "value": event.get("value")}
        for index, event in enumerate(events)
        if event.get("evt") == "MARKER"
    ]
    begin = [row for row in markers if row["kind"] == "begin"]
    end = [row for row in markers if row["kind"] == "end"]
    begin_value = parse_int(begin[0]["value"]) if len(begin) == 1 else None
    end_value = parse_int(end[0]["value"]) if len(end) == 1 else None
    ordered = bool(begin and end and int(begin[0]["event_index"]) < int(end[0]["event_index"]))
    payload_match = begin_value is not None and end_value is not None and (begin_value & 0x0FFFFFFF) == (end_value & 0x0FFFFFFF)
    status = "PASS" if len(markers) == 2 and len(begin) == 1 and len(end) == 1 and ordered and payload_match else "FAIL"
    if not markers:
        status = "MISSING"
    return {
        "status": status,
        "begin_index": begin[0]["event_index"] if len(begin) == 1 else None,
        "end_index": end[0]["event_index"] if len(end) == 1 else None,
        "markers": markers,
    }


def runtime_map_rows(process: dict[str, Any]) -> list[dict[str, Any]]:
    rows = process.get("maps", [])
    result: list[dict[str, Any]] = []
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


def runtime_process_index(process_map: dict[str, Any] | None) -> dict[str, Any] | None:
    if process_map is None:
        return None
    owners = process_map.get("owners")
    if not isinstance(owners, dict):
        owners = {str(row.get("role")): row for row in process_map.get("processes", []) if isinstance(row, dict)}
    indexed: dict[str, Any] = {}
    for role, process in owners.items():
        if isinstance(process, dict):
            indexed[str(role)] = {**process, "maps": runtime_map_rows(process)}
    return {
        "schema": process_map.get("schema"),
        "status": process_map.get("status"),
        "sample_id": process_map.get("sample_id"),
        "rep": process_map.get("rep"),
        "owners": indexed,
        "provenance": process_map.get("provenance", {}),
    }


def marker_scoped_event(scope: dict[str, Any] | None, event_index: int | None) -> bool:
    if scope is None or scope.get("status") != "PASS" or event_index is None:
        return False
    begin = scope.get("begin_index")
    end = scope.get("end_index")
    return isinstance(begin, int) and isinstance(end, int) and begin < event_index < end


def runtime_owner(pc: int, runtime_index: dict[str, Any] | None, scope: dict[str, Any] | None, event_index: int | None) -> dict[str, Any]:
    if runtime_index is None:
        return {
            "process_owner": "unknown",
            "process_confidence": "runtime_process_map_missing",
            "runtime_map_match": None,
        }
    if runtime_index.get("status") != "PASS":
        return {
            "process_owner": "unknown",
            "process_confidence": "runtime_process_map_blocked",
            "runtime_map_match": None,
        }
    if not marker_scoped_event(scope, event_index):
        return {
            "process_owner": "unknown",
            "process_confidence": "not_marker_scoped",
            "runtime_map_match": None,
        }
    owners = runtime_index.get("owners", {}) if isinstance(runtime_index.get("owners"), dict) else {}
    matches: list[tuple[str, dict[str, Any]]] = []
    for role in ("target_child", "runner_parent", "kernel"):
        process = owners.get(role)
        if not isinstance(process, dict):
            continue
        match = find_range(process.get("maps", []), pc)
        if match is not None:
            matches.append((role, match))
    if len(matches) == 1:
        role, match = matches[0]
        return {
            "process_owner": role,
            "process_confidence": "marker_scoped_runtime_map",
            "runtime_map_match": {
                "role": role,
                "start": match.get("start"),
                "end": match.get("end"),
                "perms": match.get("perms"),
                "path": match.get("path"),
            },
        }
    if len(matches) > 1:
        return {
            "process_owner": "unknown",
            "process_confidence": "ambiguous_runtime_map_overlap",
            "runtime_map_match": [
                {
                    "role": role,
                    "start": match.get("start"),
                    "end": match.get("end"),
                    "perms": match.get("perms"),
                    "path": match.get("path"),
                }
                for role, match in matches
            ],
        }
    if (pc & 0xFFFFFFFF) >= 0xC0000000:
        return {
            "process_owner": "kernel",
            "process_confidence": "marker_scoped_kernel_range",
            "runtime_map_match": None,
        }
    return {
        "process_owner": "unknown",
        "process_confidence": "marker_scoped_no_runtime_map_match",
        "runtime_map_match": None,
    }


def static_pc_annotation(pc_value: Any, code_map: dict[str, Any], index: dict[str, Any]) -> dict[str, Any]:
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
            "code_attribution_basis": "static_elf_vaddr_range",
            "process_attribution": "not_proven",
            "load_base_assumption": code_map.get("load_base_assumption"),
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


def pc_annotation(
    pc_value: Any,
    code_map: dict[str, Any],
    index: dict[str, Any],
    runtime_index: dict[str, Any] | None = None,
    scope: dict[str, Any] | None = None,
    event_index: int | None = None,
) -> dict[str, Any]:
    static = static_pc_annotation(pc_value, code_map, index)
    result = dict(static)
    result["pc_owner_static"] = static.get("pc_owner", "unknown")
    pc = parse_int(pc_value)
    if pc is None:
        result.update(
            {
                "process_owner": "unknown",
                "process_confidence": "missing_pc",
                "attribution_confidence": "missing_pc",
            }
        )
        return result
    owner = runtime_owner(pc, runtime_index, scope, event_index)
    result.update(owner)
    callsite = str(static.get("callsite_kind", "unknown"))
    if owner.get("process_owner") == "target_child" and static.get("pc_owner") == "target_sample":
        if callsite not in {"normal_code", "unknown"}:
            result["attribution_confidence"] = "marker_scoped_runtime_map_code_site"
            result["process_attribution"] = "proven"
        else:
            result["attribution_confidence"] = "marker_scoped_runtime_map_static_range"
            result["process_attribution"] = "runtime_map_static_range"
    elif owner.get("process_owner") == "runner_parent":
        result["attribution_confidence"] = "runner_parent_runtime_map"
        result["process_attribution"] = "runner_parent"
    elif owner.get("process_owner") == "kernel":
        result["attribution_confidence"] = "kernel_or_supervisor_context"
        result["process_attribution"] = "kernel"
    else:
        result["attribution_confidence"] = owner.get("process_confidence", "not_proven")
        result["process_attribution"] = "not_proven"
    return {key: value for key, value in result.items() if value is not None}


def annotate_event(
    event: dict[str, Any],
    code_map: dict[str, Any],
    index: dict[str, Any],
    runtime_index: dict[str, Any] | None,
    scope: dict[str, Any],
    event_index: int,
) -> dict[str, Any]:
    annotated = dict(event)
    annotated.update(pc_annotation(event.get("pc"), code_map, index, runtime_index, scope, event_index))
    if "target" in event:
        target = pc_annotation(event.get("target"), code_map, index, runtime_index, scope, event_index)
        annotated["target_pc_owner"] = target.get("pc_owner")
        annotated["target_pc_owner_static"] = target.get("pc_owner_static")
        annotated["target_code_confidence"] = target.get("code_confidence")
        annotated["target_process_owner"] = target.get("process_owner")
        annotated["target_process_confidence"] = target.get("process_confidence")
        annotated["target_attribution_confidence"] = target.get("attribution_confidence")
        if target.get("symbol"):
            annotated["target_symbol"] = target.get("symbol")
    return annotated


def annotate_events(
    events: list[dict[str, Any]],
    code_map: dict[str, Any],
    runtime_process_map: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    index = code_map_index(code_map)
    runtime_index = runtime_process_index(runtime_process_map)
    scope = marker_scope(events)
    annotated = [annotate_event(event, code_map, index, runtime_index, scope, event_index) for event_index, event in enumerate(events)]
    owner_counts: dict[str, int] = {}
    process_owner_counts: dict[str, int] = {}
    callsite_counts: dict[str, int] = {}
    attribution_counts: dict[str, int] = {}
    for event in annotated:
        owner = str(event.get("pc_owner", "unknown"))
        process_owner = str(event.get("process_owner", "unknown"))
        callsite = str(event.get("callsite_kind", "unknown"))
        attribution = str(event.get("attribution_confidence", "unknown"))
        owner_counts[owner] = owner_counts.get(owner, 0) + 1
        process_owner_counts[process_owner] = process_owner_counts.get(process_owner, 0) + 1
        callsite_counts[callsite] = callsite_counts.get(callsite, 0) + 1
        attribution_counts[attribution] = attribution_counts.get(attribution, 0) + 1
    process_attributed_code_sites = sum(
        1 for event in annotated if event.get("attribution_confidence") == "marker_scoped_runtime_map_code_site"
    )
    return annotated, {
        "schema": "rvmt.trace_code_join.summary.v1",
        "sample_id": code_map.get("sample_id"),
        "binary_role": code_map.get("binary_role"),
        "runtime_path": code_map.get("runtime_path"),
        "elf": code_map.get("elf"),
        "elf_type": code_map.get("elf_type"),
        "load_base_assumption": code_map.get("load_base_assumption"),
        "process_attribution": "proven" if process_attributed_code_sites else "not_proven",
        "attribution_model": "marker_scope_static_code_map_runtime_process_map",
        "runtime_process_map_schema": runtime_process_map.get("schema") if isinstance(runtime_process_map, dict) else None,
        "runtime_process_map_status": runtime_process_map.get("status") if isinstance(runtime_process_map, dict) else "MISSING",
        "marker_scope": scope,
        "events": len(annotated),
        "pc_owner_counts": dict(sorted(owner_counts.items())),
        "process_owner_counts": dict(sorted(process_owner_counts.items())),
        "callsite_kind_counts": dict(sorted(callsite_counts.items())),
        "attribution_confidence_counts": dict(sorted(attribution_counts.items())),
        "target_attributed_events": owner_counts.get("target_sample", 0),
        "process_attributed_code_site_events": process_attributed_code_sites,
        "runtime_process_attribution_proven": bool(process_attributed_code_sites and scope.get("status") == "PASS"),
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
    if annotated[0].get("process_attribution") != "not_proven":
        print("[FAIL] join_trace_code_map missed static attribution limitation", file=sys.stderr)
        return 1
    if summary["target_attributed_events"] != 2:
        print("[FAIL] join_trace_code_map summary mismatch", file=sys.stderr)
        return 1
    runtime_map = {
        "schema": "rvmt.runtime_process_map.v1",
        "status": "PASS",
        "sample_id": "self",
        "rep": 0,
        "owners": {
            "target_child": {
                "role": "target_child",
                "pid": 101,
                "tgid": 101,
                "comm": "self",
                "exe": "/usr/bin/self",
                "maps": [{"start": "0x0000000000010000", "end": "0x0000000000011000", "perms": "r-xp", "path": "/usr/bin/self"}],
            },
            "runner_parent": {
                "role": "runner_parent",
                "pid": 100,
                "tgid": 100,
                "comm": "runner",
                "exe": "/usr/bin/rvmt_exp_runner",
                "maps": [{"start": "0x0000000000020000", "end": "0x0000000000021000", "perms": "r-xp", "path": "/usr/bin/rvmt_exp_runner"}],
            },
            "kernel": {
                "role": "kernel",
                "pid": 0,
                "tgid": 0,
                "comm": "kernel",
                "exe": "",
                "maps": [{"start": "0xc0000000", "end": "0xffffffff", "perms": "r-xp", "path": "linux_kernel"}],
            },
            "unknown": {"role": "unknown", "pid": -1, "tgid": -1, "comm": "unknown", "exe": "", "maps": []},
        },
    }
    scoped_events = [
        {"evt": "MARKER", "value": "0xb0000001"},
        {"evt": "SYSCALL_ENTRY", "pc": "0x0000000000010004"},
        {"evt": "TRAP", "pc": "0x0000000000010008"},
        {"evt": "MARKER", "value": "0xe0000001"},
    ]
    scoped, scoped_summary = annotate_events(scoped_events, code_map, runtime_map)
    if scoped[1].get("process_owner") != "target_child":
        print("[FAIL] join_trace_code_map missed target runtime process owner", file=sys.stderr)
        return 1
    if scoped[1].get("attribution_confidence") != "marker_scoped_runtime_map_code_site":
        print("[FAIL] join_trace_code_map missed process-attributed code-site confidence", file=sys.stderr)
        return 1
    if not scoped_summary.get("runtime_process_attribution_proven"):
        print("[FAIL] join_trace_code_map missed runtime process attribution summary", file=sys.stderr)
        return 1
    print("[PASS] join_trace_code_map self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Join RV-MalTrace JSONL events with a target ELF code map.")
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--code-map", type=Path)
    parser.add_argument("--runtime-process-map", type=Path)
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
        runtime_process_map = load_json(args.runtime_process_map) if args.runtime_process_map is not None else None
        annotated, summary = annotate_events(events, code_map, runtime_process_map)
        summary["trace"] = repo_rel(args.trace)
        summary["code_map"] = repo_rel(args.code_map)
        if args.runtime_process_map is not None:
            summary["runtime_process_map"] = repo_rel(args.runtime_process_map)
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
