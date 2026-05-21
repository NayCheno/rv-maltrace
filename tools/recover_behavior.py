from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from join_trace_code_map import code_map_index, pc_annotation


SYSCALL_NAMES = {
    35: "unlinkat",
    48: "faccessat",
    53: "fchmodat",
    56: "openat",
    57: "close",
    61: "getdents64",
    63: "read",
    64: "write",
    66: "writev",
    79: "newfstatat",
    80: "fstat",
    93: "exit",
    94: "exit_group",
    95: "waitid",
    113: "clock_gettime",
    117: "ptrace",
    198: "socket",
    203: "connect",
    172: "getpid",
    215: "munmap",
    214: "brk",
    220: "clone",
    221: "execve",
    222: "mmap",
    226: "mprotect",
    260: "wait4",
}


def load_trace(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"{path}:{line_no}: event must be a JSON object")
            events.append(event)
    return events


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def parse_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith("0x") else int(value, 10)
        except ValueError:
            return None
    return None


def hex_or_none(value: Any) -> str | None:
    number = parse_int(value)
    if number is None:
        return None
    return f"0x{number:016x}"


def event_base(event: dict[str, Any], index: int, code_map: dict[str, Any] | None = None, code_index: dict[str, Any] | None = None) -> dict[str, Any]:
    base = {
        "index": index,
        "cycle": event.get("cycle"),
        "pc": event.get("pc"),
        "evt": event.get("evt"),
    }
    if code_map is not None and code_index is not None:
        base.update(pc_annotation(event.get("pc"), code_map, code_index))
    return base


def drop_value(event: dict[str, Any]) -> int:
    if event.get("evt") != "DROP":
        return 0
    value = parse_int(event.get("value"))
    return value if value is not None else 0


def is_target_syscall_trap(event: dict[str, Any], code_map: dict[str, Any] | None, code_index: dict[str, Any] | None) -> bool:
    if event.get("evt") != "TRAP":
        return False
    if parse_int(event.get("instr")) != 0x00000073:
        return False
    if parse_int(event.get("a7")) is None:
        return False
    if code_map is None or code_index is None:
        return False
    annotation = pc_annotation(event.get("pc"), code_map, code_index)
    return annotation.get("pc_owner") == "target_sample" and annotation.get("callsite_kind") == "syscall_site"


def is_target_ecall_boundary(event: dict[str, Any], code_map: dict[str, Any] | None, code_index: dict[str, Any] | None) -> bool:
    if event.get("evt") not in {"TRAP", "ECALL", "SYSCALL_ENTRY"}:
        return False
    if event.get("evt") == "TRAP" and parse_int(event.get("instr")) != 0x00000073:
        return False
    if parse_int(event.get("a7")) is None:
        return False
    if code_map is None or code_index is None:
        return False
    annotation = pc_annotation(event.get("pc"), code_map, code_index)
    return annotation.get("pc_owner") == "target_sample"


def plausible_syscall_number(value: Any) -> bool:
    number = parse_int(value)
    return number is not None and 0 <= number <= 1024


def looks_like_openat_args(event: dict[str, Any]) -> bool:
    a0 = parse_int(event.get("a0"))
    a2 = parse_int(event.get("a2"))
    if a0 not in {0xFFFFFF9C, 0xFFFFFFFFFFFFFF9C}:
        return False
    if a2 is None:
        return False
    # O_CLOEXEC is stable in the synthetic samples and keeps this from
    # reclassifying AT_FDCWD syscalls whose third argument is a pointer.
    return 0 < a2 <= 0x00100000 and bool(a2 & 0x00080000)


def syscall_id_int(event: dict[str, Any]) -> int | None:
    return parse_int(event.get("syscall_id"))


def nearby_kernel_entry(events: list[dict[str, Any]], start: int) -> tuple[int, dict[str, Any]] | None:
    base_id = syscall_id_int(events[start])
    for index in range(start + 1, min(len(events), start + 5)):
        event = events[index]
        if event.get("evt") != "SYSCALL_ENTRY":
            continue
        if base_id is not None and syscall_id_int(event) != base_id:
            continue
        if plausible_syscall_number(event.get("a7")):
            return index, event
    return None


def empty_args() -> dict[str, None]:
    return {f"a{arg}": None for arg in range(8)}


def event_args(event: dict[str, Any]) -> dict[str, str | None]:
    return {f"a{arg}": hex_or_none(event.get(f"a{arg}")) for arg in range(8)}


def make_entry_observation(
    event: dict[str, Any],
    index: int,
    evt: str,
    source_evt: str,
    code_map: dict[str, Any] | None,
    code_index: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        **event_base(event, index, code_map, code_index),
        "evt": evt,
        "source_evt": source_evt,
        "a7": hex_or_none(event.get("a7")),
        "args": event_args(event),
    }


def select_entry_number(
    target_event: dict[str, Any],
    kernel_event: dict[str, Any] | None,
    *,
    target_syscall_site: bool,
    previous_number: int | None,
) -> tuple[int | None, str]:
    target_number = parse_int(target_event.get("a7"))
    kernel_number = parse_int(kernel_event.get("a7")) if kernel_event is not None else None
    if target_syscall_site and target_number != 56 and looks_like_openat_args(target_event):
        return 56, "target_arg_shape_openat"
    if kernel_number is not None and plausible_syscall_number(kernel_number):
        if kernel_number == 0 and target_number is not None and plausible_syscall_number(target_number):
            return target_number, "target_boundary_nr"
        if target_number is None or not plausible_syscall_number(target_number):
            return kernel_number, "kernel_entry_nr_target_args"
        if target_syscall_site and previous_number == target_number and kernel_number != target_number:
            return kernel_number, "kernel_entry_nr_target_args"
    return target_number, "target_boundary_nr"


def add_pending(
    pending_by_id: dict[int, dict[str, Any]],
    pending_without_id: list[dict[str, Any]],
    syscall: dict[str, Any],
    event: dict[str, Any],
) -> None:
    syscall_id = syscall_id_int(event)
    if syscall_id is None:
        pending_without_id.append(syscall)
    else:
        pending_by_id[syscall_id] = syscall


def find_pending_for_return(
    pending_by_id: dict[int, dict[str, Any]],
    syscall_id: int | None,
    return_number: int | None,
) -> tuple[int | None, dict[str, Any] | None]:
    if syscall_id is None:
        return None, None
    candidates = []
    previous_id = syscall_id - 1
    if previous_id in pending_by_id:
        candidates.append(previous_id)
    if syscall_id in pending_by_id:
        candidates.append(syscall_id)
    for candidate_id in candidates:
        candidate = pending_by_id[candidate_id]
        if return_number is None or candidate.get("nr") in {return_number, None}:
            return candidate_id, candidate
    return None, None


def recover_syscalls(events: list[dict[str, Any]], code_map: dict[str, Any] | None = None, code_index: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    syscalls: list[dict[str, Any]] = []
    pending_by_id: dict[int, dict[str, Any]] = {}
    pending_without_id: list[dict[str, Any]] = []
    skip_entry_indexes: set[int] = set()
    drop_total = 0
    seq = 0
    last_number: int | None = None
    for index, event in enumerate(events):
        evt = event.get("evt")
        drop_total += drop_value(event)
        trap_syscall = is_target_syscall_trap(event, code_map, code_index)
        target_boundary = is_target_ecall_boundary(event, code_map, code_index)
        if evt not in {"ECALL", "SYSCALL_ENTRY", "SYSCALL_RET"} and not trap_syscall and not target_boundary:
            continue
        if index in skip_entry_indexes:
            continue
        if evt in {"ECALL", "SYSCALL_ENTRY"} or trap_syscall or target_boundary:
            fused_entry = nearby_kernel_entry(events, index) if target_boundary else None
            fused_entry_index = fused_entry[0] if fused_entry is not None else None
            kernel_entry = fused_entry[1] if fused_entry is not None else None
            number, number_source = (
                select_entry_number(event, kernel_entry, target_syscall_site=trap_syscall, previous_number=last_number)
                if target_boundary
                else (parse_int(event.get("a7")), "entry_nr")
            )
            args = event_args(event)
            syscall_id = parse_int(event.get("syscall_id"))
            if syscall_id is not None and syscall_id in pending_by_id:
                pending_by_id[syscall_id].setdefault("entry_observations", []).append(
                    make_entry_observation(event, index, "SYSCALL_ENTRY", str(evt), code_map, code_index)
                )
                if fused_entry_index is not None and kernel_entry is not None:
                    pending_by_id[syscall_id].setdefault("entry_observations", []).append(
                        make_entry_observation(
                            kernel_entry,
                            fused_entry_index,
                            "SYSCALL_ENTRY",
                            str(kernel_entry.get("evt")),
                            code_map,
                            code_index,
                        )
                    )
                    skip_entry_indexes.add(fused_entry_index)
                continue
            confidence = "trap_ecall_syscall_site" if trap_syscall else "entry_only"
            if target_boundary:
                confidence = "fused_target_ecall_kernel_entry" if kernel_entry is not None else "target_ecall_boundary"
            syscall = {
                **event_base(event, index, code_map, code_index),
                "evt": "SYSCALL_ENTRY",
                "source_evt": evt,
                "seq": seq,
                "syscall_id": hex_or_none(event.get("syscall_id")),
                "nr": number,
                "number": number,
                "name": SYSCALL_NAMES.get(number, f"sys_{number}" if number is not None else "unknown"),
                "entry_pc": hex_or_none(event.get("pc")),
                "return_pc": None,
                "priv": event.get("priv"),
                "a7": hex_or_none(event.get("a7")),
                "args": args,
                "return_value": None,
                "duration": None,
                "drop_before": drop_total,
                "drop_after": None,
                "confidence": confidence,
                "number_source": number_source,
            }
            if kernel_entry is not None:
                syscall["kernel_entry_nr"] = hex_or_none(kernel_entry.get("a7"))
                syscall["kernel_entry_index"] = fused_entry_index
                syscall.setdefault("entry_observations", []).append(
                    make_entry_observation(event, index, "SYSCALL_ENTRY", str(evt), code_map, code_index)
                )
                syscall.setdefault("entry_observations", []).append(
                    make_entry_observation(
                        kernel_entry,
                        int(fused_entry_index),
                        "SYSCALL_ENTRY",
                        str(kernel_entry.get("evt")),
                        code_map,
                        code_index,
                    )
                )
                skip_entry_indexes.add(int(fused_entry_index))
            seq += 1
            syscalls.append(syscall)
            last_number = number
            add_pending(pending_by_id, pending_without_id, syscall, event)
            continue

        syscall_id = parse_int(event.get("syscall_id"))
        matched_id, match = find_pending_for_return(pending_by_id, syscall_id, parse_int(event.get("a7")))
        if matched_id is not None:
            pending_by_id.pop(matched_id, None)
        if match is None and pending_without_id:
            match = pending_without_id.pop(0)
        return_number = parse_int(event.get("a7"))
        return_args = event_args(event)
        ret = {
            **event_base(event, index, code_map, code_index),
            "return_value": hex_or_none(event.get("a0")),
            "return_pc": hex_or_none(event.get("target")),
            "duration": parse_int(event.get("duration")),
            "a7": hex_or_none(event.get("a7")),
            "args": return_args,
        }
        if code_map is not None and code_index is not None:
            target_ann = pc_annotation(event.get("target"), code_map, code_index)
            ret["return_pc_owner"] = target_ann.get("pc_owner")
            ret["return_code_confidence"] = target_ann.get("code_confidence")
        if match is None:
            syscalls.append(
                {
                    **event_base(event, index, code_map, code_index),
                    "evt": "SYSCALL_RET",
                    "seq": seq,
                    "syscall_id": hex_or_none(event.get("syscall_id")),
                    "nr": return_number,
                    "number": return_number,
                    "name": SYSCALL_NAMES.get(return_number, f"sys_{return_number}" if return_number is not None else "unmatched_return"),
                    "entry_pc": None,
                    "return_pc": ret["return_pc"],
                    "a7": hex_or_none(event.get("a7")),
                    "args": return_args if return_number is not None else empty_args(),
                    "return_value": ret["return_value"],
                    "duration": ret["duration"],
                    "drop_before": drop_total,
                    "drop_after": drop_total,
                    "confidence": "return_only_register_snapshot" if return_number is not None else "return_only",
                    "return": ret,
                }
            )
            last_number = return_number
            seq += 1
        else:
            match["return"] = ret
            match["return_value"] = ret["return_value"]
            match["return_pc"] = ret["return_pc"]
            match["duration"] = ret["duration"]
            match["drop_after"] = drop_total
            prior_confidence = str(match.get("confidence"))
            if prior_confidence == "trap_ecall_syscall_site":
                match["confidence"] = "paired_trap_ecall_return"
            elif prior_confidence == "target_ecall_boundary":
                match["confidence"] = "paired_target_ecall_return"
            elif prior_confidence == "fused_target_ecall_kernel_entry":
                match["confidence"] = "paired_fused_target_ecall_return"
            else:
                match["confidence"] = "paired_entry_return"
    for syscall in pending_by_id.values():
        syscall["drop_after"] = drop_total
    for syscall in pending_without_id:
        syscall["drop_after"] = drop_total
    return syscalls


def recover_control_flow(events: list[dict[str, Any]], code_map: dict[str, Any] | None = None, code_index: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        if event.get("evt") not in {"BRANCH", "JUMP"}:
            continue
        segments.append(
            {
                **event_base(event, index, code_map, code_index),
                "kind": str(event.get("evt", "")).lower(),
                "instr": event.get("instr"),
                "target": event.get("target"),
                "taken": event.get("taken") if event.get("evt") == "BRANCH" else None,
                "priv": event.get("priv"),
            }
        )
    return segments


def recover_trap_context(events: list[dict[str, Any]], code_map: dict[str, Any] | None = None, code_index: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    transitions: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        evt = event.get("evt")
        if evt not in {"TRAP", "CSR", "SATP", "PRIV"}:
            continue
        item = {
            **event_base(event, index, code_map, code_index),
            "priv": event.get("priv"),
            "old_priv": event.get("old_priv"),
            "new_priv": event.get("new_priv"),
            "cause": event.get("cause"),
            "tval": event.get("tval"),
            "csr": event.get("csr"),
            "value": event.get("value"),
            "satp": event.get("satp"),
        }
        transitions.append({key: value for key, value in item.items() if value is not None})
    return transitions


def recover_privilege_boundaries(events: list[dict[str, Any]], code_map: dict[str, Any] | None = None, code_index: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    boundaries: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        evt = event.get("evt")
        if evt in {"ECALL", "SYSCALL_ENTRY"}:
            boundaries.append({**event_base(event, index, code_map, code_index), "kind": "syscall_entry", "priv": event.get("priv")})
        elif evt == "SYSCALL_RET":
            boundaries.append({**event_base(event, index, code_map, code_index), "kind": "syscall_return", "priv": event.get("priv")})
        elif evt == "TRAP":
            boundaries.append({**event_base(event, index, code_map, code_index), "kind": "trap_entry", "priv": event.get("priv"), "cause": event.get("cause")})
        elif evt == "PRIV":
            boundaries.append(
                {
                    **event_base(event, index, code_map, code_index),
                    "kind": "privilege_change",
                    "old_priv": event.get("old_priv"),
                    "new_priv": event.get("new_priv"),
                }
            )
    return boundaries


def build_graph(semantic: dict[str, Any]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = [{"id": "trace", "kind": "trace", "label": "trace"}]
    edges: list[dict[str, Any]] = []

    def append_node(kind: str, label: str, payload: dict[str, Any]) -> str:
        node_id = f"{kind}:{len(nodes)}"
        nodes.append({"id": node_id, "kind": kind, "label": label, "payload": payload})
        edges.append({"source": "trace", "target": node_id, "kind": "contains"})
        return node_id

    previous_syscall: str | None = None
    for syscall in semantic["syscall_sequence"]:
        node_id = append_node("syscall", syscall["name"], syscall)
        if previous_syscall is not None:
            edges.append({"source": previous_syscall, "target": node_id, "kind": "next_syscall"})
        previous_syscall = node_id

    for segment in semantic["control_flow_segments"]:
        append_node("control_flow", segment["kind"], segment)

    for transition in semantic["trap_context_transitions"]:
        append_node("context", str(transition.get("evt", "context")).lower(), transition)

    for boundary in semantic["privilege_boundaries"]:
        append_node("privilege_boundary", boundary["kind"], boundary)

    return {
        "schema": "rvmt.behavior.graph.v1",
        "nodes": nodes,
        "edges": edges,
    }


def parser_warning_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    unknown = 0
    corrupt = 0
    for event in events:
        if event.get("evt") == "UNKNOWN":
            unknown += 1
        warnings = event.get("parser_warnings", [])
        if not isinstance(warnings, list):
            continue
        for warning in warnings:
            key = str(warning)
            counts[key] = counts.get(key, 0) + 1
            if key.startswith("corrupt_"):
                corrupt += 1
    return {
        "warning_counts": dict(sorted(counts.items())),
        "unknown_event_count": unknown,
        "corrupt_record_count": corrupt,
    }


def recover(
    events: list[dict[str, Any]],
    source: str,
    code_map: dict[str, Any] | None = None,
    code_map_source: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    code_index = code_map_index(code_map) if code_map is not None else None
    code_map_summary = None
    if code_map is not None:
        code_map_summary = {
            "sample_id": code_map.get("sample_id"),
            "source": code_map_source,
            "elf": code_map.get("elf"),
            "binary_role": code_map.get("binary_role"),
            "runtime_path": code_map.get("runtime_path"),
            "sha256": code_map.get("sha256"),
            "elf_header": code_map.get("elf_header"),
            "load_ranges": len(code_map.get("load_ranges", [])) if isinstance(code_map.get("load_ranges"), list) else 0,
            "syscall_sites": len(code_map.get("syscall_sites", [])) if isinstance(code_map.get("syscall_sites"), list) else 0,
            "trap_sites": len(code_map.get("trap_sites", [])) if isinstance(code_map.get("trap_sites"), list) else 0,
        }
    semantic = {
        "schema": "rvmt.behavior.semantic.v1",
        "source": source,
        "status": "DERIVED",
        "code_map": code_map_summary,
        "parser_warnings": parser_warning_summary(events),
        "syscall_sequence": recover_syscalls(events, code_map, code_index),
        "control_flow_segments": recover_control_flow(events, code_map, code_index),
        "trap_context_transitions": recover_trap_context(events, code_map, code_index),
        "privilege_boundaries": recover_privilege_boundaries(events, code_map, code_index),
    }
    graph = build_graph(semantic)
    report = "\n".join(
        [
            "# Behavior Recovery Report",
            "",
            f"- Source trace: `{source}`",
            f"- Input events: {len(events)}",
            f"- syscall_sequence: {len(semantic['syscall_sequence'])}",
            f"- control_flow_segment: {len(semantic['control_flow_segments'])}",
            f"- trap_context_transition: {len(semantic['trap_context_transitions'])}",
            f"- privilege_boundary: {len(semantic['privilege_boundaries'])}",
            f"- code_map: {code_map_source or 'none'}",
            f"- UNKNOWN events: {semantic['parser_warnings']['unknown_event_count']}",
            f"- corrupt records: {semantic['parser_warnings']['corrupt_record_count']}",
            f"- basic_behavior_graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges",
            "",
            "This report is derived trace semantics, not malware detection evidence.",
            "",
        ]
    )
    return semantic, graph, report


def write_outputs(trace_path: Path, out_dir: Path, code_map_path: Path | None = None) -> None:
    events = load_trace(trace_path)
    code_map = load_json(code_map_path) if code_map_path is not None else None
    semantic, graph, report = recover(events, trace_path.as_posix(), code_map, code_map_path.as_posix() if code_map_path is not None else None)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "semantic_events.json").write_text(json.dumps(semantic, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "behavior_graph.json").write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "recovery_report.md").write_text(report, encoding="utf-8", newline="\n")


def self_test() -> int:
    trace = "\n".join(
        [
            '{"cycle":1,"evt":"SYSCALL_ENTRY","pc":"0x1000","priv":"U","syscall_id":"0x0","a7":"0x40","a0":"0x1"}',
            '{"cycle":2,"evt":"SYSCALL_RET","pc":"0x1008","priv":"S","target":"0x1004","syscall_id":"0x0","duration":1,"a0":"0x5"}',
            '{"cycle":3,"evt":"SYSCALL_RET","pc":"0x100c","priv":"S","target":"0x1008","syscall_id":"0x1","duration":2,"a0":"0x5","a1":"0x2000","a2":"0x5","a7":"0x40"}',
            '{"cycle":4,"evt":"BRANCH","pc":"0x1004","taken":true,"target":"0x1010","priv":"U"}',
            '{"cycle":5,"evt":"TRAP","pc":"0x1010","priv":"U","cause":"0x2","tval":"0xffffffff"}',
            '{"cycle":6,"evt":"PRIV","pc":"0x1010","old_priv":"U","new_priv":"S"}',
        ]
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        trace_path = root / "trace.jsonl"
        out_dir = root / "out"
        trace_path.write_text(trace + "\n", encoding="utf-8")
        write_outputs(trace_path, out_dir)
        semantic = json.loads((out_dir / "semantic_events.json").read_text(encoding="utf-8"))
        graph = json.loads((out_dir / "behavior_graph.json").read_text(encoding="utf-8"))
        if semantic["syscall_sequence"][0]["name"] != "write":
            print("[FAIL] self-test missed write syscall recovery", file=sys.stderr)
            return 1
        syscall = semantic["syscall_sequence"][0]
        syscall_return = syscall.get("return", {})
        if syscall_return.get("return_value") != "0x0000000000000005":
            print("[FAIL] self-test missed syscall return recovery", file=sys.stderr)
            return 1
        if syscall_return.get("return_pc") != "0x0000000000001004":
            print("[FAIL] self-test missed syscall return PC recovery", file=sys.stderr)
            return 1
        if syscall_return.get("duration") != 1:
            print("[FAIL] self-test missed syscall duration recovery", file=sys.stderr)
            return 1
        if syscall.get("return_pc") != "0x0000000000001004" or syscall.get("duration") != 1:
            print("[FAIL] self-test missed flattened syscall return fields", file=sys.stderr)
            return 1
        if syscall.get("nr") != 64 or syscall.get("seq") != 0 or syscall.get("confidence") != "paired_entry_return":
            print("[FAIL] self-test missed stable syscall schema fields", file=sys.stderr)
            return 1
        return_only = semantic["syscall_sequence"][1]
        if return_only.get("name") != "write" or return_only.get("confidence") != "return_only_register_snapshot":
            print("[FAIL] self-test missed return-only syscall register snapshot recovery", file=sys.stderr)
            return 1
        if sorted(syscall.get("args", {})) != [f"a{arg}" for arg in range(8)]:
            print("[FAIL] self-test missed full argument field set", file=sys.stderr)
            return 1
        if not semantic["control_flow_segments"]:
            print("[FAIL] self-test missed control-flow recovery", file=sys.stderr)
            return 1
        if len(semantic["trap_context_transitions"]) < 2:
            print("[FAIL] self-test missed trap/context recovery", file=sys.stderr)
            return 1
        if len(semantic["privilege_boundaries"]) < 2:
            print("[FAIL] self-test missed privilege-boundary recovery", file=sys.stderr)
            return 1
        if not graph["nodes"] or not graph["edges"]:
            print("[FAIL] self-test missed behavior graph recovery", file=sys.stderr)
            return 1
        trap_trace = root / "trap_trace.jsonl"
        trap_out = root / "trap_out"
        code_map_path = root / "code_map.json"
        trap_trace.write_text(
            '{"cycle":1,"evt":"TRAP","pc":"0x2000","instr":"0x00000073","priv":"U","cause":"0x0","syscall_id":"0x2","a0":"0x1","a1":"0x3000","a2":"0x11","a7":"0x40"}\n'
            '{"cycle":2,"evt":"SYSCALL_RET","pc":"0x2000","priv":"S","target":"0x0","syscall_id":"0x2","duration":1,"a0":"0x11","a7":"0x40"}\n',
            encoding="utf-8",
        )
        code_map_path.write_text(
            json.dumps(
                {
                    "schema": "rvmt.code_map.v1",
                    "sample_id": "self",
                    "elf": "self.elf",
                    "load_ranges": [{"start": "0x0000000000002000", "end": "0x0000000000002100"}],
                    "sections": [{"name": ".text", "start": "0x0000000000002000", "end": "0x0000000000002100"}],
                    "symbols": [{"name": "handler", "start": "0x0000000000002000", "end": "0x0000000000002010"}],
                    "syscall_sites": [{"pc": "0x0000000000002000", "symbol": "handler"}],
                    "trap_sites": [],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        write_outputs(trap_trace, trap_out, code_map_path)
        trap_semantic = json.loads((trap_out / "semantic_events.json").read_text(encoding="utf-8"))
        if trap_semantic["syscall_sequence"][0]["name"] != "write":
            print("[FAIL] self-test missed target syscall-site trap recovery", file=sys.stderr)
            return 1
        if trap_semantic["syscall_sequence"][0]["confidence"] != "paired_target_ecall_return":
            print("[FAIL] self-test missed target syscall-site trap confidence", file=sys.stderr)
            return 1
        fused_trace = root / "fused_trace.jsonl"
        fused_out = root / "fused_out"
        fused_trace.write_text(
            '{"cycle":8,"evt":"TRAP","pc":"0x2000","instr":"0x00000073","priv":"U","cause":"0x0","syscall_id":"0x6","a0":"0x0","a1":"0x1000","a2":"0x3","a7":"0xde"}\n'
            '{"cycle":9,"evt":"SYSCALL_RET","pc":"0x2000","priv":"U","target":"0x0","syscall_id":"0x7","duration":1,"a0":"0x4000","a7":"0xde"}\n'
            '{"cycle":10,"evt":"TRAP","pc":"0x2000","instr":"0x00000073","priv":"U","cause":"0x0","syscall_id":"0x7","a0":"0x4000","a1":"0x1000","a2":"0x5","a7":"0xde"}\n'
            '{"cycle":11,"evt":"SYSCALL_ENTRY","pc":"0xc0001000","priv":"S","syscall_id":"0x7","a0":"0xc0010000","a1":"0x0","a2":"0x0","a7":"0xe2"}\n'
            '{"cycle":12,"evt":"SYSCALL_RET","pc":"0x2000","priv":"U","target":"0x0","syscall_id":"0x8","duration":1,"a0":"0x0","a7":"0xe2"}\n',
            encoding="utf-8",
        )
        write_outputs(fused_trace, fused_out, code_map_path)
        fused_semantic = json.loads((fused_out / "semantic_events.json").read_text(encoding="utf-8"))
        fused = fused_semantic["syscall_sequence"][1]
        if fused.get("name") != "mprotect" or fused.get("args", {}).get("a2") != "0x0000000000000005":
            print("[FAIL] self-test missed target-arg/kernel-number syscall fusion", file=sys.stderr)
            return 1
        if fused.get("return_value") != "0x0000000000000000" or fused.get("confidence") != "paired_fused_target_ecall_return":
            print("[FAIL] self-test missed p0c id+1 return pairing", file=sys.stderr)
            return 1
    print("[PASS] behavior recovery self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recover semantic behavior artifacts from rv-maltrace JSONL.")
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--code-map", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.trace is None or args.out_dir is None:
        parser.error("--trace and --out-dir are required unless --self-test is used")
    try:
        write_outputs(args.trace, args.out_dir, args.code_map)
    except Exception as exc:
        print(f"recover_behavior: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
