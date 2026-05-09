from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


SYSCALL_NAMES = {
    56: "openat",
    57: "close",
    63: "read",
    64: "write",
    66: "writev",
    93: "exit",
    94: "exit_group",
    172: "getpid",
    214: "brk",
    220: "clone",
    221: "execve",
    222: "mmap",
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


def event_base(event: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "index": index,
        "cycle": event.get("cycle"),
        "pc": event.get("pc"),
        "evt": event.get("evt"),
    }


def recover_syscalls(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    syscalls: list[dict[str, Any]] = []
    pending_by_id: dict[int, dict[str, Any]] = {}
    pending_without_id: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        evt = event.get("evt")
        if evt not in {"ECALL", "SYSCALL_ENTRY", "SYSCALL_RET"}:
            continue
        if evt in {"ECALL", "SYSCALL_ENTRY"}:
            number = parse_int(event.get("a7"))
            syscall = {
                **event_base(event, index),
                "evt": "SYSCALL_ENTRY",
                "syscall_id": hex_or_none(event.get("syscall_id")),
                "number": number,
                "name": SYSCALL_NAMES.get(number, f"sys_{number}" if number is not None else "unknown"),
                "priv": event.get("priv"),
                "a7": hex_or_none(event.get("a7")),
                "args": {f"a{arg}": hex_or_none(event.get(f"a{arg}")) for arg in range(6)},
            }
            syscalls.append(syscall)
            syscall_id = parse_int(event.get("syscall_id"))
            if syscall_id is None:
                pending_without_id.append(syscall)
            else:
                pending_by_id[syscall_id] = syscall
            continue

        syscall_id = parse_int(event.get("syscall_id"))
        match = pending_by_id.pop(syscall_id, None) if syscall_id is not None else None
        if match is None and pending_without_id:
            match = pending_without_id.pop()
        ret = {
            **event_base(event, index),
            "return_value": hex_or_none(event.get("a0")),
            "return_pc": hex_or_none(event.get("target")),
            "duration": parse_int(event.get("duration")),
        }
        if match is None:
            syscalls.append(
                {
                    **event_base(event, index),
                    "evt": "SYSCALL_RET",
                    "syscall_id": hex_or_none(event.get("syscall_id")),
                    "name": "unmatched_return",
                    "return": ret,
                }
            )
        else:
            match["return"] = ret
            match["return_value"] = ret["return_value"]
            match["return_pc"] = ret["return_pc"]
            match["duration"] = ret["duration"]
    return syscalls


def recover_control_flow(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        if event.get("evt") not in {"BRANCH", "JUMP"}:
            continue
        segments.append(
            {
                **event_base(event, index),
                "kind": str(event.get("evt", "")).lower(),
                "instr": event.get("instr"),
                "target": event.get("target"),
                "taken": event.get("taken") if event.get("evt") == "BRANCH" else None,
                "priv": event.get("priv"),
            }
        )
    return segments


def recover_trap_context(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    transitions: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        evt = event.get("evt")
        if evt not in {"TRAP", "CSR", "SATP", "PRIV"}:
            continue
        item = {
            **event_base(event, index),
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


def recover_privilege_boundaries(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    boundaries: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        evt = event.get("evt")
        if evt in {"ECALL", "SYSCALL_ENTRY"}:
            boundaries.append({**event_base(event, index), "kind": "syscall_entry", "priv": event.get("priv")})
        elif evt == "SYSCALL_RET":
            boundaries.append({**event_base(event, index), "kind": "syscall_return", "priv": event.get("priv")})
        elif evt == "TRAP":
            boundaries.append({**event_base(event, index), "kind": "trap_entry", "priv": event.get("priv"), "cause": event.get("cause")})
        elif evt == "PRIV":
            boundaries.append(
                {
                    **event_base(event, index),
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


def recover(events: list[dict[str, Any]], source: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    semantic = {
        "schema": "rvmt.behavior.semantic.v1",
        "source": source,
        "status": "DERIVED",
        "syscall_sequence": recover_syscalls(events),
        "control_flow_segments": recover_control_flow(events),
        "trap_context_transitions": recover_trap_context(events),
        "privilege_boundaries": recover_privilege_boundaries(events),
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
            f"- basic_behavior_graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges",
            "",
            "This report is derived trace semantics, not malware detection evidence.",
            "",
        ]
    )
    return semantic, graph, report


def write_outputs(trace_path: Path, out_dir: Path) -> None:
    events = load_trace(trace_path)
    semantic, graph, report = recover(events, trace_path.as_posix())
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "semantic_events.json").write_text(json.dumps(semantic, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "behavior_graph.json").write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "recovery_report.md").write_text(report, encoding="utf-8", newline="\n")


def self_test() -> int:
    trace = "\n".join(
        [
            '{"cycle":1,"evt":"SYSCALL_ENTRY","pc":"0x1000","priv":"U","syscall_id":"0x0","a7":"0x40","a0":"0x1"}',
            '{"cycle":2,"evt":"SYSCALL_RET","pc":"0x1008","priv":"S","target":"0x1004","syscall_id":"0x0","duration":1,"a0":"0x5"}',
            '{"cycle":3,"evt":"BRANCH","pc":"0x1004","taken":true,"target":"0x1010","priv":"U"}',
            '{"cycle":4,"evt":"TRAP","pc":"0x1010","priv":"U","cause":"0x2","tval":"0xffffffff"}',
            '{"cycle":5,"evt":"PRIV","pc":"0x1010","old_priv":"U","new_priv":"S"}',
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
    print("[PASS] behavior recovery self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recover semantic behavior artifacts from rv-maltrace JSONL.")
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.trace is None or args.out_dir is None:
        parser.error("--trace and --out-dir are required unless --self-test is used")
    try:
        write_outputs(args.trace, args.out_dir)
    except Exception as exc:
        print(f"recover_behavior: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
