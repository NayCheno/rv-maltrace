from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULT_ROOT = Path("results/experiments/35t")
SAMPLE_CLASS = "malware_like_synthetic"
SAMPLE_ID = "process_chain"
TRACE_ON = "trace-on"
PROCESS_NAMES = {"clone", "execve", "waitid", "wait4", "waitpid"}
PROCESS_SYSCALL_NRS = {95: "waitid", 220: "clone", 221: "execve", 260: "wait4"}


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def repo_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
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


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith("0x") else int(value, 10)
        except ValueError:
            return None
    return None


def sample_root(run_root: Path) -> Path:
    return run_root / "samples" / SAMPLE_CLASS / SAMPLE_ID


def event_counts(events: list[dict[str, Any]], status: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        evt = str(event.get("evt", "NONE"))
        counts[evt] = counts.get(evt, 0) + 1
    counts["DROP_STATUS"] = int(status.get("drop", 0) or 0)
    return dict(sorted(counts.items()))


def compact_event(event: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "index": index,
        "record_index": event.get("record_index"),
        "cycle": event.get("cycle"),
        "evt": event.get("evt"),
        "pc": event.get("pc"),
        "target": event.get("target"),
        "priv": event.get("priv"),
        "cause": event.get("cause"),
        "instr": event.get("instr"),
        "syscall_id": event.get("syscall_id"),
        "a0": event.get("a0"),
        "a1": event.get("a1"),
        "a2": event.get("a2"),
        "a3": event.get("a3"),
        "a4": event.get("a4"),
        "a5": event.get("a5"),
        "a6": event.get("a6"),
        "a7": event.get("a7"),
        "pc_owner": event.get("pc_owner"),
        "target_pc_owner": event.get("target_pc_owner"),
        "code_confidence": event.get("code_confidence"),
        "callsite_kind": event.get("callsite_kind"),
        "symbol": event.get("symbol"),
        "symbol_offset": event.get("symbol_offset"),
    }


def count_by(rows: list[dict[str, Any]], *keys: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        label = "|".join(str(row.get(key, "missing")) for key in keys)
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def trap_source(event: dict[str, Any]) -> str:
    owner = event.get("pc_owner")
    instr = parse_int(event.get("instr"))
    cause = parse_int(event.get("cause"))
    if owner == "target_sample" and instr == 0x73:
        return "target_ecall_boundary"
    if owner == "target_sample":
        return "target_non_ecall_trap"
    if owner == "kernel":
        return "kernel_or_loader_trap"
    if cause == 2:
        return "non_target_illegal_or_decode_trap"
    return "unknown_or_non_target_trap"


def trap_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    traps = [{**compact_event(event, index), "source": trap_source(event)} for index, event in enumerate(events) if event.get("evt") == "TRAP"]
    source_counts = count_by(traps, "source")
    return {
        "total": len(traps),
        "by_source": source_counts,
        "by_cause_priv_owner": count_by(traps, "cause", "priv", "pc_owner"),
        "top_symbols": dict(list(count_by(traps, "pc_owner", "symbol").items())[:12]),
        "events": traps,
        "dominant_source": next(iter(source_counts), "none"),
    }


def syscall_arg(row: dict[str, Any], arg: str) -> Any:
    args = row.get("args")
    if isinstance(args, dict) and arg in args:
        return args[arg]
    return row.get(arg)


def syscall_summary(row: dict[str, Any]) -> dict[str, Any]:
    args = row.get("args") if isinstance(row.get("args"), dict) else {}
    return {
        "seq": row.get("seq"),
        "name": row.get("name"),
        "nr": row.get("nr"),
        "a0": args.get("a0"),
        "a1": args.get("a1"),
        "a2": args.get("a2"),
        "a3": args.get("a3"),
        "a4": args.get("a4"),
        "a5": args.get("a5"),
        "a6": args.get("a6"),
        "a7": row.get("a7"),
        "return_value": row.get("return_value"),
        "confidence": row.get("confidence"),
        "number_source": row.get("number_source"),
        "code_map_owner": row.get("pc_owner"),
        "callsite_kind": row.get("callsite_kind"),
        "return_pc_owner": (row.get("return") or {}).get("return_pc_owner") if isinstance(row.get("return"), dict) else None,
    }


def process_syscalls(semantic: dict[str, Any]) -> list[dict[str, Any]]:
    rows = semantic.get("syscall_sequence", [])
    if not isinstance(rows, list):
        return []
    return [syscall_summary(row) for row in rows if isinstance(row, dict) and str(row.get("name")) in PROCESS_NAMES]


def process_boundary(syscalls: list[dict[str, Any]]) -> dict[str, Any]:
    clone_parent_return_candidates: list[int] = []
    wait_pid_args: list[int] = []
    for row in syscalls:
        if row.get("name") == "clone":
            value = parse_int(row.get("return_value"))
            if value is not None and value > 0 and value < (1 << 31):
                clone_parent_return_candidates.append(value)
        if row.get("name") == "waitid":
            value = parse_int(row.get("a1"))
            if value is not None:
                wait_pid_args.append(value)
        if row.get("name") in {"wait4", "waitpid"}:
            value = parse_int(row.get("a0"))
            if value is not None:
                wait_pid_args.append(value)
    overlap = sorted(set(clone_parent_return_candidates) & set(wait_pid_args))
    reason = "closed" if overlap else "no clone parent return candidate appears in wait pid args"
    if not clone_parent_return_candidates:
        reason = "missing positive parent-side clone return candidate"
    elif not wait_pid_args:
        reason = "missing waitid/wait4 pid argument recovery"
    return {
        "clone_parent_return_candidates": clone_parent_return_candidates,
        "wait_pid_args": wait_pid_args,
        "overlap": overlap,
        "closed": bool(overlap),
        "reason": reason,
    }


def is_pid_like(value: int | None) -> bool:
    return value is not None and 2 <= value <= 32768


def raw_process_pid_hints(events: list[dict[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    clone_parent_like: list[int] = []
    wait_pid_like: list[int] = []
    for index, event in enumerate(events):
        if event.get("evt") not in {"TRAP", "SYSCALL_ENTRY", "SYSCALL_RET"}:
            continue
        if event.get("pc_owner") != "target_sample":
            continue
        a0 = parse_int(event.get("a0"))
        a1 = parse_int(event.get("a1"))
        a2 = parse_int(event.get("a2"))
        a3 = parse_int(event.get("a3"))
        a7 = parse_int(event.get("a7"))
        syscall_name = PROCESS_SYSCALL_NRS.get(a7)
        annotations: list[str] = []
        if syscall_name:
            annotations.append(f"a7_{syscall_name}")
        if a7 == 220 and is_pid_like(a0):
            annotations.append("clone_parent_return_like")
            clone_parent_like.append(int(a0))
        if a7 == 95 and is_pid_like(a0) and a3 == 4:
            annotations.append("ambiguous_waitid_or_clone_return_preload")
            clone_parent_like.append(int(a0))
        if a0 == 1 and is_pid_like(a1) and a3 == 4:
            annotations.append("waitid_pid_arg_like")
            wait_pid_like.append(int(a1))
        if a7 == 260 and is_pid_like(a0):
            annotations.append("wait4_pid_arg_like")
            wait_pid_like.append(int(a0))
        if not annotations and not any(is_pid_like(value) for value in (a0, a1, a2)):
            continue
        if not annotations and len(rows) >= 16:
            continue
        rows.append(
            {
                "index": index,
                "record_index": event.get("record_index"),
                "evt": event.get("evt"),
                "pc": event.get("pc"),
                "symbol": event.get("symbol"),
                "callsite_kind": event.get("callsite_kind"),
                "priv": event.get("priv"),
                "a0": event.get("a0"),
                "a1": event.get("a1"),
                "a2": event.get("a2"),
                "a3": event.get("a3"),
                "a7": event.get("a7"),
                "syscall_name_by_a7": syscall_name,
                "annotations": annotations or ["pid_like_register_snapshot"],
            }
        )
    overlap = sorted(set(clone_parent_like) & set(wait_pid_like))
    if overlap:
        note = "raw pid-like snapshots overlap, but this is debug-only until semantic recovery proves syscall role and argument ownership"
    elif clone_parent_like or wait_pid_like:
        note = "raw pid-like snapshots exist, but clone parent return and wait pid argument do not close under strict semantic ownership"
    else:
        note = "no raw target pid-like snapshots found"
    return {
        "clone_parent_like_values": sorted(set(clone_parent_like)),
        "wait_pid_like_values": sorted(set(wait_pid_like)),
        "overlap": overlap,
        "note": note,
        "events": rows,
    }


def drop_windows(events: list[dict[str, Any]], window: int, status_drop: int) -> dict[str, Any]:
    indexes = [index for index, event in enumerate(events) if event.get("evt") == "DROP"]
    windows = []
    for index in indexes:
        start = max(0, index - window)
        end = min(len(events), index + window + 1)
        windows.append(
            {
                "drop_event_index": index,
                "before_after": [compact_event(event, pos) for pos, event in enumerate(events[start:end], start=start)],
            }
        )
    return {
        "status_drop": status_drop,
        "drop_events_in_trace": len(indexes),
        "note": "DROP was reported in rep status, not as in-band trace events" if status_drop and not indexes else "",
        "windows": windows,
    }


def expected_match(audit: dict[str, Any]) -> dict[str, Any]:
    for item in audit.get("matches", []):
        if isinstance(item, dict) and item.get("rule") == "process_creation_chain":
            return item
    return {"rule": "process_creation_chain", "matched": False, "missing": ["rule_not_evaluated"]}


def analyze_rep(rep_dir: Path, trace_records: int | None, tail: int, window: int) -> dict[str, Any]:
    status = load_json(rep_dir / "status.json")
    trace_path = rep_dir / "trace_code_map" / "trace.code_map.jsonl"
    if not trace_path.exists():
        trace_path = rep_dir / "trace.jsonl"
    semantic = load_json(rep_dir / "behavior_recovery" / "semantic_events.json")
    audit = load_json(rep_dir / "behavior_audit" / "behavior_audit.json")
    events = load_jsonl(trace_path)
    proc = process_syscalls(semantic)
    traps = trap_summary(events)
    cap_hit = bool(trace_records is not None and len(events) >= trace_records)
    status_drop = int(status.get("drop", 0) or 0)
    return {
        "rep": rep_dir.name,
        "status": status,
        "trace": repo_rel(trace_path),
        "event_counts": event_counts(events, status),
        "captured_events": len(events),
        "trace_records": trace_records,
        "cap_hit": cap_hit,
        "drop_rate": status_drop / (status_drop + len(events)) if status_drop + len(events) else 0.0,
        "trap_summary": traps,
        "process_syscalls": proc,
        "process_boundary": process_boundary(proc),
        "raw_process_pid_hints": raw_process_pid_hints(events),
        "rule_match": expected_match(audit),
        "cap_tail_events": [compact_event(event, index) for index, event in list(enumerate(events))[-tail:]],
        "drop_windows": drop_windows(events, window, status_drop),
    }


def aggregate_summary(reps: list[dict[str, Any]]) -> dict[str, Any]:
    totals: dict[str, int] = {}
    for rep in reps:
        for key, value in rep.get("event_counts", {}).items():
            totals[key] = totals.get(key, 0) + int(value)
    return {
        "event_totals": dict(sorted(totals.items())),
        "capped_reps": [rep["rep"] for rep in reps if rep.get("cap_hit")],
        "drop_rates": {rep["rep"]: rep.get("drop_rate") for rep in reps},
        "strong_reps": [rep["rep"] for rep in reps if rep.get("rule_match", {}).get("matched")],
        "weak_reps": [rep["rep"] for rep in reps if rep.get("rule_match", {}).get("weak_matched")],
        "boundary_closed_reps": [rep["rep"] for rep in reps if rep.get("process_boundary", {}).get("closed")],
        "dominant_trap_sources": {rep["rep"]: rep.get("trap_summary", {}).get("dominant_source") for rep in reps},
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Process Chain Capacity Debug",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Artifact root: `{report['artifact_root']}`",
        "",
        "| Rep | Events | DROP | DROP rate | Cap | SYSCALL_ENTRY | SYSCALL_RET | TRAP | Dominant TRAP source | Strong | Weak | Boundary closed |",
        "| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- | --- | --- | --- |",
    ]
    for rep in report["reps"]:
        counts = rep["event_counts"]
        match = rep["rule_match"]
        lines.append(
            f"| `{rep['rep']}` | {rep['captured_events']} | {counts.get('DROP_STATUS', 0)} | {rep['drop_rate']:.6f} | "
            f"{rep['cap_hit']} | {counts.get('SYSCALL_ENTRY', 0)} | {counts.get('SYSCALL_RET', 0)} | "
            f"{counts.get('TRAP', 0)} | {rep['trap_summary']['dominant_source']} | {match.get('matched')} | "
            f"{match.get('weak_matched')} | {rep['process_boundary']['closed']} |"
        )
    lines.extend(["", "## Boundary Evidence", ""])
    for rep in report["reps"]:
        boundary = rep["process_boundary"]
        lines.extend(
            [
                f"### `{rep['rep']}`",
                "",
                f"- Clone parent return candidates: `{boundary['clone_parent_return_candidates']}`",
                f"- Wait pid args: `{boundary['wait_pid_args']}`",
                f"- Overlap: `{boundary['overlap']}`",
                f"- Reason: {boundary['reason']}",
                "",
                "| Seq | Name | Nr | a0 | a1 | a2 | Return | Confidence | Owner |",
                "| ---: | --- | ---: | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for row in rep["process_syscalls"]:
            lines.append(
                f"| {row.get('seq')} | `{row.get('name')}` | {row.get('nr')} | {row.get('a0')} | {row.get('a1')} | "
                f"{row.get('a2')} | {row.get('return_value')} | {row.get('confidence')} | {row.get('code_map_owner')} |"
            )
        lines.append("")
        raw_hints = rep.get("raw_process_pid_hints", {})
        lines.extend(
            [
                f"- Raw clone-parent-like values: `{raw_hints.get('clone_parent_like_values', [])}`",
                f"- Raw wait-pid-like values: `{raw_hints.get('wait_pid_like_values', [])}`",
                f"- Raw overlap: `{raw_hints.get('overlap', [])}`",
                f"- Raw hint note: {raw_hints.get('note', '')}",
                "",
                "| Event | Record | Evt | a0 | a1 | a3 | a7 | Annotation |",
                "| ---: | ---: | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for event in raw_hints.get("events", [])[:12]:
            lines.append(
                f"| {event.get('index')} | {event.get('record_index')} | `{event.get('evt')}` | {event.get('a0')} | "
                f"{event.get('a1')} | {event.get('a3')} | {event.get('a7')} | {', '.join(event.get('annotations', []))} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Debug Artifacts",
            "",
            "- JSON: `aggregate/process_chain_capacity_debug.json`",
            "- Markdown: `aggregate/process_chain_capacity_debug.md`",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(run_root: Path, tail: int, window: int) -> dict[str, Any]:
    run_config = load_json(run_root / "run_config.json") if (run_root / "run_config.json").exists() else {}
    trace_records = parse_int(run_config.get("trace_records"))
    root = sample_root(run_root) / "board" / TRACE_ON
    reps = [
        analyze_rep(rep_dir, trace_records, tail, window)
        for rep_dir in sorted(root.glob("rep_*"))
        if (rep_dir / "status.json").exists() and (rep_dir / "behavior_recovery" / "semantic_events.json").exists()
    ]
    report = {
        "schema": "rvmt.process_chain_capacity_debug.v1",
        "run_id": run_root.name,
        "artifact_root": repo_rel(run_root),
        "run_config": run_config,
        "sample_id": SAMPLE_ID,
        "summary": aggregate_summary(reps),
        "reps": reps,
    }
    aggregate = run_root / "aggregate"
    aggregate.mkdir(parents=True, exist_ok=True)
    (aggregate / "process_chain_capacity_debug.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (aggregate / "process_chain_capacity_debug.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")
    return report


def self_test() -> int:
    events = [
        {"evt": "TRAP", "pc_owner": "target_sample", "instr": "0x00000073", "cause": "0x0"},
        {"evt": "TRAP", "pc_owner": "kernel", "instr": "0x0", "cause": "0x2"},
    ]
    traps = trap_summary(events)
    if traps["by_source"].get("target_ecall_boundary") != 1 or traps["by_source"].get("kernel_or_loader_trap") != 1:
        print("[FAIL] trap source classification failed", file=sys.stderr)
        return 1
    boundary = process_boundary(
        [
            {"name": "clone", "return_value": "0x10"},
            {"name": "waitid", "a1": "0x10"},
        ]
    )
    if not boundary["closed"]:
        print("[FAIL] process boundary closure self-test failed", file=sys.stderr)
        return 1
    raw_hints = raw_process_pid_hints(
        [
            {"evt": "SYSCALL_RET", "pc_owner": "target_sample", "a0": "0x21", "a1": "0x0", "a3": "0x4", "a7": "0x5f"},
            {"evt": "SYSCALL_RET", "pc_owner": "target_sample", "a0": "0x1", "a1": "0x22", "a3": "0x4", "a7": "0x0"},
        ]
    )
    if raw_hints["clone_parent_like_values"] != [33] or raw_hints["wait_pid_like_values"] != [34]:
        print("[FAIL] raw pid hint self-test failed", file=sys.stderr)
        return 1
    print("[PASS] process chain capacity debug self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explain process_chain trace capacity, DROP, TRAP source, and parent/child boundary evidence.")
    parser.add_argument("--run-id", required=False)
    parser.add_argument("--root", type=Path, default=DEFAULT_RESULT_ROOT)
    parser.add_argument("--tail", type=int, default=24)
    parser.add_argument("--window", type=int, default=8)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.run_id:
        parser.error("--run-id is required unless --self-test is used")
    try:
        run_root = resolve(args.root) / args.run_id
        report = write_outputs(run_root, args.tail, args.window)
    except Exception as exc:
        print(f"debug_process_chain_capacity: error: {exc}", file=sys.stderr)
        return 2
    print(f"[PASS] process_chain capacity debug written: {run_root / 'aggregate' / 'process_chain_capacity_debug.json'}")
    return 0 if report.get("reps") else 1


if __name__ == "__main__":
    raise SystemExit(main())
