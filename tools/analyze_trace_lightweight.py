from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import compress_trace
from parse_trace import load_trace


PROFILE_EVENTS = {
    "board_minimal": {
        "behavior_events": {"BRANCH", "SYSCALL_ENTRY", "SYSCALL_RET", "TRAP", "CSR", "SATP", "PRIV"},
        "accounting_events": {"DROP"},
        "allowed_other_events": set(),
        "forbidden_behavior_events": {"RETIRE", "JUMP", "MARKER", "ARG_MEM"},
    },
    "semantic_mvp": {
        "behavior_events": {"BRANCH", "JUMP", "SYSCALL_ENTRY", "SYSCALL_RET", "TRAP", "CSR", "SATP", "PRIV", "ARG_MEM"},
        "accounting_events": {"DROP"},
        "allowed_other_events": set(),
        "forbidden_behavior_events": {"MARKER"},
    },
}


def parse_int(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not an integer")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 0)


def event_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        evt = str(event.get("evt", "NONE"))
        counts[evt] = counts.get(evt, 0) + 1
    return dict(sorted(counts.items()))


def drop_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    values = [parse_int(event.get("value", 0)) for event in events if event.get("evt") == "DROP"]
    return {
        "drop_records": len(values),
        "dropped_event_count": sum(values),
        "max_drop_value": max(values) if values else 0,
    }


def byte_count(items: list[dict[str, Any]]) -> int:
    return compress_trace.byte_count(items)


def profile_summary(events: list[dict[str, Any]], profile: str) -> dict[str, Any]:
    if profile not in PROFILE_EVENTS:
        raise ValueError(f"unknown lightweight profile: {profile}")
    policy = PROFILE_EVENTS[profile]
    counts = event_counts(events)
    present = {evt for evt, count in counts.items() if count > 0}
    forbidden_present = sorted(present & policy["forbidden_behavior_events"])
    behavior_present = sorted(present & policy["behavior_events"])
    accounting_present = sorted(present & policy["accounting_events"])
    allowed_present = set(policy["behavior_events"]) | set(policy["accounting_events"]) | set(policy["allowed_other_events"])
    unexpected_present = sorted(present - allowed_present)
    return {
        "profile": profile,
        "behavior_events_present": behavior_present,
        "accounting_events_present": accounting_present,
        "unexpected_events_present": unexpected_present,
        "forbidden_behavior_events_present": forbidden_present,
        "profile_matched": not forbidden_present and not unexpected_present,
    }


def analyze(events: list[dict[str, Any]], source: str, profile: str) -> dict[str, Any]:
    records = compress_trace.compress_events(events)
    decoded = compress_trace.decompress_records(records)
    if decoded != events:
        raise ValueError("compact trace roundtrip mismatch")
    original_bytes = byte_count(events)
    compact_bytes = byte_count(records)
    payload_bytes = sum(int(record["header"]["payload_len"]) for record in records)
    return {
        "schema": "rvmt.lightweight_trace.analysis.v1",
        "source": source,
        "profile": profile_summary(events, profile),
        "event_counts": event_counts(events),
        "events": len(events),
        "bytes": {
            "original_jsonl": original_bytes,
            "compact_jsonl": compact_bytes,
            "payload": payload_bytes,
            "compact_to_original_ratio": (compact_bytes / original_bytes) if original_bytes else None,
        },
        "drop": drop_summary(events),
        "roundtrip": "PASS",
        "non_claim": "This is trace-volume and selectivity analysis, not runtime overhead or detection-quality evidence.",
    }


def render_report(result: dict[str, Any]) -> str:
    profile = result["profile"]
    byte_stats = result["bytes"]
    drop = result["drop"]
    lines = [
        "# Lightweight Trace Analysis",
        "",
        f"- Source trace: `{result['source']}`",
        f"- Profile: `{profile['profile']}`",
        f"- Profile matched: {profile['profile_matched']}",
        f"- Events: {result['events']}",
        f"- Original JSONL bytes: {byte_stats['original_jsonl']}",
        f"- Compact JSONL bytes: {byte_stats['compact_jsonl']}",
        f"- Compact/original ratio: {byte_stats['compact_to_original_ratio']:.3f}" if byte_stats["compact_to_original_ratio"] is not None else "- Compact/original ratio: n/a",
        f"- DROP records: {drop['drop_records']}",
        f"- Dropped event count: {drop['dropped_event_count']}",
        "",
        "| Event | Count |",
        "| --- | ---: |",
    ]
    for evt, count in result["event_counts"].items():
        lines.append(f"| {evt} | {count} |")
    lines.extend(
        [
            "",
            "This report is trace-volume and selectivity analysis only. It is not runtime overhead or detection-quality evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(trace_path: Path, out_dir: Path, profile: str) -> None:
    events = load_trace(trace_path)
    result = analyze(events, trace_path.as_posix(), profile)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "lightweight_trace_analysis.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "lightweight_trace_report.md").write_text(render_report(result), encoding="utf-8", newline="\n")


def self_test() -> int:
    trace = [
        {"cycle": 1, "evt": "SYSCALL_ENTRY", "pc": "0x0000000000001000", "instr": "0x00000073", "priv": "U", "syscall_id": "0x0", "a0": "0x1", "a1": "0x0", "a2": "0x0", "a3": "0x0", "a4": "0x0", "a5": "0x0", "a6": "0x0", "a7": "0x40"},
        {"cycle": 2, "evt": "TRAP", "pc": "0x0000000000001000", "cause": "0x8", "tval": "0x0", "priv": "U"},
        {"cycle": 3, "evt": "PRIV", "pc": "0x0000000000001000", "old_priv": "U", "new_priv": "S", "target": "0x0000000000002000"},
        {"cycle": 4, "evt": "BRANCH", "pc": "0x0000000000001010", "instr": "0x00050863", "priv": "S", "taken": True, "target": "0x0000000000001020"},
        {"cycle": 5, "evt": "DROP", "value": "0x2"},
    ]
    bad_trace = [*trace, {"cycle": 6, "evt": "RETIRE", "pc": "0x0000000000001030", "instr": "0x00000013", "priv": "S"}]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        trace_path = root / "trace.jsonl"
        bad_trace_path = root / "bad_trace.jsonl"
        out_dir = root / "out"
        trace_path.write_text("\n".join(json.dumps(event) for event in trace) + "\n", encoding="utf-8")
        bad_trace_path.write_text("\n".join(json.dumps(event) for event in bad_trace) + "\n", encoding="utf-8")
        write_outputs(trace_path, out_dir, "board_minimal")
        result = json.loads((out_dir / "lightweight_trace_analysis.json").read_text(encoding="utf-8"))
        if not result["profile"]["profile_matched"]:
            print("[FAIL] self-test rejected board-minimal trace", file=sys.stderr)
            return 1
        if result["drop"]["dropped_event_count"] != 2:
            print("[FAIL] self-test missed DROP accounting", file=sys.stderr)
            return 1
        bad = analyze(load_trace(bad_trace_path), bad_trace_path.as_posix(), "board_minimal")
        if bad["profile"]["profile_matched"]:
            print("[FAIL] self-test allowed RETIRE in board-minimal profile", file=sys.stderr)
            return 1
        unknown = analyze([*trace, {"cycle": 6, "evt": "FOO"}], "unknown", "board_minimal")
        if unknown["profile"]["profile_matched"]:
            print("[FAIL] self-test allowed unknown event in board-minimal profile", file=sys.stderr)
            return 1
    print("[PASS] lightweight trace analysis self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze event selectivity and compact trace volume for rv-maltrace JSONL.")
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--profile", choices=sorted(PROFILE_EVENTS), default="semantic_mvp")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.trace is None or args.out_dir is None:
        parser.error("--trace and --out-dir are required unless --self-test is used")
    try:
        write_outputs(args.trace, args.out_dir, args.profile)
    except Exception as exc:
        print(f"analyze_trace_lightweight: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
