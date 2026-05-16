from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_INVARIANTS = Path("sim/golden/fuzz_invariants.json")
KNOWN_EVENTS = {
    "RETIRE",
    "BRANCH",
    "JUMP",
    "SYSCALL_ENTRY",
    "SYSCALL_RET",
    "TRAP",
    "CSR",
    "SATP",
    "PRIV",
    "ARG_MEM",
    "DROP",
    "MARKER",
}
TRACE_REQUIRED_FIELDS = {
    "RETIRE": ["cycle", "pc", "instr", "priv"],
    "BRANCH": ["cycle", "pc", "instr", "taken", "target"],
    "JUMP": ["cycle", "pc", "instr", "target"],
    "SYSCALL_ENTRY": ["cycle", "pc", "instr", "priv", "syscall_id", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
    "SYSCALL_RET": ["cycle", "pc", "instr", "priv", "target", "syscall_id", "duration", "a0"],
    "TRAP": ["cycle", "pc", "cause", "tval", "priv"],
    "CSR": ["cycle", "pc", "instr", "csr", "value", "priv"],
    "SATP": ["cycle", "pc", "instr", "csr", "value", "satp", "priv"],
    "PRIV": ["cycle", "pc", "old_priv", "new_priv"],
    "ARG_MEM": ["cycle", "pc", "priv", "syscall_id", "arg_index", "mem_addr", "mem_data", "mem_size", "mem_last"],
    "DROP": ["cycle", "value"],
    "MARKER": ["cycle", "value"],
}
NUMERIC_FIELDS = {
    "cycle",
    "pc",
    "instr",
    "target",
    "syscall_id",
    "duration",
    "a0",
    "a1",
    "a2",
    "a3",
    "a4",
    "a5",
    "a6",
    "a7",
    "cause",
    "tval",
    "csr",
    "value",
    "satp",
    "arg_index",
    "mem_addr",
    "mem_data",
    "mem_size",
}
PRIV_FIELDS = {"priv", "old_priv", "new_priv"}
VALID_PRIVS = {"U", "S", "H", "M"}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
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


def case_config(spec: dict[str, Any], case_id: str) -> dict[str, Any]:
    cases = spec.get("cases", [])
    if not isinstance(cases, list):
        return {}
    for case in cases:
        if isinstance(case, dict) and case.get("id") == case_id:
            return case
    return {}


def event_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        evt = event.get("evt")
        if isinstance(evt, str):
            counts[evt] = counts.get(evt, 0) + 1
    return counts


def check_known_event_types(events: list[dict[str, Any]]) -> list[str]:
    errors = []
    for index, event in enumerate(events):
        evt = event.get("evt")
        if evt not in KNOWN_EVENTS:
            errors.append(f"event {index}: unknown evt {evt!r}")
    return errors


def check_trace_schema_required_fields(events: list[dict[str, Any]]) -> list[str]:
    errors = []
    for index, event in enumerate(events):
        evt = event.get("evt")
        if evt not in KNOWN_EVENTS:
            continue
        for field in TRACE_REQUIRED_FIELDS.get(str(evt), []):
            if field not in event:
                errors.append(f"event {index}: {evt} missing schema field {field}")
                continue
            if field in NUMERIC_FIELDS and parse_int(event.get(field)) is None:
                errors.append(f"event {index}: {evt}.{field} must be numeric")
            if field in PRIV_FIELDS and event.get(field) not in VALID_PRIVS:
                errors.append(f"event {index}: {evt}.{field} must be one of U/S/H/M")
        if evt == "BRANCH" and not isinstance(event.get("taken"), bool):
            errors.append(f"event {index}: BRANCH.taken must be boolean")
        if evt == "ARG_MEM" and not isinstance(event.get("mem_last"), bool):
            errors.append(f"event {index}: ARG_MEM.mem_last must be boolean")
    return errors


def check_control_flow_targets_aligned(events: list[dict[str, Any]]) -> list[str]:
    errors = []
    for index, event in enumerate(events):
        if event.get("evt") not in {"BRANCH", "JUMP"}:
            continue
        if event.get("evt") == "BRANCH" and not isinstance(event.get("taken"), bool):
            errors.append(f"event {index}: BRANCH taken must be boolean")
        target = parse_int(event.get("target"))
        if target is None:
            errors.append(f"event {index}: {event.get('evt')} missing numeric target")
        elif target % 2:
            errors.append(f"event {index}: {event.get('evt')} target is not 2-byte aligned: {event.get('target')}")
    return errors


def check_trap_not_retire(events: list[dict[str, Any]]) -> list[str]:
    errors = []
    def retire_key(event: dict[str, Any]) -> tuple[int, int] | None:
        pc = parse_int(event.get("pc"))
        instr = parse_int(event.get("instr"))
        if pc is None or instr is None:
            return None
        return (pc, instr)

    retires = {
        key
        for event in events
        if event.get("evt") == "RETIRE" and (key := retire_key(event)) is not None
    }
    for index, event in enumerate(events):
        if event.get("evt") != "TRAP":
            continue
        if event.get("cause") is None:
            errors.append(f"event {index}: TRAP missing cause")
        key = retire_key(event)
        if key is None:
            errors.append(f"event {index}: TRAP must carry numeric pc/instr for trap-not-retire invariant")
            continue
        if key in retires:
            errors.append(f"event {index}: TRAP pc/instr also appeared as RETIRE")
    return errors


def check_syscall_pairing(events: list[dict[str, Any]]) -> list[str]:
    errors = []
    pending: dict[int, dict[str, Any]] = {}
    last_id = -1
    for index, event in enumerate(events):
        evt = event.get("evt")
        if evt == "SYSCALL_ENTRY":
            if event.get("priv") != "U":
                errors.append(f"event {index}: SYSCALL_ENTRY must be U-mode")
            for arg in [f"a{i}" for i in range(8)]:
                if arg not in event:
                    errors.append(f"event {index}: SYSCALL_ENTRY missing {arg}")
                elif parse_int(event.get(arg)) is None:
                    errors.append(f"event {index}: SYSCALL_ENTRY {arg} must be numeric")
            syscall_id = parse_int(event.get("syscall_id"))
            if syscall_id is None:
                errors.append(f"event {index}: SYSCALL_ENTRY missing numeric syscall_id")
                continue
            if syscall_id <= last_id:
                errors.append(f"event {index}: syscall_id is not strictly increasing")
            last_id = syscall_id
            pending[syscall_id] = event
        elif evt == "SYSCALL_RET":
            if event.get("priv") != "S":
                errors.append(f"event {index}: SYSCALL_RET must be S-mode")
            syscall_id = parse_int(event.get("syscall_id"))
            if syscall_id is None or syscall_id not in pending:
                errors.append(f"event {index}: SYSCALL_RET has no matching entry")
                continue
            pending.pop(syscall_id)
            duration = parse_int(event.get("duration"))
            if duration is None or duration < 0:
                errors.append(f"event {index}: SYSCALL_RET duration must be non-negative")
            if parse_int(event.get("target")) is None:
                errors.append(f"event {index}: SYSCALL_RET missing numeric target return PC")
            if parse_int(event.get("a0")) is None:
                errors.append(f"event {index}: SYSCALL_RET missing numeric a0 return value")
    for syscall_id in sorted(pending):
        errors.append(f"syscall_id {syscall_id}: missing SYSCALL_RET")
    return errors


def check_context_events(events: list[dict[str, Any]]) -> list[str]:
    errors = []
    for index, event in enumerate(events):
        evt = event.get("evt")
        if evt == "PRIV" and (event.get("old_priv") is None or event.get("new_priv") is None):
            errors.append(f"event {index}: PRIV missing old_priv/new_priv")
        if evt == "SATP" and parse_int(event.get("satp")) is None:
            errors.append(f"event {index}: SATP missing numeric satp")
        if evt == "CSR":
            if parse_int(event.get("csr")) is None:
                errors.append(f"event {index}: CSR missing numeric csr")
            if parse_int(event.get("value")) is None:
                errors.append(f"event {index}: CSR missing numeric value")
    return errors


def check_drop_monotonic(events: list[dict[str, Any]]) -> list[str]:
    errors = []
    previous = -1
    for index, event in enumerate(events):
        if event.get("evt") != "DROP":
            continue
        value = parse_int(event.get("value"))
        if value is None:
            errors.append(f"event {index}: DROP missing numeric value")
            continue
        if value <= previous:
            errors.append(f"event {index}: DROP value must be strictly increasing")
        previous = value
    return errors


CHECKS = {
    "known_event_types": check_known_event_types,
    "trace_schema_required_fields": check_trace_schema_required_fields,
    "control_flow_targets_aligned": check_control_flow_targets_aligned,
    "trap_not_retire": check_trap_not_retire,
    "syscall_pairing": check_syscall_pairing,
    "context_events_well_formed": check_context_events,
    "drop_count_monotonic": check_drop_monotonic,
}


def check_case_requirements(events: list[dict[str, Any]], case: dict[str, Any]) -> list[str]:
    errors = []
    counts = event_counts(events)
    min_counts = case.get("min_counts", {})
    if isinstance(min_counts, dict):
        for evt, minimum in sorted(min_counts.items()):
            minimum_int = parse_int(minimum)
            actual = counts.get(str(evt), 0)
            if minimum_int is None:
                errors.append(f"{case.get('id')}: min_counts.{evt} is not numeric")
            elif actual < minimum_int:
                errors.append(f"{case.get('id')}: expected at least {minimum_int} {evt} events, got {actual}")

    required_fields = case.get("required_fields", {})
    if isinstance(required_fields, dict):
        for evt, fields in sorted(required_fields.items()):
            if not isinstance(fields, list):
                errors.append(f"{case.get('id')}: required_fields.{evt} must be a list")
                continue
            for index, event in enumerate(events):
                if event.get("evt") != evt:
                    continue
                for field in fields:
                    if field not in event:
                        errors.append(f"event {index}: {evt} missing required field {field}")

    allowed_trap_causes = case.get("allowed_trap_causes", [])
    if isinstance(allowed_trap_causes, list) and allowed_trap_causes:
        allowed = {parse_int(value) for value in allowed_trap_causes}
        allowed.discard(None)
        for index, event in enumerate(events):
            if event.get("evt") != "TRAP":
                continue
            cause = parse_int(event.get("cause"))
            if cause not in allowed:
                errors.append(f"event {index}: TRAP cause {event.get('cause')} is not allowed for {case.get('id')}")
    return errors


def check_trace(events: list[dict[str, Any]], case: dict[str, Any]) -> list[str]:
    errors = []
    if not events:
        errors.append("trace is empty")
    invariants = case.get("invariants", [])
    if not isinstance(invariants, list):
        errors.append(f"{case.get('id')}: invariants must be a list")
        return errors
    errors.extend(check_case_requirements(events, case))
    for invariant in invariants:
        check = CHECKS.get(invariant)
        if check is None:
            errors.append(f"unknown invariant: {invariant}")
            continue
        errors.extend(check(events))
    return errors


def build_report(trace_path: Path, events: list[dict[str, Any]], case: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    return {
        "schema": "rvmt.fuzz.trace_report.v1",
        "case": case.get("id"),
        "trace": trace_path.as_posix(),
        "status": "FAIL" if errors else "PASS",
        "events": len(events),
        "event_counts": dict(sorted(event_counts(events).items())),
        "invariants": case.get("invariants", []),
        "min_counts": case.get("min_counts", {}),
        "errors": errors,
        "non_claim": "This report validates RV-MalTrace trace invariants, not processor bug discovery.",
    }


def render_report(report: dict[str, Any]) -> str:
    lines = [
        "# Fuzz Trace Invariant Report",
        "",
        f"- Case: `{report.get('case')}`",
        f"- Source trace: `{report.get('trace')}`",
        f"- Status: {report.get('status')}",
        f"- Events: {report.get('events')}",
        "",
        "| Event | Count |",
        "| --- | ---: |",
    ]
    counts = report.get("event_counts", {})
    if isinstance(counts, dict):
        for evt, count in counts.items():
            lines.append(f"| {evt} | {count} |")
    errors = report.get("errors", [])
    lines.extend(["", "## Errors", ""])
    if errors:
        for error in errors:
            lines.append(f"- {error}")
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "This report validates trace invariants only. It is not a processor bug-discovery or malware-detection claim.",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(trace_path: Path, out_dir: Path, events: list[dict[str, Any]], case: dict[str, Any], errors: list[str]) -> None:
    report = build_report(trace_path, events, case, errors)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "fuzz_trace_invariants.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "fuzz_trace_report.md").write_text(render_report(report), encoding="utf-8", newline="\n")


def self_test() -> int:
    good_trace = [
        {"cycle": 1, "evt": "SYSCALL_ENTRY", "pc": "0x1000", "instr": "0x00000073", "priv": "U", "syscall_id": "0x0", "a0": "0x1", "a1": "0x0", "a2": "0x0", "a3": "0x0", "a4": "0x0", "a5": "0x0", "a6": "0x0", "a7": "0x40"},
        {"cycle": 2, "evt": "SYSCALL_RET", "pc": "0x1010", "instr": "0x10200073", "priv": "S", "target": "0x1004", "syscall_id": "0x0", "duration": 1, "a0": "0x1"},
        {"cycle": 3, "evt": "BRANCH", "pc": "0x1004", "instr": "0x00050863", "target": "0x1010", "taken": True},
        {"cycle": 4, "evt": "JUMP", "pc": "0x1010", "instr": "0x0000006f", "target": "0x1020"},
        {"cycle": 5, "evt": "TRAP", "pc": "0x1020", "instr": "0xffffffff", "cause": "0x2", "tval": "0xffffffff", "priv": "U"},
        {"cycle": 6, "evt": "PRIV", "pc": "0x1020", "old_priv": "U", "new_priv": "S"},
        {"cycle": 7, "evt": "SATP", "pc": "0x1024", "instr": "0x18051073", "csr": "0x180", "value": "0x0", "satp": "0x0", "priv": "S"},
        {"cycle": 8, "evt": "DROP", "value": "0x1"},
        {"cycle": 9, "evt": "DROP", "value": "0x2"},
    ]
    good_case = {
        "id": "smoke",
        "invariants": sorted(CHECKS),
        "min_counts": {"SYSCALL_ENTRY": 1, "SYSCALL_RET": 1, "BRANCH": 1, "JUMP": 1, "TRAP": 1, "PRIV": 1, "SATP": 1, "DROP": 2},
        "required_fields": {"BRANCH": ["target", "taken"], "JUMP": ["target"], "TRAP": ["cause"], "DROP": ["value"]},
        "allowed_trap_causes": ["0x2"],
    }
    if check_trace(good_trace, good_case):
        print("[FAIL] self-test rejected valid fuzz trace", file=sys.stderr)
        return 1

    negative_cases = [
        ([{"cycle": 1, "evt": "MARKER", "value": "0x1"}], {"id": "cf", "invariants": ["known_event_types", "trace_schema_required_fields"], "min_counts": {"BRANCH": 1}}, "marker-only missing branch"),
        ([{"cycle": 1, "evt": "DROP", "value": "0x1"}], {"id": "context", "invariants": ["known_event_types", "trace_schema_required_fields"], "min_counts": {"SATP": 1}}, "drop-only missing context"),
        ([{"cycle": 1, "evt": "BRANCH", "target": "0x1000", "taken": True}, {"cycle": 2, "evt": "JUMP", "target": "0x1004"}], {"id": "weak-cf-schema", "invariants": ["trace_schema_required_fields"], "min_counts": {"BRANCH": 1, "JUMP": 1}}, "control-flow missing pc/instr"),
        ([{"cycle": True, "evt": "BRANCH", "pc": "0x1000", "instr": "0x63", "target": False, "taken": True}], {"id": "bad-bool-numeric", "invariants": ["trace_schema_required_fields"], "min_counts": {"BRANCH": 1}}, "boolean numeric field"),
        ([{"cycle": 1, "evt": "TRAP", "cause": "0x2"}], {"id": "weak-trap-schema", "invariants": ["trace_schema_required_fields"], "min_counts": {"TRAP": 1}}, "trap missing schema fields"),
        ([{**good_trace[2], "target": "0x1011"}], {"id": "bad-cf", "invariants": ["control_flow_targets_aligned"], "min_counts": {"BRANCH": 1}}, "unaligned branch target"),
        ([{**good_trace[2], "taken": "yes"}], {"id": "bad-branch-taken", "invariants": ["control_flow_targets_aligned"], "min_counts": {"BRANCH": 1}}, "branch taken not boolean"),
        ([{key: value for key, value in good_trace[2].items() if key != "taken"}], {"id": "bad-branch", "invariants": ["known_event_types"], "min_counts": {"BRANCH": 1}, "required_fields": {"BRANCH": ["target", "taken"]}}, "branch missing taken"),
        ([{**good_trace[0], "priv": "S"}], {"id": "bad-syscall", "invariants": ["syscall_pairing"], "min_counts": {"SYSCALL_ENTRY": 1}}, "S-mode syscall entry"),
        ([{**good_trace[0], "a7": "not-a-number"}], {"id": "bad-syscall-arg", "invariants": ["syscall_pairing"], "min_counts": {"SYSCALL_ENTRY": 1}}, "non-numeric syscall arg"),
        ([{"cycle": 1, "evt": "SYSCALL_ENTRY", "pc": "0x1000", "instr": "0x73", "priv": "U", "syscall_id": "0x0", "a0": "0x1", "a1": "0x0", "a2": "0x0", "a3": "0x0", "a4": "0x0", "a5": "0x0", "a6": "0x0", "a7": "0x40"}, {"cycle": 2, "evt": "SYSCALL_RET", "pc": "0x1004", "instr": "0x10200073", "priv": "S", "syscall_id": "0x0", "duration": 1, "target": "0x1000"}], {"id": "bad-ret-a0", "invariants": ["trace_schema_required_fields", "syscall_pairing"], "min_counts": {"SYSCALL_ENTRY": 1, "SYSCALL_RET": 1}}, "syscall return missing a0"),
        ([{"cycle": 1, "evt": "SYSCALL_RET", "syscall_id": "0x2", "duration": 1, "target": "0x1000", "a0": "0x0", "priv": "S"}], {"id": "bad-ret", "invariants": ["syscall_pairing"], "min_counts": {"SYSCALL_RET": 1}}, "unmatched syscall return"),
        ([{"cycle": 1, "evt": "DROP", "value": "0x2"}, {"cycle": 2, "evt": "DROP", "value": "0x2"}], {"id": "bad-drop", "invariants": ["drop_count_monotonic"], "min_counts": {"DROP": 2}}, "non-monotonic drop"),
        ([{"cycle": 1, "evt": "TRAP", "pc": "0x0000000000001000", "instr": "0xffffffff", "cause": "0x2"}, {"cycle": 2, "evt": "RETIRE", "pc": "0x1000", "instr": "0xffffffff"}], {"id": "bad-trap-retire", "invariants": ["trap_not_retire"], "min_counts": {"TRAP": 1}}, "trap/retire overlap"),
        ([{"cycle": 1, "evt": "TRAP", "pc": "0x1000", "cause": "0x2", "tval": "0x0", "priv": "U"}, {"cycle": 2, "evt": "RETIRE", "pc": "0x1000", "instr": "0xffffffff", "priv": "U"}], {"id": "bad-trap-missing-instr", "invariants": ["trap_not_retire"], "min_counts": {"TRAP": 1}}, "trap missing instr for trap invariant"),
        ([{"cycle": 1, "evt": "TRAP", "pc": "0x1000", "instr": "0xffffffff", "cause": "0x7"}], {"id": "bad-trap-cause", "invariants": ["trap_not_retire"], "min_counts": {"TRAP": 1}, "allowed_trap_causes": ["0x2"]}, "disallowed trap cause"),
        ([{"cycle": 1, "evt": "SATP", "satp": "not-a-number"}], {"id": "bad-context", "invariants": ["context_events_well_formed"], "min_counts": {"SATP": 1}}, "non-numeric SATP"),
        ([{"cycle": 1, "evt": "BRANCH", "target": "0x1000", "taken": True}], {"id": "overflow", "invariants": ["control_flow_targets_aligned", "drop_count_monotonic"], "min_counts": {"BRANCH": 1, "DROP": 1}}, "overflow without DROP"),
    ]
    for trace, case, label in negative_cases:
        if not check_trace(trace, case):
            print(f"[FAIL] self-test missed {label}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        trace_path = root / "trace.jsonl"
        spec_path = root / "invariants.json"
        trace_path.write_text("\n".join(json.dumps(event) for event in good_trace) + "\n", encoding="utf-8")
        spec_path.write_text(json.dumps({"cases": [good_case]}), encoding="utf-8")
        selected = case_config(load_json(spec_path), "smoke")
        if selected.get("invariants") != sorted(CHECKS):
            print("[FAIL] self-test failed to load case invariants", file=sys.stderr)
            return 1
        if check_trace(load_jsonl(trace_path), selected):
            print("[FAIL] self-test rejected JSONL smoke fixture", file=sys.stderr)
            return 1
        out_dir = root / "out"
        errors = check_trace(load_jsonl(trace_path), selected)
        write_outputs(trace_path, out_dir, load_jsonl(trace_path), selected, errors)
        report = load_json(out_dir / "fuzz_trace_invariants.json")
        if report.get("status") != "PASS" or report.get("event_counts", {}).get("DROP") != 2:
            print("[FAIL] self-test missed fuzz report content", file=sys.stderr)
            return 1
        report_text = (out_dir / "fuzz_trace_report.md").read_text(encoding="utf-8")
        if "not a processor bug-discovery" not in report_text:
            print("[FAIL] self-test missed fuzz report non-claim", file=sys.stderr)
            return 1

    print("[PASS] fuzz trace invariant checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check rv-maltrace fuzz/stress trace invariants.")
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--invariants", type=Path, default=DEFAULT_INVARIANTS)
    parser.add_argument("--case", required=False)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.trace is None or args.case is None:
        parser.error("--trace and --case are required unless --self-test is used")
    try:
        spec = load_json(args.invariants)
        case = case_config(spec, args.case)
        if not case:
            raise ValueError(f"{args.invariants}: no case found for {args.case!r}")
        events = load_jsonl(args.trace)
        errors = check_trace(events, case)
        if args.out_dir is not None:
            write_outputs(args.trace, args.out_dir, events, case, errors)
    except Exception as exc:
        print(f"check_fuzz_trace: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print(f"[PASS] fuzz trace invariants hold for {args.case}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
