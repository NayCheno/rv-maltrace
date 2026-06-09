from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from compare_trace import compare


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
    return rows


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def parse_capture_spec(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in text.split(","):
        if not part:
            continue
        key, sep, value = part.partition("=")
        if not sep:
            raise ValueError(f"invalid capture spec part: {part}")
        result[key.strip()] = value.strip()
    required = {"id", "csv", "trace", "program", "log", "trigger", "validity"}
    missing = sorted(required - set(result))
    if missing:
        raise ValueError(f"capture spec missing keys: {', '.join(missing)}")
    return result


def rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def parse_log_value(text: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}=(.*)$", text, flags=re.MULTILINE)
    return match.group(1).strip() if match else None


def event_counts(events: list[dict[str, Any]]) -> Counter[str]:
    return Counter(str(event.get("evt", "")) for event in events)


def syscall_entry_counts(events: list[dict[str, Any]]) -> Counter[str]:
    return Counter(
        str(event.get("a7"))
        for event in events
        if event.get("evt") == "SYSCALL_ENTRY" and event.get("a7") is not None
    )


def normalize_syscall(number: int) -> str:
    return f"0x{number:016x}"


def summarize_requirements(events: list[dict[str, Any]], expected: dict[str, Any]) -> dict[str, Any]:
    counts = event_counts(events)
    syscalls = syscall_entry_counts(events)
    required_events = list(expected.get("required_events", []))
    forbidden_events = list(expected.get("forbidden_events", []))
    required_syscalls = [row for row in expected.get("required_syscalls", []) if isinstance(row, dict)]
    wanted = Counter(normalize_syscall(int(row["number"])) for row in required_syscalls if "number" in row)
    return {
        "required_events": {
            event: {"required": True, "actual_count": counts.get(str(event), 0), "pass": counts.get(str(event), 0) > 0}
            for event in required_events
        },
        "forbidden_events": {
            event: {"required_absent": True, "actual_count": counts.get(str(event), 0), "pass": counts.get(str(event), 0) == 0}
            for event in forbidden_events
        },
        "required_syscalls": {
            number: {"minimum": minimum, "actual_entry_count": syscalls.get(number, 0), "pass": syscalls.get(number, 0) >= minimum}
            for number, minimum in sorted(wanted.items())
        },
    }


def all_requirement_checks_pass(requirements: dict[str, Any]) -> bool:
    for group in requirements.values():
        if isinstance(group, dict):
            for row in group.values():
                if isinstance(row, dict) and row.get("pass") is not True:
                    return False
    return True


def render_observation(summary: dict[str, Any]) -> str:
    lines = [
        f"# {summary['sample_id']} Board Trace Observation",
        "",
        f"Status: {summary['status']}",
        "",
        f"Run: `{summary['run_id']}`",
        f"Board: {summary['board']} / {summary['cpu']}",
        f"Runtime path: `{summary['runtime_path']}`",
        "",
        "## Evidence",
        "",
        f"- Program log: `program.log`",
        f"- Merged trace: `trace.jsonl`",
        f"- Trace summary: `trace_summary.json`",
        f"- Capture manifest: `capture_manifest.json`",
        f"- Compare log: `compare.log`",
        "",
        "## Event Counts",
        "",
    ]
    for key, value in sorted(summary["event_counts"].items()):
        lines.append(f"- {key}: {value}")
    lines += ["", "## Syscall Entry Counts", ""]
    for key, value in sorted(summary["syscall_entry_counts"].items()):
        lines.append(f"- {key}: {value}")
    if not summary["syscall_entry_counts"]:
        lines.append("- none")
    lines += ["", "## Capture Boundary", ""]
    lines.extend(f"- {item}" for item in summary.get("limitations", []))
    lines += ["", "## Capture Set", ""]
    for capture in summary["captures"]:
        lines.append(f"- `{capture['id']}`: {capture['trigger']}; validity={capture['validity']}; events={capture['events']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Package Genesys2/CVA6 ILA captures into board trace evidence artifacts.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--sample-dir", type=Path, required=True)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--runtime-path", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--status", default="PARTIAL")
    parser.add_argument("--limitation", action="append", default=[])
    parser.add_argument("--capture", action="append", default=[], help="Comma-separated key=value spec.")
    args = parser.parse_args()

    if not args.capture:
        parser.error("at least one --capture is required")

    root = args.repo_root.resolve()
    sample_dir = args.sample_dir
    expected = load_json(args.expected)

    merged: list[dict[str, Any]] = []
    captures: list[dict[str, Any]] = []
    program_parts: list[str] = []
    for spec_text in args.capture:
        spec = parse_capture_spec(spec_text)
        trace_path = Path(spec["trace"])
        csv_path = Path(spec["csv"])
        program_path = Path(spec["program"])
        log_path = Path(spec["log"])
        events = load_jsonl(trace_path)
        log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
        program_text = program_path.read_text(encoding="utf-8", errors="replace") if program_path.exists() else ""
        program_parts.append(f"===== {spec['id']} ({spec['trigger']}) =====\n{program_text.rstrip()}\n")
        captures.append(
            {
                "id": spec["id"],
                "trigger": spec["trigger"],
                "validity": spec["validity"],
                "csv": rel(csv_path, root),
                "trace": rel(trace_path, root),
                "program_log": rel(program_path, root),
                "capture_log": rel(log_path, root),
                "events": len(events),
                "event_counts": dict(sorted(event_counts(events).items())),
                "trigger_compare": parse_log_value(log_text, "RVMT_TRIGGER_PAYLOAD_COMPARE"),
                "capture_mode": parse_log_value(log_text, "RVMT_CAPTURE_MODE"),
                "capture_condition": parse_log_value(log_text, "RVMT_CAPTURE_CONDITION"),
            }
        )
        for event in events:
            combined = dict(event)
            combined["source_record_index"] = combined.get("record_index")
            combined["record_index"] = len(merged)
            combined["capture_id"] = spec["id"]
            combined["capture_trigger"] = spec["trigger"]
            combined["capture_validity"] = spec["validity"]
            combined["capture_csv"] = rel(csv_path, root)
            merged.append(combined)

    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "program.log").write_text("\n".join(program_parts), encoding="utf-8", newline="\n")
    (sample_dir / "trace.jsonl").write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in merged), encoding="utf-8", newline="\n"
    )
    ok, messages = compare(merged, expected)
    (sample_dir / "compare.log").write_text("\n".join(messages) + "\n", encoding="utf-8", newline="\n")
    requirements = summarize_requirements(merged, expected)
    paired_capture_ids = [
        capture["id"]
        for capture in captures
        if capture["event_counts"].get("SYSCALL_ENTRY", 0) > 0 and capture["event_counts"].get("SYSCALL_RET", 0) > 0
    ]
    summary = {
        "schema": "rvmt.genesys2.board_trace_summary.v1",
        "sample_id": args.sample_id,
        "run_id": args.run_id,
        "board": "Digilent Genesys2",
        "cpu": "CVA6",
        "runtime_path": args.runtime_path,
        "binary": args.binary,
        "source": args.source,
        "expected": rel(args.expected, root),
        "status": args.status,
        "events": len(merged),
        "event_counts": dict(sorted(event_counts(merged).items())),
        "syscall_entry_counts": dict(sorted(syscall_entry_counts(merged).items())),
        "requirements": requirements,
        "compare_pass": ok,
        "requirement_checks_pass": all_requirement_checks_pass(requirements),
        "paired_entry_return_capture_ids": paired_capture_ids,
        "paired_entry_return_in_single_capture": bool(paired_capture_ids),
        "captures": captures,
        "limitations": args.limitation,
    }
    write_json(sample_dir / "trace_summary.json", summary)
    write_json(
        sample_dir / "capture_manifest.json",
        {
            "schema": "rvmt.genesys2.capture_manifest.v1",
            "sample_id": args.sample_id,
            "run_id": args.run_id,
            "board": "Digilent Genesys2",
            "cpu": "CVA6",
            "jtag": "Genesys2 onboard JTAG via Vivado hw_server",
            "uart": "Genesys2 onboard UART COM7 115200 8N1",
            "ila": {
                "data_depth": 1024,
                "capture_mode": "ALWAYS",
                "storage_qualification": "not enabled in current xlnx_ila bitstream",
            },
            "captures": captures,
            "limitations": args.limitation,
        },
    )
    (sample_dir / "observation.md").write_text(render_observation(summary), encoding="utf-8", newline="\n")
    print(f"[PASS] packaged {args.sample_id}: compare_pass={ok} events={len(merged)}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
