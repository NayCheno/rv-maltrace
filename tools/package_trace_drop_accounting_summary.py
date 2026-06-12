from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_P0_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260611-p0-continuous-136bit")
DEFAULT_P0_BRAM_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260612-p0-bram-repetitions")
DEFAULT_SAFE_RUN_ROOT = Path("results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610")
DEFAULT_SAFE_BRAM_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait")
DEFAULT_OUT = Path("results/evaluation/genesys2-cva6/current/drop_accounting_summary.json")

P0_TRACE_PATHS = {
    "hello_write": Path("01_hello_write/trace.jsonl"),
    "file_open_read_write": Path("02_file_open_read_write/trace.jsonl"),
    "fork_exec": Path("03_fork_exec/trace.jsonl"),
    "illegal_instruction": Path("04_illegal_instruction/trace.jsonl"),
}

SAFE_TRACE_PATHS = {
    "file_scan": Path("file_scan/hardware_trace/trace.jsonl"),
    "batch_open_read_write": Path("batch_open_read_write/hardware_trace/trace.jsonl"),
    "self_copy_sim": Path("self_copy_sim/hardware_trace/trace.jsonl"),
    "abnormal_syscall_sequence": Path("abnormal_syscall_sequence/hardware_trace/trace.jsonl"),
    "illegal_trap": Path("illegal_trap/hardware_trace/trace.jsonl"),
    "process_chain": Path("process_chain/hardware_trace/trace.jsonl"),
    "dynamic_executable_memory": Path("dynamic_executable_memory/hardware_trace/trace.jsonl"),
    "anti_debug_like": Path("anti_debug_like/hardware_trace/trace.jsonl"),
}


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


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


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
        except ValueError:
            return None
    return None


def is_drop_event(event: dict[str, Any]) -> bool:
    evt = str(event.get("evt") or "").upper()
    evt_code = parse_int(event.get("evt_code"))
    return evt in {"DROP", "EVT_DROP"} or evt_code == 11


def drop_amount(event: dict[str, Any]) -> int:
    for key in ("drop_count", "dropped_count", "value", "packed_primary"):
        parsed = parse_int(event.get(key))
        if parsed is not None:
            return max(parsed, 0)
    return 1


def capture_window_count(events: list[dict[str, Any]]) -> int:
    capture_ids = {str(event.get("capture_id")) for event in events if event.get("capture_id") is not None}
    if capture_ids:
        return len(capture_ids)
    return 1 if events else 0


def marker_window_present(events: list[dict[str, Any]]) -> bool:
    markers = [event for event in events if str(event.get("evt")) == "MARKER"]
    begins = [event for event in markers if str(event.get("packed_primary") or event.get("value") or "").lower().startswith("0xb")]
    ends = [event for event in markers if str(event.get("packed_primary") or event.get("value") or "").lower().startswith("0xe")]
    return bool(begins and ends)


def rep_sort_key(path: Path) -> tuple[int, str]:
    name = path.parent.name
    if name.startswith("rep_"):
        suffix = name.split("_", 1)[1]
        if suffix.isdigit():
            return (int(suffix), name)
    return (10**9, name)


def bram_repetition_paths(run_root: Path, sample_id: str) -> list[Path]:
    sample_root = run_root / sample_id
    if not sample_root.is_dir():
        return []
    return sorted(sample_root.glob("rep_*/bram_records.jsonl"), key=rep_sort_key)


def package_sample(
    sample_id: str,
    trace_path: Path,
    *,
    sample_class: str,
    continuity_scope: str | None = None,
) -> dict[str, Any]:
    if not trace_path.is_file():
        return {
            "sample_id": sample_id,
            "sample_class": sample_class,
            "trace": repo_rel(trace_path),
            "status": "FAIL",
            "total_events": 0,
            "drop_events": 0,
            "unaccounted_drop": 1,
            "missing_trace": True,
        }
    events = load_jsonl(trace_path)
    return package_events(
        sample_id,
        trace_path,
        events,
        sample_class=sample_class,
        continuity_scope=continuity_scope,
    )


def package_events(
    sample_id: str,
    trace_path: Path,
    events: list[dict[str, Any]],
    *,
    sample_class: str,
    continuity_scope: str | None = None,
) -> dict[str, Any]:
    drops = [event for event in events if is_drop_event(event)]
    drop_total = sum(drop_amount(event) for event in drops)
    row: dict[str, Any] = {
        "sample_id": sample_id,
        "sample_class": sample_class,
        "trace": repo_rel(trace_path),
        "status": "PASS" if events and drop_total == 0 else "FAIL",
        "total_events": len(events),
        "event_counts": dict(sorted(Counter(str(event.get("evt")) for event in events).items())),
        "drop_events": len(drops),
        "drop_total": drop_total,
        "unaccounted_drop": drop_total,
        "capture_windows": capture_window_count(events),
        "marker_window_present": marker_window_present(events),
        "continuity_scope": continuity_scope
        or ("continuous_marker_window" if sample_class == "p0_safe_synthetic" else "captured_trace_windows"),
    }
    if drops:
        row["drop_locations"] = [
            {
                "record_index": event.get("record_index"),
                "cycle": event.get("cycle"),
                "amount": drop_amount(event),
                "trace": repo_rel(trace_path),
            }
            for event in drops
        ]
        row["impact_analysis"] = "DROP events are present; this sample cannot be used as correctness-mode no-drop evidence."
    return row


def package_bram_sample(sample_id: str, bram_run_root: Path, *, sample_class: str) -> dict[str, Any]:
    paths = bram_repetition_paths(bram_run_root, sample_id)
    if not paths:
        return {
            "sample_id": sample_id,
            "sample_class": sample_class,
            "trace": repo_rel(bram_run_root / sample_id / "rep_01" / "bram_records.jsonl"),
            "status": "FAIL",
            "total_events": 0,
            "drop_events": 0,
            "unaccounted_drop": 1,
            "missing_trace": True,
        }

    repetitions: list[dict[str, Any]] = []
    failed_attempts: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    drop_locations: list[dict[str, Any]] = []
    for path in paths:
        events = load_jsonl(path)
        rep = package_events(
            sample_id,
            path,
            events,
            sample_class=sample_class,
            continuity_scope="begin_marker_cleared_bram_window",
        )
        rep["repetition_id"] = path.parent.name
        summary_path = path.parent / "bram_summary.json"
        if summary_path.is_file():
            summary = load_json(summary_path)
            bram = summary.get("bram_ring", {}) if isinstance(summary.get("bram_ring"), dict) else {}
            bram_drop = int(bram.get("dropped_count", 0) or 0)
            bram_wrap = int(bram.get("wrap_count", 0) or 0)
            rep["bram_summary"] = repo_rel(summary_path)
            rep["bram_dropped_count"] = bram_drop
            rep["bram_wrap_count"] = bram_wrap
            if bram_drop or bram_wrap:
                rep["status"] = "FAIL"
                rep["drop_events"] = max(int(rep.get("drop_events", 0) or 0), 1 if bram_drop else 0)
                rep["drop_total"] = max(int(rep.get("drop_total", 0) or 0), bram_drop)
                rep["unaccounted_drop"] = max(int(rep.get("unaccounted_drop", 0) or 0), bram_drop)
                rep["impact_analysis"] = "BRAM summary reports dropped or wrapped records; this attempt is retained as a failed attempt and is not counted as accepted no-drop evidence."
                rep["drop_locations"] = rep.get("drop_locations") or [
                    {
                        "record_index": None,
                        "cycle": bram.get("start_timestamp"),
                        "amount": bram_drop,
                        "wrap_count": bram_wrap,
                        "trace": repo_rel(path),
                        "bram_summary": repo_rel(summary_path),
                    }
                ]
        target = repetitions if rep.get("status") == "PASS" and int(rep.get("unaccounted_drop", 0) or 0) == 0 else failed_attempts
        target.append(rep)
        if target is repetitions:
            counts.update(rep.get("event_counts", {}))
        for location in rep.get("drop_locations", []) or []:
            if isinstance(location, dict):
                merged = dict(location)
                merged["repetition_id"] = rep["repetition_id"]
                if target is repetitions:
                    drop_locations.append(merged)

    total_events = sum(int(rep.get("total_events", 0) or 0) for rep in repetitions)
    drop_events = sum(int(rep.get("drop_events", 0) or 0) for rep in repetitions)
    drop_total = sum(int(rep.get("drop_total", 0) or 0) for rep in repetitions)
    unaccounted_drop = sum(int(rep.get("unaccounted_drop", 0) or 0) for rep in repetitions)
    row: dict[str, Any] = {
        "sample_id": sample_id,
        "sample_class": sample_class,
        "trace": repetitions[0].get("trace"),
        "traces": [rep.get("trace") for rep in repetitions],
        "status": "PASS" if repetitions and all(rep.get("status") == "PASS" for rep in repetitions) else "FAIL",
        "total_events": total_events,
        "event_counts": dict(sorted(counts.items())),
        "drop_events": drop_events,
        "drop_total": drop_total,
        "unaccounted_drop": unaccounted_drop,
        "capture_windows": sum(int(rep.get("capture_windows", 0) or 0) for rep in repetitions),
        "marker_window_present": all(bool(rep.get("marker_window_present")) for rep in repetitions),
        "continuity_scope": "begin_marker_cleared_bram_window_repetitions",
        "repetition_count": len(repetitions),
        "attempt_count": len(paths),
        "failed_attempt_count": len(failed_attempts),
        "repetitions": repetitions,
        "failed_attempts": failed_attempts,
        "drop_total_distribution": [int(rep.get("drop_total", 0) or 0) for rep in repetitions],
        "capture_windows_distribution": [int(rep.get("capture_windows", 0) or 0) for rep in repetitions],
    }
    if drop_locations:
        row["drop_locations"] = drop_locations
        row["impact_analysis"] = "DROP events are present in one or more BRAM repetitions; this sample cannot be used as correctness-mode no-drop evidence."
    return row


def package_summary(
    p0_run_root: Path,
    safe_run_root: Path,
    safe_bram_run_root: Path | None = None,
    p0_bram_run_root: Path | None = None,
) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    for sample_id, relpath in P0_TRACE_PATHS.items():
        bram_paths = bram_repetition_paths(p0_bram_run_root, sample_id) if p0_bram_run_root is not None else []
        if bram_paths:
            samples.append(package_bram_sample(sample_id, p0_bram_run_root, sample_class="p0_safe_synthetic"))
        else:
            samples.append(package_sample(sample_id, p0_run_root / relpath, sample_class="p0_safe_synthetic"))
    for sample_id, relpath in SAFE_TRACE_PATHS.items():
        bram_paths = bram_repetition_paths(safe_bram_run_root, sample_id) if safe_bram_run_root is not None else []
        if bram_paths:
            samples.append(package_bram_sample(sample_id, safe_bram_run_root, sample_class="malware_like_synthetic_syscall_only"))
        else:
            samples.append(package_sample(sample_id, safe_run_root / relpath, sample_class="malware_like_synthetic"))

    status = "PASS" if all(row.get("status") == "PASS" and row.get("unaccounted_drop") == 0 for row in samples) else "FAIL"
    return {
        "schema": "rvmt.trace_drop_accounting.v1",
        "status": status,
        "correctness_mode": status == "PASS",
        "correctness_scope": "captured_trace_windows",
        "board": "Digilent Genesys2",
        "cpu": "CVA6 rv64gc sv39",
        "p0_run_root": repo_rel(p0_run_root),
        "p0_bram_run_root": repo_rel(p0_bram_run_root) if p0_bram_run_root is not None else None,
        "safe_surrogate_run_root": repo_rel(safe_run_root),
        "safe_surrogate_bram_run_root": repo_rel(safe_bram_run_root) if safe_bram_run_root is not None else None,
        "allowed_claims": [
            "All listed Genesys2/CVA6 captured trace windows have zero unaccounted DROP events.",
        ],
        "non_claims": [
            "Captured-window drop accounting is not a full continuous semantic-reconstruction claim for safe-surrogate workloads.",
            "This summary does not claim pointer semantic reconstruction, source-line attribution, process ownership, baseline alignment, or behavior metric completeness.",
        ],
        "samples": samples,
    }


def run_self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        p0 = root / "p0"
        safe = root / "safe"
        for relpath in P0_TRACE_PATHS.values():
            path = p0 / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"evt":"MARKER","packed_primary":"0xb0000a01"}\n{"evt":"SYSCALL_ENTRY"}\n{"evt":"MARKER","packed_primary":"0xe0000a01"}\n', encoding="utf-8")
        for relpath in SAFE_TRACE_PATHS.values():
            path = safe / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"evt":"SYSCALL_ENTRY","capture_id":"openat_entry"}\n{"evt":"SYSCALL_RET","capture_id":"openat_entry"}\n', encoding="utf-8")
        summary = package_summary(p0, safe)
    if summary.get("status") != "PASS":
        print("[FAIL] expected fixture summary to pass", file=sys.stderr)
        return 1
    if len(summary.get("samples", [])) != 12:
        print("[FAIL] expected 12 sample rows", file=sys.stderr)
        return 1
    print("[PASS] trace drop accounting packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package Genesys2/CVA6 trace DROP accounting from current P0 and safe-surrogate traces.")
    parser.add_argument("--p0-run-root", type=Path, default=DEFAULT_P0_RUN_ROOT)
    parser.add_argument("--p0-bram-run-root", type=Path, default=DEFAULT_P0_BRAM_RUN_ROOT)
    parser.add_argument("--safe-run-root", type=Path, default=DEFAULT_SAFE_RUN_ROOT)
    parser.add_argument("--safe-bram-run-root", type=Path, default=DEFAULT_SAFE_BRAM_RUN_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()
    try:
        summary = package_summary(args.p0_run_root, args.safe_run_root, args.safe_bram_run_root, args.p0_bram_run_root)
        write_json(args.out, summary)
    except Exception as exc:
        print(f"package_trace_drop_accounting_summary: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote trace drop accounting summary to {args.out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
