from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_jsonl,
    repo_rel_from,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_P0_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260611-p0-continuous-136bit")
DEFAULT_SAFE_RUN_ROOT = Path("results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610")
DEFAULT_SAFE_BRAM_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260612-pointer-snapshot-bram")
DEFAULT_OUT = Path("results/evaluation/genesys2-cva6/current/pointer_snapshot_guardrails.json")
USER_POINTER_MAX = 0x0000_4000_0000_0000
MULTIPLE_REPETITION_TRACES = "MULTIPLE_REPETITION_TRACES_SEE_TRACES"

PRIORITY_SYSCALLS = [
    "openat",
    "read",
    "write",
    "close",
    "execve",
    "clone",
    "wait4",
    "waitid",
    "mmap",
    "mprotect",
    "ptrace",
    "clock_gettime",
    "getdents64",
]
HARDWARE_SNAPSHOT_SYSCALLS = ["openat", "execve", "write"]
SYSCALL_NR_NAMES = {
    56: "openat",
    64: "write",
    221: "execve",
}

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


repo_rel = repo_rel_from(ROOT)


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


def is_arg_mem_event(event: dict[str, Any]) -> bool:
    evt = str(event.get("evt") or "").upper()
    evt_code = parse_int(event.get("evt_code"))
    return evt in {"ARG_MEM", "EVT_ARG_MEM", "POINTER_SNAPSHOT"} or evt_code == 10


def snapshot_bytes(event: dict[str, Any]) -> int:
    for key in ("snapshot_bytes", "byte_count", "length", "size"):
        parsed = parse_int(event.get(key))
        if parsed is not None:
            return max(parsed, 0)
    return 0


def event_syscall_name(event: dict[str, Any]) -> str | None:
    for key in ("associated_syscall_name", "syscall_name", "syscall"):
        value = event.get(key)
        if isinstance(value, str) and value:
            return value
    syscall_nr = parse_int(event.get("associated_syscall_nr")) or parse_int(event.get("syscall_nr")) or parse_int(event.get("syscall_id"))
    if syscall_nr is None:
        return None
    return SYSCALL_NR_NAMES.get(syscall_nr)


def is_user_pointer_addr(event: dict[str, Any]) -> bool:
    mem_addr = parse_int(event.get("mem_addr"))
    if mem_addr is None:
        return True
    return 0 <= mem_addr < USER_POINTER_MAX


def enrich_arg_mem_syscall_context(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    active: dict[int, tuple[int | None, str | None]] = {}
    latest: tuple[int | None, int | None, str | None] = (None, None, None)
    for event in events:
        row = dict(event)
        evt = str(row.get("evt") or "").upper()
        if evt == "SYSCALL_ENTRY":
            syscall_id = parse_int(row.get("packed_aux") or row.get("syscall_id"))
            syscall_nr = parse_int(row.get("packed_primary") or row.get("syscall_nr") or row.get("a7"))
            syscall_name = SYSCALL_NR_NAMES.get(syscall_nr) if syscall_nr is not None else None
            if syscall_id is not None:
                active[syscall_id] = (syscall_nr, syscall_name)
            latest = (syscall_id, syscall_nr, syscall_name)
        elif is_arg_mem_event(row):
            syscall_id, syscall_nr, syscall_name = latest
            if syscall_id is not None:
                row.setdefault("associated_syscall_id", f"0x{syscall_id:08x}")
            if syscall_nr is not None:
                row.setdefault("associated_syscall_nr", syscall_nr)
            if syscall_name is not None:
                row.setdefault("associated_syscall_name", syscall_name)
        elif evt == "SYSCALL_RET":
            syscall_id = parse_int(row.get("packed_primary") or row.get("syscall_id"))
            if syscall_id is not None:
                active.pop(syscall_id, None)
                if latest[0] == syscall_id:
                    if active:
                        last_id = next(reversed(active))
                        syscall_nr, syscall_name = active[last_id]
                        latest = (last_id, syscall_nr, syscall_name)
                    else:
                        latest = (None, None, None)
        enriched.append(row)
    return enriched


def summarize_sample_events(
    sample_id: str,
    *,
    sample_class: str,
    traces: list[str],
    events: list[dict[str, Any]],
    max_bytes_per_pointer: int,
    missing_trace: bool = False,
    repetition_count: int | None = None,
    repetitions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    snapshots = [event for event in events if is_arg_mem_event(event)]
    total_bytes = sum(snapshot_bytes(event) for event in snapshots)
    byte_budget = max_bytes_per_pointer * max(len(snapshots), 1)
    kernel_address_count = sum(1 for event in snapshots if not is_user_pointer_addr(event))
    sources = sorted({str(event.get("snapshot_source") or "unknown") for event in snapshots})
    syscall_names = sorted({name for event in snapshots if (name := event_syscall_name(event))})
    hardware_syscall_names = sorted(
        {
            name
            for event in snapshots
            if str(event.get("snapshot_source") or "").startswith("hardware_") and (name := event_syscall_name(event))
        }
    )
    row: dict[str, Any] = {
        "sample_id": sample_id,
        "sample_class": sample_class,
        "trace": traces[0] if len(traces) == 1 else MULTIPLE_REPETITION_TRACES,
        "traces": traces,
        "guardrails_pass": (not missing_trace) and total_bytes <= byte_budget and kernel_address_count == 0,
        "snapshot_mode": "disabled" if not snapshots else "bounded_prefix",
        "snapshot_count": len(snapshots),
        "snapshot_bytes": total_bytes,
        "snapshot_sources": sources,
        "snapshot_syscalls": syscall_names,
        "hardware_snapshot_syscalls": hardware_syscall_names,
        "hardware_snapshot_syscall_coverage": {
            name: name in hardware_syscall_names for name in HARDWARE_SNAPSHOT_SYSCALLS
        },
        "hardware_user_pointer_snapshot": any(source.startswith("hardware_") for source in sources),
        "hardware_derived_pointer_strings": False,
        "hardware_pointer_strings_claimed": False,
        "companion_derived_strings_as_hardware": False,
        "kernel_address_snapshot_count": kernel_address_count,
        "max_bytes_per_pointer": max_bytes_per_pointer,
        "raw_payload_release": "none" if not snapshots else "local_only_or_sanitized_summary",
        "missing_trace": missing_trace,
    }
    if repetition_count is not None:
        row["repetition_count"] = repetition_count
    if repetitions is not None:
        row["repetitions"] = repetitions
    return row


def package_sample(sample_id: str, trace_path: Path, *, sample_class: str, max_bytes_per_pointer: int) -> dict[str, Any]:
    if not trace_path.is_file():
        return summarize_sample_events(
            sample_id,
            sample_class=sample_class,
            traces=[repo_rel(trace_path)],
            events=[],
            max_bytes_per_pointer=max_bytes_per_pointer,
            missing_trace=True,
        )
    events = enrich_arg_mem_syscall_context(load_jsonl(trace_path))
    return summarize_sample_events(
        sample_id,
        sample_class=sample_class,
        traces=[repo_rel(trace_path)],
        events=events,
        max_bytes_per_pointer=max_bytes_per_pointer,
    )


def rep_sort_key(path: Path) -> tuple[int, str]:
    name = path.parent.name if path.name == "bram_records.jsonl" else path.name
    try:
        return (int(name.split("_", 1)[1]), name)
    except (IndexError, ValueError):
        return (10**9, name)


def bram_repetition_paths(safe_bram_run_root: Path, sample_id: str) -> list[Path]:
    sample_root = safe_bram_run_root / sample_id
    if not sample_root.is_dir():
        return []
    paths = [path for path in sample_root.glob("rep_*/bram_records.jsonl") if path.is_file()]
    return sorted(paths, key=rep_sort_key)


def package_bram_sample(sample_id: str, safe_bram_run_root: Path, *, max_bytes_per_pointer: int) -> dict[str, Any] | None:
    paths = bram_repetition_paths(safe_bram_run_root, sample_id)
    if not paths:
        return None
    events: list[dict[str, Any]] = []
    repetitions: list[dict[str, Any]] = []
    for path in paths:
        rep_events = enrich_arg_mem_syscall_context(load_jsonl(path))
        events.extend(rep_events)
        snapshots = [event for event in rep_events if is_arg_mem_event(event)]
        repetitions.append(
            {
                "rep": path.parent.name,
                "trace": repo_rel(path),
                "snapshot_count": len(snapshots),
                "snapshot_bytes": sum(snapshot_bytes(event) for event in snapshots),
                "snapshot_sources": sorted({str(event.get("snapshot_source") or "unknown") for event in snapshots}),
                "snapshot_syscalls": sorted({name for event in snapshots if (name := event_syscall_name(event))}),
                "hardware_snapshot_syscalls": sorted(
                    {
                        name
                        for event in snapshots
                        if str(event.get("snapshot_source") or "").startswith("hardware_") and (name := event_syscall_name(event))
                    }
                ),
            }
        )
    return summarize_sample_events(
        sample_id,
        sample_class="malware_like_synthetic",
        traces=[repo_rel(path) for path in paths],
        events=events,
        max_bytes_per_pointer=max_bytes_per_pointer,
        repetition_count=len(paths),
        repetitions=repetitions,
    )


def package_summary(
    p0_run_root: Path,
    safe_run_root: Path,
    safe_bram_run_root: Path,
    *,
    max_bytes_per_pointer: int,
) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    for sample_id, relpath in P0_TRACE_PATHS.items():
        samples.append(
            package_sample(sample_id, p0_run_root / relpath, sample_class="p0_safe_synthetic", max_bytes_per_pointer=max_bytes_per_pointer)
        )
    for sample_id, relpath in SAFE_TRACE_PATHS.items():
        bram_sample = package_bram_sample(sample_id, safe_bram_run_root, max_bytes_per_pointer=max_bytes_per_pointer)
        samples.append(bram_sample if bram_sample is not None else package_sample(sample_id, safe_run_root / relpath, sample_class="malware_like_synthetic", max_bytes_per_pointer=max_bytes_per_pointer))
    snapshot_count = sum(int(row.get("snapshot_count", 0)) for row in samples)
    snapshot_sources = sorted(
        {
            str(source)
            for row in samples
            for source in row.get("snapshot_sources", [])
            if source
        }
    )
    hardware_snapshot_syscalls = sorted(
        {
            str(name)
            for row in samples
            for name in row.get("hardware_snapshot_syscalls", [])
            if name
        }
    )
    status = "PASS" if all(row.get("guardrails_pass") is True for row in samples) else "FAIL"
    return {
        "schema": "rvmt.pointer_snapshot_guardrails.v1",
        "status": status,
        "snapshot_mode": "disabled" if snapshot_count == 0 else "bounded_prefix",
        "snapshot_count": snapshot_count,
        "snapshot_bytes": sum(int(row.get("snapshot_bytes", 0)) for row in samples),
        "snapshot_sources": snapshot_sources,
        "hardware_snapshot_syscalls": hardware_snapshot_syscalls,
        "hardware_snapshot_syscall_coverage": {
            name: name in hardware_snapshot_syscalls for name in HARDWARE_SNAPSHOT_SYSCALLS
        },
        "hardware_user_pointer_snapshot": any(source.startswith("hardware_") for source in snapshot_sources),
        "hardware_derived_pointer_strings": False,
        "hardware_pointer_strings_claimed": False,
        "companion_derived_strings_as_hardware": False,
        "board": "Digilent Genesys2",
        "cpu": "CVA6 rv64gc sv39",
        "p0_run_root": repo_rel(p0_run_root),
        "safe_surrogate_run_root": repo_rel(safe_run_root),
        "safe_surrogate_bram_run_root": repo_rel(safe_bram_run_root),
        "policy": {
            "full_memory_dump": False,
            "captures_kernel_memory": False,
            "network_default": "disabled",
            "max_bytes_per_pointer": max_bytes_per_pointer,
            "allowed_syscalls": PRIORITY_SYSCALLS,
            "hardware_snapshot_syscalls": HARDWARE_SNAPSHOT_SYSCALLS,
            "redaction_policy": "raw pointer payloads are either absent or retained only in local BRAM/ILA artifacts; published summaries expose bounded byte counts and sanitized metadata",
            "bounds_checking": "bounded-prefix mode clips to configured byte limits, rejects kernel-range addresses, and records DROP instead of backpressuring the core",
        },
        "allowed_claims": (
            [
                "Current Genesys2/CVA6 traces satisfy pointer snapshot guardrails in disabled mode: no full memory dump, no kernel memory capture, no default raw pointer payload release.",
            ]
            if snapshot_count == 0
            else [
                "Current Genesys2/CVA6 traces satisfy bounded-prefix pointer snapshot guardrails for captured ARG_MEM records: no full memory dump, no kernel memory capture, and no default raw pointer payload release.",
            ]
        ),
        "non_claims": [
            "This guardrail artifact verifies bounds, address class, and artifact-release policy; semantic reconstruction accuracy is reported by the semantic reconstruction summary.",
            "BRAM/ILA compact ARG_MEM payloads expose only bounded 32-bit address/data prefixes in the current board evidence format.",
            "Trusted companion strings are not reported as hardware-derived pointer strings.",
            "This artifact does not claim fd/path graph, source-line attribution, process ownership, or baseline metric completion.",
        ],
        "samples": samples,
    }


def run_self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        p0 = root / "p0"
        safe = root / "safe"
        bram = root / "bram"
        for relpath in P0_TRACE_PATHS.values():
            path = p0 / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"evt":"SYSCALL_ENTRY"}\n', encoding="utf-8")
        for relpath in SAFE_TRACE_PATHS.values():
            path = safe / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"evt":"SYSCALL_ENTRY","capture_id":"openat_entry"}\n', encoding="utf-8")
        summary = package_summary(p0, safe, bram, max_bytes_per_pointer=256)
    if summary.get("status") != "PASS" or summary.get("snapshot_mode") != "disabled":
        print("[FAIL] expected disabled-mode fixture summary to pass", file=sys.stderr)
        return 1
    if len(summary.get("samples", [])) != 12:
        print("[FAIL] expected 12 sample rows", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        p0 = root / "p0"
        safe = root / "safe"
        bram = root / "bram"
        for relpath in P0_TRACE_PATHS.values():
            path = p0 / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"evt":"SYSCALL_ENTRY"}\n', encoding="utf-8")
        for sample_id, relpath in SAFE_TRACE_PATHS.items():
            path = safe / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"evt":"SYSCALL_ENTRY"}\n', encoding="utf-8")
            rep = bram / sample_id / "rep_01" / "bram_records.jsonl"
            rep.parent.mkdir(parents=True, exist_ok=True)
            if sample_id == "file_scan":
                rep.write_text(
                    '{"evt":"ARG_MEM","snapshot_bytes":4,"snapshot_source":"hardware_bram_ring_compact","mem_addr":"0x0000000080002000","mem_data":"0x00000000706d742f","syscall_id":"0x38"}\n',
                    encoding="utf-8",
                )
            else:
                rep.write_text('{"evt":"SYSCALL_ENTRY"}\n', encoding="utf-8")
        bounded = package_summary(p0, safe, bram, max_bytes_per_pointer=64)
    if bounded.get("status") != "PASS" or bounded.get("snapshot_mode") != "bounded_prefix":
        print("[FAIL] expected bounded-prefix fixture summary to pass", file=sys.stderr)
        return 1
    if bounded.get("hardware_user_pointer_snapshot") is not True:
        print("[FAIL] expected hardware snapshot source flag", file=sys.stderr)
        return 1
    print("[PASS] pointer snapshot guardrails packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package current Genesys2/CVA6 pointer snapshot guardrails evidence.")
    parser.add_argument("--p0-run-root", type=Path, default=DEFAULT_P0_RUN_ROOT)
    parser.add_argument("--safe-run-root", type=Path, default=DEFAULT_SAFE_RUN_ROOT)
    parser.add_argument("--safe-bram-run-root", type=Path, default=DEFAULT_SAFE_BRAM_RUN_ROOT)
    parser.add_argument("--max-bytes-per-pointer", type=int, default=256)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()
    try:
        summary = package_summary(args.p0_run_root, args.safe_run_root, args.safe_bram_run_root, max_bytes_per_pointer=args.max_bytes_per_pointer)
        write_json(args.out, summary)
    except Exception as exc:
        print(f"package_pointer_snapshot_guardrails: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote pointer snapshot guardrails to {args.out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
