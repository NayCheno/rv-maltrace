from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "streaming_dma_target_summary.json"
TRACE_WIDTH_SOURCE = Path("src/rv_maltrace/cli.py")
EXTERNAL_SUMMARY_PATH = "results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json"
BYTES_PER_SECOND_REQUIRES_CLOCK = "REQUIRES_EXACT_STREAMING_CLOCK_HZ"
DEFAULT_COHORT_SAMPLE_CLASSES = {
    "p0_bram_repetitions": "p0_safe_synthetic",
    "safe_surrogate_bram_repetitions": "malware_like_synthetic_syscall_only",
}


def repo_rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def integer(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return default
    return default


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * quantile))
    return ordered[index]


def numeric_stats(values: list[int | float]) -> dict[str, Any]:
    numeric = [float(value) for value in values]
    if not numeric:
        return {"min": 0.0, "median": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0, "variance": 0.0}
    median = statistics.median(numeric)
    return {
        "min": min(numeric),
        "median": median,
        "p50": median,
        "p95": percentile(numeric, 0.95),
        "p99": percentile(numeric, 0.99),
        "max": max(numeric),
        "variance": statistics.pvariance(numeric) if len(numeric) > 1 else 0.0,
    }


def trace_record_width_bits(repo_root: Path) -> int:
    source = repo_root / TRACE_WIDTH_SOURCE
    text = source.read_text(encoding="utf-8")
    match = re.search(r'"C_PROBE1_WIDTH"\s*:\s*"(?P<width>\d+)"', text)
    if not match:
        raise ValueError(f"{TRACE_WIDTH_SOURCE}: C_PROBE1_WIDTH not found")
    return int(match.group("width"))


def marker_window_cycles(rep: dict[str, Any]) -> int:
    marker = as_dict(rep.get("marker_window"))
    begin_marker = str(marker.get("begin_marker") or "").lower()
    end_marker = str(marker.get("end_marker") or "").lower()
    markers = [row for row in as_list(marker.get("markers_seen")) if isinstance(row, dict)]
    begins = [row for row in markers if str(row.get("primary") or "").lower() == begin_marker]
    ends = [row for row in markers if str(row.get("primary") or "").lower() == end_marker]
    if not begins or not ends:
        return 0
    return max(0, integer(ends[-1].get("cycle")) - integer(begins[0].get("cycle")))


def marker_window_event_count(rep: dict[str, Any]) -> int:
    marker = as_dict(rep.get("marker_window"))
    begin = integer(marker.get("begin_sequence"), -1)
    end = integer(marker.get("end_sequence"), -1)
    if begin < 0 or end < begin:
        return 0
    return end - begin + 1


def source_row(current_root: Path, artifact_id: str, filename: str, checker: str) -> dict[str, Any]:
    path = current_root / filename
    data = load_json(path)
    return {
        "id": artifact_id,
        "path": repo_rel(ROOT, path),
        "schema": data.get("schema"),
        "status": data.get("status"),
        "checker_command": checker,
    }


def repetition_rows(
    summary: dict[str, Any],
    cohort_id: str,
    record_width_bytes: int,
    default_sample_class: str | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sample in as_list(summary.get("samples")):
        if not isinstance(sample, dict):
            continue
        for rep in as_list(sample.get("repetitions")):
            if not isinstance(rep, dict):
                continue
            bram = as_dict(rep.get("bram_ring"))
            cycles = marker_window_cycles(rep)
            captured_events = integer(bram.get("event_count"))
            window_events = marker_window_event_count(rep)
            trace_bytes = captured_events * record_width_bytes
            sample_class = rep.get("sample_class") or sample.get("sample_class") or default_sample_class
            rows.append(
                {
                    "cohort_id": cohort_id,
                    "sample_id": rep.get("sample_id") or sample.get("sample_id"),
                    "sample_class": sample_class,
                    "repetition": rep.get("repetition"),
                    "trace_sink_mode": rep.get("trace_sink_mode"),
                    "parse_success": rep.get("parse_success"),
                    "captured_event_count": captured_events,
                    "marker_window_event_count": window_events,
                    "trace_record_width_bytes": record_width_bytes,
                    "trace_bytes": trace_bytes,
                    "marker_window_cycles": cycles,
                    "captured_events_per_cycle": (captured_events / cycles) if cycles else 0.0,
                    "marker_window_events_per_cycle": (window_events / cycles) if cycles else 0.0,
                    "event_bytes_per_cycle": (trace_bytes / cycles) if cycles else 0.0,
                    "unaccounted_drop": integer(rep.get("unaccounted_drop")),
                    "bram_dropped_count": integer(bram.get("dropped_count")),
                    "bram_wrap_count": integer(bram.get("wrap_count")),
                    "bram_full": bram.get("full"),
                }
            )
    return rows


def cohort_row(summary: dict[str, Any], cohort_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    cohort_rows = [row for row in rows if row.get("cohort_id") == cohort_id]
    sample_ids = sorted({str(row.get("sample_id")) for row in cohort_rows if row.get("sample_id")})
    return {
        "id": cohort_id,
        "run_root": summary.get("run_root"),
        "sample_count": len(sample_ids),
        "sample_ids": sample_ids,
        "accepted_repetition_count": len(cohort_rows),
        "trace_bytes": numeric_stats([integer(row.get("trace_bytes")) for row in cohort_rows]),
        "marker_window_cycles": numeric_stats([integer(row.get("marker_window_cycles")) for row in cohort_rows]),
        "captured_events_per_cycle": numeric_stats([float(row.get("captured_events_per_cycle") or 0.0) for row in cohort_rows]),
        "marker_window_events_per_cycle": numeric_stats([float(row.get("marker_window_events_per_cycle") or 0.0) for row in cohort_rows]),
        "event_bytes_per_cycle": numeric_stats([float(row.get("event_bytes_per_cycle") or 0.0) for row in cohort_rows]),
        "max_unaccounted_drop": max((integer(row.get("unaccounted_drop")) for row in cohort_rows), default=0),
        "max_bram_dropped_count": max((integer(row.get("bram_dropped_count")) for row in cohort_rows), default=0),
        "max_bram_wrap_count": max((integer(row.get("bram_wrap_count")) for row in cohort_rows), default=0),
    }


def package_summary(repo_root: Path, current_root: Path) -> dict[str, Any]:
    p0 = load_json(current_root / "p0_bram_trace_summary.json")
    safe = load_json(current_root / "safe_surrogate_bram_trace_summary.json")
    external_plan = load_json(current_root / "external_closure_plan.json")
    width_bits = trace_record_width_bits(repo_root)
    width_bytes = math.ceil(width_bits / 8)

    rows = [
        *repetition_rows(p0, "p0_bram_repetitions", width_bytes, DEFAULT_COHORT_SAMPLE_CLASSES["p0_bram_repetitions"]),
        *repetition_rows(
            safe,
            "safe_surrogate_bram_repetitions",
            width_bytes,
            DEFAULT_COHORT_SAMPLE_CLASSES["safe_surrogate_bram_repetitions"],
        ),
    ]
    cohorts = [
        cohort_row(p0, "p0_bram_repetitions", rows),
        cohort_row(safe, "safe_surrogate_bram_repetitions", rows),
    ]
    aggregate = {
        "source_summary_count": 2,
        "board_sample_count": sum(integer(row.get("sample_count")) for row in cohorts),
        "accepted_repetition_count": len(rows),
        "p0_accepted_repetition_count": cohorts[0]["accepted_repetition_count"],
        "safe_surrogate_accepted_repetition_count": cohorts[1]["accepted_repetition_count"],
        "trace_record_width_bits": width_bits,
        "trace_record_width_bytes": width_bytes,
        "trace_bytes": numeric_stats([integer(row.get("trace_bytes")) for row in rows]),
        "marker_window_cycles": numeric_stats([integer(row.get("marker_window_cycles")) for row in rows]),
        "captured_events_per_cycle": numeric_stats([float(row.get("captured_events_per_cycle") or 0.0) for row in rows]),
        "marker_window_events_per_cycle": numeric_stats([float(row.get("marker_window_events_per_cycle") or 0.0) for row in rows]),
        "event_bytes_per_cycle": numeric_stats([float(row.get("event_bytes_per_cycle") or 0.0) for row in rows]),
        "max_unaccounted_drop": max((integer(row.get("unaccounted_drop")) for row in rows), default=0),
        "max_bram_dropped_count": max((integer(row.get("bram_dropped_count")) for row in rows), default=0),
        "max_bram_wrap_count": max((integer(row.get("bram_wrap_count")) for row in rows), default=0),
    }
    status = "PASS"
    if p0.get("status") != "PASS" or safe.get("status") != "PASS" or external_plan.get("status") != "PASS":
        status = "FAIL"
    if aggregate["accepted_repetition_count"] < 120 or aggregate["board_sample_count"] != 12:
        status = "FAIL"
    if cohorts[0]["accepted_repetition_count"] < 40 or cohorts[1]["accepted_repetition_count"] < 80:
        status = "FAIL"
    if aggregate["trace_record_width_bits"] <= 0 or aggregate["trace_record_width_bytes"] <= 0:
        status = "FAIL"
    if aggregate["max_unaccounted_drop"] != 0 or aggregate["max_bram_dropped_count"] != 0 or aggregate["max_bram_wrap_count"] != 0:
        status = "FAIL"
    if any(integer(row.get("marker_window_cycles")) <= 0 for row in rows):
        status = "FAIL"
    if any(float(row.get("captured_events_per_cycle") or 0.0) <= 0.0 for row in rows):
        status = "FAIL"
    if any(float(row.get("marker_window_events_per_cycle") or 0.0) <= 0.0 for row in rows):
        status = "FAIL"

    p99_event_bytes_per_cycle = aggregate["event_bytes_per_cycle"]["p99"]
    required_event_bytes_per_cycle = p99_event_bytes_per_cycle * 1.5

    target = {
        "metric": "compact_trace_event_bytes_per_marker_window_cycle",
        "p50_event_bytes_per_cycle": aggregate["event_bytes_per_cycle"]["p50"],
        "p95_event_bytes_per_cycle": aggregate["event_bytes_per_cycle"]["p95"],
        "p99_event_bytes_per_cycle": p99_event_bytes_per_cycle,
        "p50_captured_events_per_cycle": aggregate["captured_events_per_cycle"]["p50"],
        "p95_captured_events_per_cycle": aggregate["captured_events_per_cycle"]["p95"],
        "p99_captured_events_per_cycle": aggregate["captured_events_per_cycle"]["p99"],
        "p50_marker_window_events_per_cycle": aggregate["marker_window_events_per_cycle"]["p50"],
        "p95_marker_window_events_per_cycle": aggregate["marker_window_events_per_cycle"]["p95"],
        "p99_marker_window_events_per_cycle": aggregate["marker_window_events_per_cycle"]["p99"],
        "max_observed_event_bytes_per_cycle": aggregate["event_bytes_per_cycle"]["max"],
        "record_width_bits": width_bits,
        "record_width_bytes": width_bytes,
        "minimum_sustained_throughput_multiplier": 1.5,
        "required_sustained_event_bytes_per_cycle": required_event_bytes_per_cycle,
        "external_summary_path": EXTERNAL_SUMMARY_PATH,
        "required_external_summary_schema": "rvmt.genesys2.streaming_dma_throughput.v1",
        "bytes_per_second_conversion": "event_bytes_per_cycle * exact trace clock Hz from the production streaming bitstream timing report",
        "p95_event_bytes_per_second": BYTES_PER_SECOND_REQUIRES_CLOCK,
        "p99_event_bytes_per_second": BYTES_PER_SECOND_REQUIRES_CLOCK,
        "required_sustained_bytes_per_second": BYTES_PER_SECOND_REQUIRES_CLOCK,
        "clock_hz_required_for_bytes_per_second": True,
        "future_acceptance_rule": "external sustained_bytes_per_second must exceed 1.5 * p99_event_bytes_per_cycle * exact trace clock Hz from the production streaming bitstream timing report",
    }

    return {
        "schema": "rvmt.genesys2.streaming_dma_target.v1",
        "status": status,
        "canonical_evaluation_root": repo_rel(repo_root, current_root),
        "evidence_scope": "cycle_normalized_target_only_for_future_production_streaming_dma_experiment",
        "source_summaries": [
            source_row(current_root, "p0_bram_trace", "p0_bram_trace_summary.json", "uv run python tools/check_genesys2_p0_bram_trace.py --root ."),
            source_row(current_root, "safe_surrogate_bram_trace", "safe_surrogate_bram_trace_summary.json", "uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root ."),
            source_row(current_root, "external_closure_plan", "external_closure_plan.json", "uv run python tools/check_genesys2_external_closure_plan.py --root ."),
        ],
        "trace_record_width": {
            "bits": width_bits,
            "bytes": width_bytes,
            "source": repo_rel(repo_root, repo_root / TRACE_WIDTH_SOURCE),
            "source_key": "C_PROBE1_WIDTH",
        },
        "cohorts": cohorts,
        "workload_repetition_rows": rows,
        "aggregate": aggregate,
        "throughput_target": target,
        "claim_boundary": {
            "streaming_dma_target_baseline_claimed": True,
            "production_streaming_dma_throughput_claimed": False,
            "external_streaming_dma_experiment_completed": False,
            "bram_jtag_substituted_for_streaming": False,
            "real_malware_validation_claimed": False,
        },
        "allowed_claims": [
            "The current controlled BRAM marker-window evidence defines cycle-normalized p50/p95/p99 event production targets for future non-BRAM streaming/DMA experiments.",
            "Future production streaming/DMA summaries must convert the p99 target to bytes/sec using the exact clock report for the streaming bitstream and exceed 1.5x that rate with sustained transport throughput.",
        ],
        "non_claims": [
            "This target summary is not production streaming/DMA throughput evidence.",
            "BRAM ring captures, ILA/JTAG dumps, and local runtime benchmarks are not substitutes for a non-BRAM production transport experiment.",
            "This summary does not prove host receiver losslessness, timing closure, resource deltas, or trace-off versus trace-on noninterference for a streaming/DMA bitstream.",
            "This summary does not add real-malware validation or randomized workload generalization.",
        ],
        "validation_commands": [
            "uv run python tools/package_genesys2_streaming_dma_target.py",
            "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
            "uv run python tools/run_check_suite.py --suite genesys2-current",
        ],
    }


def fixture_board_summary(sample_count: int, prefix: str, *, sample_class: str | None = None, drop: bool = False) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    for sample_index in range(sample_count):
        sample_id = f"{prefix}_{sample_index + 1}"
        reps: list[dict[str, Any]] = []
        for rep_index in range(10):
            events = 40 + sample_index + rep_index
            cycles = 1000 + sample_index * 100 + rep_index
            dropped = 1 if drop and sample_index == 0 and rep_index == 0 else 0
            reps.append(
                {
                    "sample_id": sample_id,
                    "sample_class": sample_class or prefix,
                    "repetition": f"rep_{rep_index + 1:02d}",
                    "trace_sink_mode": "bram_ring",
                    "parse_success": True,
                    "bram_ring": {
                        "event_count": events,
                        "dropped_count": dropped,
                        "wrap_count": 0,
                        "full": False,
                    },
                    "marker_window": {
                        "begin_marker": "0xb0000a01",
                        "end_marker": "0xe0000a01",
                        "begin_sequence": 0,
                        "end_sequence": events - 1,
                        "markers_seen": [
                            {"primary": "0xb0000a01", "cycle": 100},
                            {"primary": "0xe0000a01", "cycle": 100 + cycles},
                        ],
                    },
                    "sequence_gaps": [],
                    "unaccounted_drop": dropped,
                }
            )
        samples.append({"sample_id": sample_id, "pass_repetition_count": 10, "repetitions": reps})
    return {"schema": "fixture", "status": "PASS", "run_root": f"raw/{prefix}", "samples": samples}


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        source = root / TRACE_WIDTH_SOURCE
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('DEFAULT_VIVADO_PROPERTIES = {"C_PROBE1_WIDTH": "136"}\n', encoding="utf-8")
        write_json(
            current / "p0_bram_trace_summary.json",
            fixture_board_summary(4, "p0", sample_class="p0_safe_synthetic"),
        )
        safe_fixture = fixture_board_summary(8, "safe", sample_class="malware_like_synthetic_syscall_only")
        for sample in safe_fixture["samples"]:
            for rep in sample["repetitions"]:
                rep.pop("sample_class", None)
        write_json(current / "safe_surrogate_bram_trace_summary.json", safe_fixture)
        write_json(current / "external_closure_plan.json", {"schema": "fixture", "status": "PASS"})
        summary = package_summary(root, current)
        if summary.get("status") != "PASS":
            print("[FAIL] streaming DMA target fixture did not pass", file=sys.stderr)
            return 1
        if summary.get("aggregate", {}).get("accepted_repetition_count") < 120:
            print("[FAIL] streaming DMA target fixture repetition count mismatch", file=sys.stderr)
            return 1
        safe_classes = {
            row.get("sample_class")
            for row in summary.get("workload_repetition_rows", [])
            if row.get("cohort_id") == "safe_surrogate_bram_repetitions"
        }
        if safe_classes != {"malware_like_synthetic_syscall_only"}:
            print("[FAIL] expected streaming DMA target safe-surrogate sample class fallback", file=sys.stderr)
            return 1
        target = as_dict(summary.get("throughput_target"))
        if not target.get("p99_event_bytes_per_cycle") or target.get("p99_event_bytes_per_second") != BYTES_PER_SECOND_REQUIRES_CLOCK:
            print("[FAIL] streaming DMA target fixture throughput target mismatch", file=sys.stderr)
            return 1
        if target.get("minimum_sustained_throughput_multiplier") != 1.5:
            print("[FAIL] streaming DMA target fixture multiplier mismatch", file=sys.stderr)
            return 1
        write_json(
            current / "safe_surrogate_bram_trace_summary.json",
            fixture_board_summary(8, "safe", sample_class="malware_like_synthetic_syscall_only", drop=True),
        )
        summary = package_summary(root, current)
        if summary.get("status") != "FAIL":
            print("[FAIL] streaming DMA target bad fixture passed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 streaming/DMA target packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package the current Genesys2/CVA6 streaming/DMA throughput target baseline.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.root.resolve()
    current_root = args.current_root if args.current_root.is_absolute() else repo_root / args.current_root
    out = args.out if args.out.is_absolute() else repo_root / args.out
    try:
        summary = package_summary(repo_root, current_root)
        write_json(out, summary)
    except Exception as exc:
        print(f"package_genesys2_streaming_dma_target: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote Genesys2 streaming/DMA target summary to {out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
