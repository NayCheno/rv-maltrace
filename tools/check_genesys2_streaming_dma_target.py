from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import package_genesys2_streaming_dma_target as packager


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/streaming_dma_target_summary.json")
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
EXPECTED_SCHEMA = "rvmt.genesys2.streaming_dma_target.v1"
EXPECTED_ROW_SAMPLE_CLASSES = {
    "p0_bram_repetitions": "p0_safe_synthetic",
    "safe_surrogate_bram_repetitions": "malware_like_synthetic_syscall_only",
}


def repo_path(root: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def row_map(rows: list[Any], key: str = "id") -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get(key), str) and row.get(key):
            result[str(row[key])] = row
    return result


def check_summary(data: dict[str, Any], root: Path, current_root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == EXPECTED_SCHEMA, "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(
        errors,
        data.get("evidence_scope") == "cycle_normalized_target_only_for_future_production_streaming_dma_experiment",
        "evidence scope mismatch",
    )

    expected = packager.package_summary(root, current_root)
    require(errors, expected.get("status") == "PASS", "recomputed streaming/DMA target must pass")
    for key in ("trace_record_width", "cohorts", "workload_repetition_rows", "aggregate", "throughput_target"):
        require(errors, data.get(key) == expected.get(key), f"{key} does not match source summaries")

    width = as_dict(data.get("trace_record_width"))
    require(errors, width.get("bits") == 136, "trace record width must be 136 bits")
    require(errors, width.get("bytes") == 17, "trace record width must be 17 bytes")
    width_source = width.get("source")
    require(errors, bool(width_source), "trace record width source missing")
    if width_source:
        require(errors, repo_path(root, width_source).is_file(), f"trace record width source missing: {width_source}")

    aggregate = as_dict(data.get("aggregate"))
    require(errors, aggregate.get("board_sample_count") == 12, "expected 12 board samples")
    require(errors, aggregate.get("accepted_repetition_count") == 120, "expected 120 accepted repetitions")
    require(errors, aggregate.get("p0_accepted_repetition_count") == 40, "expected 40 P0 accepted repetitions")
    require(errors, aggregate.get("safe_surrogate_accepted_repetition_count") == 80, "expected 80 safe-surrogate accepted repetitions")
    require(errors, aggregate.get("max_unaccounted_drop") == 0, "accepted repetitions must have zero unaccounted DROP")
    require(errors, aggregate.get("max_bram_dropped_count") == 0, "accepted repetitions must have zero BRAM dropped count")
    require(errors, aggregate.get("max_bram_wrap_count") == 0, "accepted repetitions must have zero BRAM wrap")
    rates = as_dict(aggregate.get("event_bytes_per_cycle"))
    require(errors, float(rates.get("p95") or 0.0) > 0.0, "p95 event bytes/cycle must be positive")
    require(errors, float(rates.get("max") or 0.0) >= float(rates.get("p95") or 0.0), "max bytes/cycle must be >= p95")

    cohorts = row_map(as_list(data.get("cohorts")))
    require(errors, set(cohorts) == {"p0_bram_repetitions", "safe_surrogate_bram_repetitions"}, "cohort ids mismatch")
    if "p0_bram_repetitions" in cohorts:
        require(errors, cohorts["p0_bram_repetitions"].get("accepted_repetition_count") == 40, "P0 cohort count mismatch")
    if "safe_surrogate_bram_repetitions" in cohorts:
        require(errors, cohorts["safe_surrogate_bram_repetitions"].get("accepted_repetition_count") == 80, "safe cohort count mismatch")

    rows = as_list(data.get("workload_repetition_rows"))
    require(errors, len(rows) == 120, "expected 120 repetition rows")
    for row in rows:
        if not isinstance(row, dict):
            errors.append("repetition rows must be objects")
            continue
        label = f"{row.get('sample_id')}/{row.get('repetition')}"
        events = int(row.get("captured_event_count") or 0)
        bytes_ = int(row.get("trace_bytes") or 0)
        cycles = int(row.get("marker_window_cycles") or 0)
        require(errors, row.get("parse_success") is True, f"{label}: parse_success must be true")
        require(errors, row.get("trace_sink_mode") == "bram_ring", f"{label}: source trace sink must be bram_ring")
        expected_class = EXPECTED_ROW_SAMPLE_CLASSES.get(str(row.get("cohort_id") or ""))
        require(errors, bool(row.get("sample_class")), f"{label}: sample_class must be explicit")
        if expected_class:
            require(errors, row.get("sample_class") == expected_class, f"{label}: sample_class/cohort mismatch")
        require(errors, int(row.get("trace_record_width_bytes") or 0) == 17, f"{label}: record width mismatch")
        require(errors, bytes_ == events * 17, f"{label}: trace byte calculation mismatch")
        require(errors, cycles > 0, f"{label}: marker window cycles must be positive")
        require(errors, float(row.get("event_bytes_per_cycle") or 0.0) > 0.0, f"{label}: bytes/cycle must be positive")
        require(errors, int(row.get("unaccounted_drop") or 0) == 0, f"{label}: unaccounted DROP must be zero")
        require(errors, int(row.get("bram_dropped_count") or 0) == 0, f"{label}: BRAM dropped count must be zero")
        require(errors, int(row.get("bram_wrap_count") or 0) == 0, f"{label}: BRAM wrap count must be zero")
        require(errors, row.get("bram_full") is False, f"{label}: BRAM full flag must be false")

    target = as_dict(data.get("throughput_target"))
    require(errors, target.get("metric") == "compact_trace_event_bytes_per_marker_window_cycle", "throughput target metric mismatch")
    require(errors, target.get("p95_event_bytes_per_cycle") == rates.get("p95"), "target p95 must match aggregate p95")
    require(errors, target.get("max_observed_event_bytes_per_cycle") == rates.get("max"), "target max must match aggregate max")
    require(errors, target.get("record_width_bits") == 136, "target record width bits mismatch")
    require(errors, target.get("record_width_bytes") == 17, "target record width bytes mismatch")
    require(errors, target.get("external_summary_path") == packager.EXTERNAL_SUMMARY_PATH, "external summary path mismatch")
    require(errors, target.get("required_external_summary_schema") == "rvmt.genesys2.streaming_dma_throughput.v1", "external schema mismatch")
    require(
        errors,
        target.get("p95_event_bytes_per_second") == packager.BYTES_PER_SECOND_REQUIRES_CLOCK,
        "bytes/sec must remain deferred without exact external clock",
    )
    require(errors, target.get("clock_hz_required_for_bytes_per_second") is True, "clock requirement missing")
    require(errors, "exact streaming bitstream clock" in str(target.get("future_acceptance_rule") or ""), "future acceptance rule missing exact clock requirement")

    source_rows = row_map(as_list(data.get("source_summaries")))
    require(errors, {"p0_bram_trace", "safe_surrogate_bram_trace", "external_closure_plan"} <= set(source_rows), "source summaries missing")
    for source_id, row in source_rows.items():
        path_value = row.get("path")
        require(errors, bool(path_value), f"{source_id}: source path missing")
        if path_value:
            path = repo_path(root, path_value)
            require(errors, path.is_file(), f"{source_id}: source file missing: {path_value}")
            if path.is_file():
                source = load_json(path)
                require(errors, source.get("schema") == row.get("schema"), f"{source_id}: source schema mismatch")
                require(errors, source.get("status") == row.get("status"), f"{source_id}: source status mismatch")
        require(errors, "uv run python" in str(row.get("checker_command") or ""), f"{source_id}: checker command missing")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("streaming_dma_target_baseline_claimed") is True, "target baseline claim missing")
    require(errors, boundary.get("production_streaming_dma_throughput_claimed") is False, "production streaming/DMA throughput must not be claimed")
    require(errors, boundary.get("external_streaming_dma_experiment_completed") is False, "external streaming/DMA experiment must not be marked complete")
    require(errors, boundary.get("bram_jtag_substituted_for_streaming") is False, "BRAM/JTAG must not be substituted")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not production streaming/dma throughput evidence" in non_claims, "production streaming non-claim missing")
    require(errors, "not substitutes for a non-bram production transport" in non_claims, "BRAM/JTAG substitution non-claim missing")
    require(errors, "does not prove host receiver losslessness" in non_claims, "host receiver non-claim missing")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_streaming_dma_target.py" in commands, "packager validation command missing")
    require(errors, "tools/check_genesys2_streaming_dma_target.py --root ." in commands, "checker validation command missing")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        source = root / packager.TRACE_WIDTH_SOURCE
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('DEFAULT_VIVADO_PROPERTIES = {"C_PROBE1_WIDTH": "136"}\n', encoding="utf-8")
        packager.write_json(
            current / "p0_bram_trace_summary.json",
            packager.fixture_board_summary(4, "p0", sample_class="p0_safe_synthetic"),
        )
        packager.write_json(
            current / "safe_surrogate_bram_trace_summary.json",
            packager.fixture_board_summary(8, "safe", sample_class="malware_like_synthetic_syscall_only"),
        )
        packager.write_json(current / "external_closure_plan.json", {"schema": "fixture", "status": "PASS"})
        summary = packager.package_summary(root, current)
        errors = check_summary(summary, root, current)
        if errors:
            print("[FAIL] streaming/DMA target good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["production_streaming_dma_throughput_claimed"] = True
        errors = check_summary(summary, root, current)
        if not any("production streaming" in error for error in errors):
            print("[FAIL] streaming/DMA target overclaim fixture passed", file=sys.stderr)
            return 1
        summary = packager.package_summary(root, current)
        summary["throughput_target"]["p95_event_bytes_per_second"] = 123.0
        errors = check_summary(summary, root, current)
        if not any("bytes/sec" in error for error in errors):
            print("[FAIL] streaming/DMA target clock fixture passed", file=sys.stderr)
            return 1
        summary = packager.package_summary(root, current)
        summary["workload_repetition_rows"][40]["sample_class"] = None
        errors = check_summary(summary, root, current)
        if not any("sample_class" in error for error in errors):
            print("[FAIL] streaming/DMA target missing sample_class fixture passed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 streaming/DMA target checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the current Genesys2/CVA6 streaming/DMA throughput target baseline.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    current_root = args.current_root if args.current_root.is_absolute() else root / args.current_root
    if not path.is_file():
        print(f"[FAIL] missing streaming/DMA target summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root, current_root)
    except Exception as exc:
        print(f"[FAIL] streaming/DMA target checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] streaming/DMA target summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] streaming/DMA target summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
