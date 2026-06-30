from __future__ import annotations

import argparse
import math
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    repo_path,
    require,
    sha256_file,
    write_json,
)


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/streaming_dma_readiness_summary.json")
EXPECTED_SOURCE_IDS = {
    "streaming_dma_target",
    "trace_export_decision",
    "trace_format",
    "signal_map",
    "trace_sink_summary",
    "drop_accounting_summary",
    "p0_bram_trace",
    "safe_surrogate_bram_trace",
    "production_runtime_benchmark",
}
EXPECTED_TRANSPORTS = {"axi_dma", "ethernet_streaming", "pcie_dma", "uart_streaming_dma"}
DISALLOWED_TRANSPORTS = {"bram_ring", "ila_jtag_dump", "local_runtime_benchmark_only"}
REQUIRED_ARTIFACT_KINDS = {
    "transport_design_manifest",
    "streaming_bitstream_clock_report",
    "host_receiver_log",
    "parser_output_log",
    "drop_accounting_report",
    "timing_report",
    "resource_report",
    "noninterference_report",
}
REQUIRED_SUMMARY_FIELDS = {
    "evidence_artifacts",
    "transport",
    "sustained_bytes_per_second",
    "p95_event_bytes_per_second",
    "p99_event_bytes_per_second",
    "required_sustained_bytes_per_second",
    "minimum_sustained_throughput_multiplier",
    "trace_clock_hz",
    "unaccounted_drop",
    "timing_passed",
    "noninterference_passed",
    "resource_delta",
    "host_receiver",
    "accepted_runs",
    "failed_attempts",
}
HOST_RECEIVER_FIELDS = {
    "bytes_received",
    "events_received",
    "elapsed_seconds",
    "parser_success",
    "parse_error_count",
    "sequence_gap_count",
    "dropped_event_count",
    "backpressure_count",
}


def as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def row_map(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def check_evidence_row(errors: list[str], root: Path, row: dict[str, Any], context: str) -> None:
    path_value = row.get("path")
    require(errors, bool(path_value), f"{context}: path missing")
    require(errors, row.get("exists") is True, f"{context}: exists must be true")
    require(errors, bool(row.get("sha256")), f"{context}: sha256 missing")
    if not path_value:
        return
    path = repo_path(root, path_value)
    require(errors, path.is_file(), f"{context}: file missing: {path_value}")
    if path.is_file():
        require(errors, row.get("sha256") == sha256_file(path), f"{context}: sha256 mismatch")
        if path.suffix == ".json":
            data = load_json(path)
            require(errors, row.get("schema") == data.get("schema"), f"{context}: schema mismatch")
            require(errors, row.get("status") == data.get("status"), f"{context}: status mismatch")


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.streaming_dma_readiness.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(errors, "non-BRAM production streaming/DMA" in str(data.get("scope") or ""), "scope must identify non-BRAM streaming/DMA readiness")

    sources = row_map(as_list(data.get("source_evidence")))
    missing_sources = sorted(EXPECTED_SOURCE_IDS - set(sources))
    require(errors, not missing_sources, f"missing source evidence ids: {', '.join(missing_sources)}")
    for source_id, row in sources.items():
        check_evidence_row(errors, root, row, f"source_evidence.{source_id}")
    target_source = sources.get("streaming_dma_target")
    require(errors, as_dict(target_source).get("schema") == "rvmt.genesys2.streaming_dma_target.v1", "streaming target source schema mismatch")
    require(errors, as_dict(target_source).get("status") == "PASS", "streaming target source status must be PASS")

    baseline = as_dict(data.get("target_baseline"))
    require(errors, baseline.get("metric") == "compact_trace_event_bytes_per_marker_window_cycle", "baseline metric mismatch")
    require(errors, as_float(baseline.get("p50_event_bytes_per_cycle")) > 0.0, "p50 event bytes/cycle must be positive")
    require(errors, as_float(baseline.get("p95_event_bytes_per_cycle")) > 0.0, "p95 event bytes/cycle must be positive")
    require(errors, as_float(baseline.get("p99_event_bytes_per_cycle")) > 0.0, "p99 event bytes/cycle must be positive")
    require(
        errors,
        as_float(baseline.get("p50_event_bytes_per_cycle"))
        <= as_float(baseline.get("p95_event_bytes_per_cycle"))
        <= as_float(baseline.get("p99_event_bytes_per_cycle"))
        <= as_float(baseline.get("max_observed_event_bytes_per_cycle")),
        "target percentiles must satisfy p50 <= p95 <= p99 <= max",
    )
    require(errors, baseline.get("minimum_sustained_throughput_multiplier") == 1.5, "target multiplier must be 1.5")
    require(
        errors,
        math.isclose(
            as_float(baseline.get("required_sustained_event_bytes_per_cycle")),
            as_float(baseline.get("p99_event_bytes_per_cycle")) * 1.5,
            rel_tol=1e-12,
            abs_tol=0.0,
        ),
        "required sustained bytes/cycle must be 1.5x p99",
    )
    require(errors, as_int(baseline.get("record_width_bits")) == 136, "record width bits must be 136")
    require(errors, as_int(baseline.get("record_width_bytes")) == 17, "record width bytes must be 17")
    require(errors, as_int(baseline.get("accepted_repetition_count")) >= 120, "baseline accepted repetition count must be at least 120")
    require(errors, as_int(baseline.get("board_sample_count")) == 12, "baseline board sample count must be 12")
    require(
        errors,
        baseline.get("external_summary_path") == "results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json",
        "external summary path mismatch",
    )
    require(errors, baseline.get("required_external_summary_schema") == "rvmt.genesys2.streaming_dma_throughput.v1", "external summary schema mismatch")
    require(errors, baseline.get("exact_clock_hz_required") is True, "exact clock requirement missing")
    formula = str(baseline.get("bytes_per_second_formula") or "")
    require(errors, "exact_streaming_bitstream_trace_clock_hz" in formula, "bytes/sec formula must require exact streaming clock")
    require(errors, "1.5 * p99_event_bytes_per_cycle" in formula, "bytes/sec formula must require p99 1.5x target")

    contract = as_dict(data.get("future_transport_contract"))
    require(errors, set(as_list(contract.get("allowed_transport_kinds"))) == EXPECTED_TRANSPORTS, "allowed transport kinds mismatch")
    require(errors, set(as_list(contract.get("disallowed_transport_kinds"))) >= DISALLOWED_TRANSPORTS, "disallowed transport kinds incomplete")
    requirements = as_dict(contract.get("minimum_requirements"))
    for key in (
        "transport_must_be_non_bram",
        "sustained_bytes_per_second_must_exceed_target",
        "exact_streaming_bitstream_clock_hz_required",
        "unaccounted_drop_must_be_zero",
        "parser_success_required",
        "timing_passed_required",
        "noninterference_passed_required",
        "resource_delta_report_required",
        "failed_attempt_retention_required",
    ):
        require(errors, requirements.get(key) is True, f"minimum requirement missing: {key}")
    require(errors, set(as_list(contract.get("required_evidence_artifact_kinds"))) >= REQUIRED_ARTIFACT_KINDS, "required evidence artifact kinds incomplete")
    require(errors, set(as_list(contract.get("required_summary_fields"))) >= REQUIRED_SUMMARY_FIELDS, "required summary fields incomplete")
    require(errors, set(as_list(contract.get("host_receiver_log_required_fields"))) >= HOST_RECEIVER_FIELDS, "host receiver fields incomplete")
    criteria_text = " ".join(str(item).lower() for item in as_list(contract.get("acceptance_criteria")))
    for needle in ("non-bram", "sustained_bytes_per_second", "1.5 * p99_event_bytes_per_cycle", "parser_success=true", "unaccounted_drop=0", "timing", "failed"):
        require(errors, needle in criteria_text, f"acceptance criteria must mention {needle}")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("streaming_dma_readiness_claimed") is True, "readiness claim boundary missing")
    require(errors, boundary.get("streaming_dma_target_baseline_available") is True, "target baseline boundary missing")
    for key in (
        "production_streaming_dma_throughput_claimed",
        "external_streaming_dma_experiment_completed",
        "bram_jtag_substituted_for_streaming",
        "host_receiver_losslessness_claimed",
        "timing_closure_for_streaming_claimed",
        "real_malware_validation_claimed",
    ):
        require(errors, boundary.get(key) is False, f"{key} must be false")
    require(errors, boundary.get("external_execution_required_for_closure") is True, "external execution requirement missing")

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "does not claim production streaming/dma throughput evidence is complete" in non_claims, "non_claims must reject production throughput completion")
    require(errors, "must not be substituted" in non_claims, "non_claims must reject BRAM/JTAG substitution")
    require(errors, "host receiver losslessness" in non_claims and "remain unclaimed" in non_claims, "non_claims must preserve host/timing boundary")
    require(errors, as_list(data.get("failures")) == [], "failures must be empty")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / "results/evaluation/genesys2-cva6/current"
        current.mkdir(parents=True)
        sources = []
        for source_id in EXPECTED_SOURCE_IDS:
            suffix = ".json" if source_id != "trace_export_decision" else ".md"
            path = current / f"{source_id}{suffix}"
            if source_id in {"trace_export_decision", "trace_format", "signal_map"}:
                path = root / f"docs/{source_id}.md"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n", encoding="utf-8")
                row = {"id": source_id, "path": path.relative_to(root).as_posix(), "exists": True, "sha256": sha256_file(path)}
            else:
                schema = "rvmt.genesys2.streaming_dma_target.v1" if source_id == "streaming_dma_target" else f"rvmt.fixture.{source_id}.v1"
                write_json(path, {"schema": schema, "status": "PASS"})
                row = {
                    "id": source_id,
                    "path": path.relative_to(root).as_posix(),
                    "exists": True,
                    "sha256": sha256_file(path),
                    "schema": schema,
                    "status": "PASS",
                }
            sources.append(row)
        summary = {
            "schema": "rvmt.genesys2.streaming_dma_readiness.v1",
            "status": "PASS",
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "scope": "readiness package for future non-BRAM production streaming/DMA trace-sink throughput evidence",
            "source_evidence": sources,
            "target_baseline": {
                "metric": "compact_trace_event_bytes_per_marker_window_cycle",
                "p50_event_bytes_per_cycle": 0.005,
                "p95_event_bytes_per_cycle": 0.01,
                "p99_event_bytes_per_cycle": 0.015,
                "minimum_sustained_throughput_multiplier": 1.5,
                "required_sustained_event_bytes_per_cycle": 0.0225,
                "max_observed_event_bytes_per_cycle": 0.02,
                "record_width_bits": 136,
                "record_width_bytes": 17,
                "accepted_repetition_count": 120,
                "board_sample_count": 12,
                "external_summary_path": "results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json",
                "required_external_summary_schema": "rvmt.genesys2.streaming_dma_throughput.v1",
                "bytes_per_second_formula": "1.5 * p99_event_bytes_per_cycle * exact_streaming_bitstream_trace_clock_hz",
                "exact_clock_hz_required": True,
            },
            "future_transport_contract": {
                "allowed_transport_kinds": sorted(EXPECTED_TRANSPORTS),
                "disallowed_transport_kinds": sorted(DISALLOWED_TRANSPORTS),
                "minimum_requirements": {
                    "transport_must_be_non_bram": True,
                    "sustained_bytes_per_second_must_exceed_target": True,
                    "exact_streaming_bitstream_clock_hz_required": True,
                    "unaccounted_drop_must_be_zero": True,
                    "parser_success_required": True,
                    "timing_passed_required": True,
                    "noninterference_passed_required": True,
                    "resource_delta_report_required": True,
                    "failed_attempt_retention_required": True,
                },
                "required_evidence_artifact_kinds": sorted(REQUIRED_ARTIFACT_KINDS),
                "required_summary_fields": sorted(REQUIRED_SUMMARY_FIELDS),
                "host_receiver_log_required_fields": sorted(HOST_RECEIVER_FIELDS),
                "acceptance_criteria": [
                    "non-BRAM transport with sustained_bytes_per_second above 1.5 * p99_event_bytes_per_cycle target, parser_success=true, unaccounted_drop=0, timing evidence, failed attempts retained",
                ],
            },
            "claim_boundary": {
                "streaming_dma_readiness_claimed": True,
                "streaming_dma_target_baseline_available": True,
                "production_streaming_dma_throughput_claimed": False,
                "external_streaming_dma_experiment_completed": False,
                "bram_jtag_substituted_for_streaming": False,
                "host_receiver_losslessness_claimed": False,
                "timing_closure_for_streaming_claimed": False,
                "real_malware_validation_claimed": False,
                "external_execution_required_for_closure": True,
            },
            "non_claims": [
                "This is a readiness package and does not claim production streaming/DMA throughput evidence is complete.",
                "BRAM evidence must not be substituted for streaming.",
                "Host receiver losslessness and timing closure remain unclaimed.",
            ],
            "failures": [],
        }
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] streaming/DMA readiness good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["production_streaming_dma_throughput_claimed"] = True
        errors = check_summary(summary, root)
        if not errors:
            print("[FAIL] streaming/DMA readiness bad fixture passed", file=sys.stderr)
            return 1
    print("[PASS] streaming/DMA readiness checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2 production streaming/DMA readiness evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing streaming/DMA readiness summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] streaming/DMA readiness checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] streaming/DMA readiness summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] streaming/DMA readiness summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
