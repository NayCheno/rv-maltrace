from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from package_genesys2_streaming_dma_target import BYTES_PER_SECOND_REQUIRES_CLOCK


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "streaming_dma_readiness_summary.json"
EXTERNAL_SUMMARY_PATH = "results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json"
EXPECTED_TRANSPORTS = ("axi_dma", "ethernet_streaming", "pcie_dma", "uart_streaming_dma")
DISALLOWED_TRANSPORTS = ("bram_ring", "ila_jtag_dump", "local_runtime_benchmark_only")

SOURCE_EVIDENCE = (
    ("streaming_dma_target", DEFAULT_CURRENT_ROOT / "streaming_dma_target_summary.json"),
    ("trace_export_decision", Path("docs/02-trace-architecture/trace_export_decision.md")),
    ("trace_format", Path("docs/02-trace-architecture/trace_format.md")),
    ("signal_map", Path("docs/02-trace-architecture/signal_map.md")),
    ("trace_sink_summary", DEFAULT_CURRENT_ROOT / "trace_sink_summary.json"),
    ("drop_accounting_summary", DEFAULT_CURRENT_ROOT / "drop_accounting_summary.json"),
    ("p0_bram_trace", DEFAULT_CURRENT_ROOT / "p0_bram_trace_summary.json"),
    ("safe_surrogate_bram_trace", DEFAULT_CURRENT_ROOT / "safe_surrogate_bram_trace_summary.json"),
    ("production_runtime_benchmark", DEFAULT_CURRENT_ROOT / "production_runtime_benchmark.json"),
)


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_path(path: str | Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else ROOT / value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


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


def evidence_row(artifact_id: str, path_value: str | Path) -> dict[str, Any]:
    path = repo_path(path_value)
    row: dict[str, Any] = {
        "id": artifact_id,
        "path": repo_rel(path),
        "exists": path.is_file(),
        "sha256": sha256_file(path) if path.is_file() else None,
    }
    if path.suffix == ".json" and path.is_file():
        try:
            data = load_json(path)
        except Exception as exc:
            row["json_error"] = str(exc)
        else:
            row["schema"] = data.get("schema")
            row["status"] = data.get("status")
    return row


def package_summary(current_root: Path) -> dict[str, Any]:
    target_path = current_root / "streaming_dma_target_summary.json"
    target = load_json(ROOT / target_path)
    aggregate = as_dict(target.get("aggregate"))
    throughput_target = as_dict(target.get("throughput_target"))
    boundary = as_dict(target.get("claim_boundary"))
    source_rows = [evidence_row(artifact_id, path) for artifact_id, path in SOURCE_EVIDENCE]
    failures: list[str] = []
    if target.get("status") != "PASS":
        failures.append("streaming_dma_target_summary status is not PASS")
    if target.get("schema") != "rvmt.genesys2.streaming_dma_target.v1":
        failures.append("streaming_dma_target_summary schema mismatch")
    if as_int(aggregate.get("accepted_repetition_count")) != 120:
        failures.append("streaming_dma_target_summary must cover 120 accepted repetitions")
    if as_int(aggregate.get("board_sample_count")) != 12:
        failures.append("streaming_dma_target_summary must cover 12 board samples")
    if as_int(aggregate.get("trace_record_width_bits")) != 136 or as_int(aggregate.get("trace_record_width_bytes")) != 17:
        failures.append("compact trace record width must be 136 bits / 17 bytes")
    if as_float(throughput_target.get("p95_event_bytes_per_cycle")) <= 0.0:
        failures.append("p95 event-byte target must be positive")
    if throughput_target.get("p95_event_bytes_per_second") != BYTES_PER_SECOND_REQUIRES_CLOCK:
        failures.append("bytes/sec target must remain deferred until exact external streaming clock is supplied")
    if throughput_target.get("clock_hz_required_for_bytes_per_second") is not True:
        failures.append("exact streaming clock requirement missing")
    if throughput_target.get("external_summary_path") != EXTERNAL_SUMMARY_PATH:
        failures.append("external streaming/DMA summary path mismatch")
    if boundary.get("production_streaming_dma_throughput_claimed") is not False:
        failures.append("streaming_dma_target_summary must not claim production throughput")
    if boundary.get("external_streaming_dma_experiment_completed") is not False:
        failures.append("streaming_dma_target_summary must not mark external experiment complete")
    for row in source_rows:
        if row.get("exists") is not True:
            failures.append(f"missing source evidence {row.get('path')}")

    p95_per_cycle = as_float(throughput_target.get("p95_event_bytes_per_cycle"))
    return {
        "schema": "rvmt.genesys2.streaming_dma_readiness.v1",
        "status": "PASS" if not failures else "FAIL",
        "canonical_evaluation_root": repo_rel(ROOT / current_root),
        "scope": "readiness package for future non-BRAM production streaming/DMA trace-sink throughput evidence",
        "source_evidence": source_rows,
        "target_baseline": {
            "metric": throughput_target.get("metric"),
            "p95_event_bytes_per_cycle": p95_per_cycle,
            "max_observed_event_bytes_per_cycle": throughput_target.get("max_observed_event_bytes_per_cycle"),
            "record_width_bits": throughput_target.get("record_width_bits"),
            "record_width_bytes": throughput_target.get("record_width_bytes"),
            "accepted_repetition_count": aggregate.get("accepted_repetition_count"),
            "board_sample_count": aggregate.get("board_sample_count"),
            "external_summary_path": EXTERNAL_SUMMARY_PATH,
            "required_external_summary_schema": "rvmt.genesys2.streaming_dma_throughput.v1",
            "bytes_per_second_formula": "p95_event_bytes_per_cycle * exact_streaming_bitstream_trace_clock_hz",
            "exact_clock_hz_required": True,
        },
        "future_transport_contract": {
            "allowed_transport_kinds": list(EXPECTED_TRANSPORTS),
            "disallowed_transport_kinds": list(DISALLOWED_TRANSPORTS),
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
            "required_evidence_artifact_kinds": [
                "transport_design_manifest",
                "streaming_bitstream_clock_report",
                "host_receiver_log",
                "parser_output_log",
                "drop_accounting_report",
                "timing_report",
                "resource_report",
                "noninterference_report",
            ],
            "required_summary_fields": [
                "evidence_artifacts",
                "transport",
                "sustained_bytes_per_second",
                "p95_event_bytes_per_second",
                "trace_clock_hz",
                "unaccounted_drop",
                "timing_passed",
                "noninterference_passed",
                "resource_delta",
                "host_receiver",
                "accepted_runs",
                "failed_attempts",
            ],
            "host_receiver_log_required_fields": [
                "bytes_received",
                "events_received",
                "elapsed_seconds",
                "parser_success",
                "parse_error_count",
                "sequence_gap_count",
                "dropped_event_count",
                "backpressure_count",
            ],
            "acceptance_criteria": [
                "transport is one of the allowed non-BRAM production transport kinds",
                "sustained_bytes_per_second exceeds p95_event_bytes_per_cycle times the exact streaming bitstream trace clock Hz",
                "accepted runs have parser_success=true and unaccounted_drop=0",
                "timing, resource, and trace_off versus trace_on noninterference reports are artifact-backed",
                "failed throughput attempts are retained with impact analysis and are not counted as accepted evidence",
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
        "validation_commands": [
            "uv run python tools/package_genesys2_streaming_dma_readiness.py",
            "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
        ],
        "non_claims": [
            "This is a readiness package and does not claim production streaming/DMA throughput evidence is complete.",
            "BRAM ring captures, ILA/JTAG dumps, and local runtime benchmarks must not be substituted for non-BRAM streaming/DMA transport evidence.",
            "Host receiver losslessness, timing closure, resource deltas, and noninterference remain unclaimed until accepted external artifacts are present.",
            "The future production streaming/DMA closure gate remains OPEN_EXTERNAL_ARTIFACTS_REQUIRED until external transport artifacts are accepted.",
        ],
        "failures": failures,
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        artifact = root / "artifact.json"
        write_json(artifact, {"schema": "rvmt.fixture.v1", "status": "PASS"})
        row = evidence_row("fixture", artifact)
    if row.get("exists") is not True or row.get("schema") != "rvmt.fixture.v1" or not row.get("sha256"):
        print("[FAIL] streaming/DMA readiness packager self-test failed", file=sys.stderr)
        return 1
    print("[PASS] streaming/DMA readiness packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package readiness evidence for future Genesys2 production streaming/DMA trace-sink runs.")
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        summary = package_summary(args.current_root)
        write_json(ROOT / args.out, summary)
    except Exception as exc:
        print(f"package_genesys2_streaming_dma_readiness: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote streaming/DMA readiness summary to {args.out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
