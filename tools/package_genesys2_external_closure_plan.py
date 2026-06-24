from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from ccfa_gate_common import ALL_CCFA_SAMPLES
from check_genesys2_external_closure_intake import EXPECTED_EXTERNAL_SUMMARIES, REQUIRED_EVIDENCE_ARTIFACT_KINDS


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_READINESS = DEFAULT_CURRENT_ROOT / "external_closure_readiness.json"
DEFAULT_INTAKE = DEFAULT_CURRENT_ROOT / "external_closure_intake.json"
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "external_closure_plan.json"
DEFAULT_TEMPLATE_ROOT = DEFAULT_CURRENT_ROOT / "external_closure_templates"


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def repo_rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_path(root: Path, value: Path) -> Path:
    return value if value.is_absolute() else root / value


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def external_template_path(record_id: str) -> str:
    summary_path = EXPECTED_EXTERNAL_SUMMARIES[record_id]["path"]
    return (DEFAULT_TEMPLATE_ROOT / f"{summary_path.stem}.template.json").as_posix()


def candidate_summary_placeholder(record_id: str) -> str:
    return f"<candidate-{record_id.replace('_', '-')}-summary.json>"


def summary_preparation_commands(record_id: str) -> list[str]:
    candidate = candidate_summary_placeholder(record_id)
    return [
        f"uv run python tools/prepare_genesys2_external_summary.py --record-id {record_id} --write-template {external_template_path(record_id)}",
        f"uv run python tools/prepare_genesys2_external_summary.py --record-id {record_id} --summary {candidate}",
    ]


def rows_by_id(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = data.get("records")
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def plan_status(intake_status: str) -> str:
    if intake_status == "EXTERNAL_SUMMARY_ACCEPTED":
        return "EXTERNAL_SUMMARY_ACCEPTED"
    if intake_status == "EXTERNAL_SUMMARY_PRESENT_INVALID":
        return "NEEDS_EXTERNAL_SUMMARY_CORRECTION"
    return "READY_TO_EXECUTE_WITH_EXTERNAL_STATE"


def template_common(schema: str) -> dict[str, Any]:
    return {
        "schema": schema,
        "status": "TEMPLATE_NOT_EVIDENCE",
        "template_only": True,
        "claim_boundary": {"real_malware_validation_claimed": False},
    }


def template_evidence_artifacts(record_id: str) -> list[dict[str, str]]:
    return [
        {
            "id": kind,
            "kind": kind,
            "path": f"results/evaluation/genesys2-cva6/current/external_closure/{record_id}/{kind}.txt",
            "sha256": "<64 lowercase hex sha256 of artifact file>",
        }
        for kind in sorted(REQUIRED_EVIDENCE_ARTIFACT_KINDS[record_id])
    ]


def source_line_template() -> dict[str, Any]:
    summary = template_common("rvmt.genesys2.board_native_source_lines.v1")
    summary["claim_boundary"].update(
        {
            "board_native_source_line_attribution_claimed": True,
            "sidecar_source_lines_substituted": False,
            "captured_elf_sha256_exact_match": True,
        }
    )
    summary.update(
        {
            "evidence_artifacts": template_evidence_artifacts("board_native_dwarf_source_lines"),
            "aggregate": {
                "sample_count": len(ALL_CCFA_SAMPLES),
                "source_line_rate": ">=0.95",
                "unknown_key_events": 0,
                "unaccounted_drop": 0,
                "marker_windows_passed": True,
            },
            "samples": [
                {
                    "id": sample_id,
                    "genesys2_cva6_board_claimed": True,
                    "captured_elf_sha256": "<64 lowercase hex sha256 of exact board ELF>",
                    "captured_elf_sha256_exact_match": True,
                    "debug_sections_present": True,
                    "readelf_debug_line_proven": True,
                    "source_line_attribution_available": True,
                    "board_trace_source_line_available": True,
                    "source_line_rate": ">=0.95",
                    "unaccounted_drop": 0,
                }
                for sample_id in ALL_CCFA_SAMPLES
            ],
        }
    )
    return summary


def pointer_string_template() -> dict[str, Any]:
    summary = template_common("rvmt.genesys2.hardware_pointer_strings.v1")
    summary["claim_boundary"].update(
        {
            "hardware_full_pointer_strings_claimed": True,
            "companion_strings_substituted_as_hardware": False,
            "kernel_or_full_memory_dump_claimed": False,
        }
    )
    summary.update(
        {
            "evidence_artifacts": template_evidence_artifacts("full_hardware_pointer_strings"),
            "aggregate": {
                "full_string_claimed": True,
                "contiguous_from_offset_zero": True,
                "mem_last_observed": True,
                "companion_derived_strings_as_hardware": 0,
                "kernel_fragment_count": 0,
                "full_memory_dump_count": 0,
            },
            "full_string_group_count": ">0",
            "redaction_policy": "<artifact-backed raw pointer payload redaction and release policy>",
            "failed_attempts": [],
            "pointer_groups": [
                {
                    "syscall_name": syscall_name,
                    "full_string_claimed": True,
                    "contiguous_from_offset_zero": True,
                    "mem_last_observed": True,
                    "companion_derived_strings_as_hardware": False,
                    "kernel_fragment_count": 0,
                }
                for syscall_name in ("openat", "write", "execve")
            ],
            "syscall_coverage": {
                syscall_name: {
                    "full_string_group_count": ">0",
                    "gap_free": True,
                    "mem_last_observed": True,
                    "companion_derived_strings_as_hardware": False,
                }
                for syscall_name in ("openat", "write", "execve")
            },
        }
    )
    return summary


def streaming_template() -> dict[str, Any]:
    summary = template_common("rvmt.genesys2.streaming_dma_throughput.v1")
    summary["claim_boundary"].update(
        {
            "production_streaming_dma_throughput_claimed": True,
            "bram_jtag_substituted_for_streaming": False,
        }
    )
    summary.update(
        {
            "evidence_artifacts": template_evidence_artifacts("production_streaming_dma_trace_sink"),
            "transport": "<axi_dma|ethernet_streaming|pcie_dma|uart_streaming_dma>",
            "sustained_bytes_per_second": "> required_sustained_bytes_per_second",
            "p95_event_bytes_per_second": "> 0",
            "p99_event_bytes_per_second": "> 0",
            "minimum_sustained_throughput_multiplier": 1.5,
            "required_sustained_bytes_per_second": "1.5 * p99_event_bytes_per_second",
            "unaccounted_drop": 0,
            "timing_passed": True,
            "noninterference_passed": True,
            "host_receiver_log_present": True,
            "resource_report_present": True,
            "failed_attempts_retained": True,
        }
    )
    return summary


def board_benign_template() -> dict[str, Any]:
    summary = template_common("rvmt.genesys2.board_benign_control.v1")
    summary["claim_boundary"].update(
        {
            "genesys2_board_benign_control_claimed": True,
            "local_linux_benign_substituted": False,
        }
    )
    summary.update(
        {
            "evidence_artifacts": template_evidence_artifacts("genesys2_board_benign_control"),
            "aggregate": {
                "genesys2_board_trace_claimed": True,
                "sample_count": ">=5",
                "unexpected_false_positive_count": 0,
                "benign_false_positive_rate": 0.0,
            },
            "samples": [
                {
                    "id": sample_id,
                    "genesys2_cva6_board_trace_claimed": True,
                    "non_network": True,
                    "unexpected_false_positive": False,
                    "semantic_events": f"results/evaluation/genesys2-cva6/current/external_closure/genesys2_board_benign_control/{sample_id}/semantic_events.json",
                    "behavior_graph": f"results/evaluation/genesys2-cva6/current/external_closure/genesys2_board_benign_control/{sample_id}/behavior_graph.json",
                    "behavior_audit": f"results/evaluation/genesys2-cva6/current/external_closure/genesys2_board_benign_control/{sample_id}/behavior_audit.json",
                }
                for sample_id in ("hello", "ls", "cat", "cp", "sha256sum")
            ],
        }
    )
    return summary


def record_plan(record_id: str, readiness: dict[str, Any], intake: dict[str, Any]) -> dict[str, Any]:
    spec = EXPECTED_EXTERNAL_SUMMARIES[record_id]
    readiness_artifacts = readiness.get("required_external_artifacts", [])
    readiness_criteria = readiness.get("acceptance_criteria", [])
    common = {
        "id": record_id,
        "readiness_status": readiness.get("readiness_status"),
        "intake_completion_status": intake.get("completion_status"),
        "plan_status": plan_status(str(intake.get("completion_status") or "")),
        "current_blocker": intake.get("current_blocker"),
        "external_summary_path": intake.get("external_summary_path"),
        "template_path": external_template_path(record_id),
        "required_summary_schema": spec["schema"],
        "acceptance_gate": "uv run python tools/check_genesys2_external_closure_intake.py --root .",
        "required_raw_artifacts": readiness_artifacts,
        "acceptance_criteria": readiness_criteria,
        "no_substitution_rule": readiness.get("no_substitution_rule"),
        "validation_commands": [
            "uv run python tools/package_genesys2_external_closure_intake.py",
            "uv run python tools/check_genesys2_external_closure_intake.py --root .",
        ],
        "exit_criteria": [
            "external_summary_exists=true in external_closure_intake.json",
            "completion_status=EXTERNAL_SUMMARY_ACCEPTED for this record",
            "completion_evidence_valid=true for this record",
            "no validation_errors for this record",
        ],
    }
    if record_id == "board_native_dwarf_source_lines":
        common.update(
            {
                "operator_inputs": [
                    "Genesys2/CVA6 board access with the current trace bitstream or a recorded equivalent bitstream hash",
                    "debug/no-PIE RISC-V Linux workload ELFs built from the exact listed sources with retained .debug_line",
                    "readelf -S and addr2line transcripts for each captured ELF",
                    "board capture roots produced from those exact debug ELFs",
                ],
                "preflight_commands": [
                    "uv run python tools/package_source_line_toolchain_probe.py",
                    "uv run python tools/check_source_line_toolchain_probe.py --root .",
                    "uv run python tools/package_genesys2_debug_elf_readiness.py",
                    "uv run python tools/check_genesys2_debug_elf_readiness.py --root .",
                    "uv run python tools/build_genesys2_p0_marker_elf.py --code-map",
                    "uv run python tools/build_genesys2_safe_syscall_elf.py --code-map",
                ],
                "collection_commands": [
                    "uv run python tools/run_genesys2_p0_bram_repetitions.py --run-root <debug-p0-board-run-root> --repetitions 10",
                    "uv run python tools/run_genesys2_safe_surrogate_bram_repetitions.py --run-root <debug-safe-board-run-root> --repetitions 10",
                    "collect debug_elf_readiness_summary.json as the candidate debug ELF manifest and require captured_elf_sha256 exact matches after board rerun",
                    "uv run python tools/build_code_map.py --elf <captured-debug-elf> --addr2line --out <code-map.json>",
                    "uv run python tools/join_trace_code_map.py --trace <trace.jsonl> --code-map <code-map.json> --out <joined.json>",
                ],
                "packaging_commands": [
                    *summary_preparation_commands(record_id),
                    "write results/evaluation/genesys2-cva6/current/external_closure/board_native_source_lines_summary.json from the accepted board run roots",
                    "uv run python tools/package_genesys2_external_closure_intake.py",
                ],
                "summary_template": source_line_template(),
            }
        )
    elif record_id == "full_hardware_pointer_strings":
        common.update(
            {
                "operator_inputs": [
                    "RTL change or equivalent CVA6 LSU/user-copy hook that observes contiguous user-pointer bytes",
                    "Trace format extension preserving mem_last and pointer-group boundaries",
                    "Genesys2/CVA6 board recapture roots for openat, write, and execve full-string cases",
                    "Raw byte redaction policy for any releasable summaries",
                ],
                "preflight_commands": [
                    "uv run python tools/check_pointer_snapshot_guardrails.py --root .",
                    "uv run python tools/check_hardware_pointer_prefixes.py --root .",
                    "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                    "uv run python tools/run_genesys2_pointer_snapshot_bram_capture.py --dry-run",
                ],
                "collection_commands": [
                    "uv run python tools/run_genesys2_pointer_snapshot_bram_capture.py --run-root <full-string-board-run-root> --repetitions 10",
                    "collect full-string ARG_MEM groups with mem_last=true and contiguous offsets from zero",
                    "retain negative kernel-range and gapped-fragment cases as non-promoted fragments",
                ],
                "packaging_commands": [
                    "uv run python tools/package_genesys2_pointer_string_readiness.py",
                    "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                    *summary_preparation_commands(record_id),
                    "write results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json from the full-string board run",
                    "uv run python tools/package_genesys2_external_closure_intake.py",
                ],
                "summary_template": pointer_string_template(),
            }
        )
    elif record_id == "production_streaming_dma_trace_sink":
        common.update(
            {
                "operator_inputs": [
                    "Non-BRAM transport implementation such as AXI DMA, Ethernet streaming, or an equivalent production streaming path",
                    "Host receiver logs with byte count, event count, elapsed time, and parser success",
                    "Resource, timing, and route reports for the exact streaming bitstream",
                    "Trace-off versus trace-on workload result comparison",
                ],
                "preflight_commands": [
                    "uv run python tools/check_trace_export_decision.py --root .",
                    "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
                    "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
                    "uv run python tools/run_genesys2_runtime_benchmark.py --dry-run",
                    "uv run python tools/check_genesys2_bitstream_artifacts.py --root .",
                ],
                "collection_commands": [
                    "external: build and program the selected non-BRAM streaming trace bitstream",
                    "external: run host receiver during the selected workload set and retain byte/event/elapsed/parser logs; compare sustained bytes/sec against 1.5 * p99_event_bytes_per_cycle from streaming_dma_target_summary.json converted with the exact streaming bitstream clock report",
                    "uv run python tools/run_genesys2_runtime_benchmark.py --run-root <streaming-runtime-run-root> --mode trace_off --mode event_only --mode bram_ring",
                ],
                "packaging_commands": [
                    "uv run python tools/package_genesys2_streaming_dma_readiness.py",
                    "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
                    *summary_preparation_commands(record_id),
                    "write results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json from transport, host receiver, timing, resource, and noninterference artifacts",
                    "uv run python tools/package_genesys2_external_closure_intake.py",
                ],
                "summary_template": streaming_template(),
            }
        )
    elif record_id == "genesys2_board_benign_control":
        common.update(
            {
                "operator_inputs": [
                    "At least five non-network benign workloads staged on the Genesys2/CVA6 target",
                    "Board trace captures for each benign workload under the current trace route",
                    "Per-workload semantic events, behavior graph, and behavior audit generated from board traces",
                    "Documented allowed benign overlaps separated from unexpected false positives",
                ],
                "preflight_commands": [
                    "uv run python tools/check_benign_control_summary.py --root .",
                    "uv run python tools/check_genesys2_board_benign_readiness.py --root .",
                    "uv run python tools/check_behavior_audit_metrics.py --root .",
                    "uv run python tools/run_genesys2_safe_surrogate_bram_repetitions.py --dry-run",
                ],
                "collection_commands": [
                    "external: execute hello, ls, cat, cp, and sha256sum or equivalent non-network benign workloads on Genesys2/CVA6",
                    "external: capture per-benign-workload BRAM marker windows and UART logs",
                    "uv run python tools/audit_behavior.py --help",
                ],
                "packaging_commands": [
                    "uv run python tools/package_genesys2_board_benign_readiness.py",
                    "uv run python tools/check_genesys2_board_benign_readiness.py --root .",
                    *summary_preparation_commands(record_id),
                    "write results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json from board-derived benign artifacts",
                    "uv run python tools/package_genesys2_external_closure_intake.py",
                ],
                "summary_template": board_benign_template(),
            }
        )
    else:  # pragma: no cover
        raise KeyError(record_id)
    return common


def package_plan(root: Path, current_root: Path) -> dict[str, Any]:
    readiness_path = repo_path(root, current_root / "external_closure_readiness.json")
    intake_path = repo_path(root, current_root / "external_closure_intake.json")
    readiness = load_json(readiness_path)
    intake = load_json(intake_path)
    readiness_records = rows_by_id(readiness)
    intake_records = rows_by_id(intake)
    records = [
        record_plan(record_id, readiness_records[record_id], intake_records[record_id])
        for record_id in EXPECTED_EXTERNAL_SUMMARIES
    ]
    return {
        "schema": "rvmt.genesys2.external_closure_plan.v1",
        "status": "PASS",
        "canonical_evaluation_root": repo_rel(repo_path(root, current_root), root),
        "scope": "executable plan and summary templates for remaining non-real-malware Genesys2/CVA6 external blockers",
        "objective_exclusions": ["real_malware_validation"],
        "claim_boundary": {
            "plan_only": True,
            "real_malware_validation_claimed": False,
            "external_execution_completed": False,
            "all_non_real_external_blockers_closed": intake.get("closure_status") == "ALL_NON_REAL_EXTERNAL_SUMMARIES_ACCEPTED",
        },
        "source_artifacts": [
            {
                "id": "external_closure_readiness",
                "path": repo_rel(readiness_path, root),
                "exists": readiness_path.is_file(),
                "sha256": sha256_file(readiness_path),
                "schema": readiness.get("schema"),
                "expected_schema": "rvmt.genesys2.external_closure_readiness.v1",
                "status": readiness.get("status"),
            },
            {
                "id": "external_closure_intake",
                "path": repo_rel(intake_path, root),
                "exists": intake_path.is_file(),
                "sha256": sha256_file(intake_path),
                "schema": intake.get("schema"),
                "expected_schema": "rvmt.genesys2.external_closure_intake.v1",
                "status": intake.get("status"),
                "closure_status": intake.get("closure_status"),
            },
        ],
        "open_external_blocker_count": intake.get("open_external_blocker_count"),
        "accepted_external_blocker_count": intake.get("accepted_external_blocker_count"),
        "invalid_external_blocker_count": intake.get("invalid_external_blocker_count"),
        "records": records,
        "validation_commands": [
            "uv run python tools/package_genesys2_external_closure_plan.py",
            "uv run python tools/check_genesys2_external_closure_plan.py --root .",
            "uv run python tools/prepare_genesys2_external_summary.py --self-test",
            "uv run python tools/check_genesys2_external_closure_intake.py --root .",
        ],
        "interpretation": [
            "This plan makes the remaining non-real-malware external work executable and template-driven.",
            "Embedded summary templates are not evidence and must not be copied into the intake path without real board, RTL, or reviewer artifacts.",
            "The plan does not close any external blocker while external_closure_intake.json remains OPEN_EXTERNAL_ARTIFACTS_REQUIRED.",
        ],
    }


def write_template_files(root: Path, package: dict[str, Any]) -> None:
    for record in package.get("records", []):
        if not isinstance(record, dict):
            continue
        template_path = record.get("template_path")
        template = record.get("summary_template")
        if isinstance(template_path, str) and isinstance(template, dict):
            write_json(repo_path(root, Path(template_path)), template)


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        readiness_records = []
        intake_records = []
        for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
            readiness_records.append(
                {
                    "id": record_id,
                    "readiness_status": "fixture",
                    "required_external_artifacts": ["one", "two", "three", "four"],
                    "acceptance_criteria": ["one", "two", "three", "four"],
                    "no_substitution_rule": "fixture must not be substituted for external evidence",
                }
            )
            intake_records.append(
                {
                    "id": record_id,
                    "completion_status": "OPEN_NO_EXTERNAL_SUMMARY",
                    "current_blocker": True,
                    "external_summary_path": spec["path"].as_posix(),
                }
            )
        write_json(
            current / "external_closure_readiness.json",
            {"schema": "rvmt.genesys2.external_closure_readiness.v1", "status": "PASS", "records": readiness_records},
        )
        write_json(
            current / "external_closure_intake.json",
            {
                "schema": "rvmt.genesys2.external_closure_intake.v1",
                "status": "PASS",
                "closure_status": "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
                "open_external_blocker_count": 4,
                "accepted_external_blocker_count": 0,
                "invalid_external_blocker_count": 0,
                "records": intake_records,
            },
        )
        package = package_plan(root, DEFAULT_CURRENT_ROOT)
        if package.get("status") != "PASS" or len(package.get("records", [])) != len(EXPECTED_EXTERNAL_SUMMARIES):
            print("[FAIL] external closure plan fixture failed", file=sys.stderr)
            print(json.dumps(package, indent=2), file=sys.stderr)
            return 1
        if any(record.get("summary_template", {}).get("status") != "TEMPLATE_NOT_EVIDENCE" for record in package["records"]):
            print("[FAIL] plan templates must not be evidence", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 external closure plan packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package an executable plan for remaining non-real-malware Genesys2/CVA6 external blockers.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    out = repo_path(root, args.out)
    try:
        package = package_plan(root, args.current_root)
        write_json(out, package)
        write_template_files(root, package)
    except Exception as exc:
        print(f"package_genesys2_external_closure_plan: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{package['status']}] wrote Genesys2 external closure plan to {out}")
    return 0 if package["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
