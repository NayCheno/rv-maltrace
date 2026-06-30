from __future__ import annotations

from pathlib import Path
from typing import Any

from ccfa_current_quality_spec import (
    DEFAULT_CURRENT_ROOT,
    EXPECTED_EXECVE_TARGETS,
    EXPECTED_SAMPLE_SYSCALLS,
    PLANNING_DOCS,
    SUMMARY_SCHEMAS,
    UART_WALL_CLOCK_RUNTIME_METRIC,
)
from ccfa_gate_spec import ALL_CCFA_SAMPLES, P0_SAMPLES, SAFE_SURROGATE_SAMPLES
from experiment_common import load_json, sha256_file, write_json


def touch(path: Path, text: str = "fixture\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def write_fixture(root: Path) -> Path:
    current = root / DEFAULT_CURRENT_ROOT
    current.mkdir(parents=True, exist_ok=True)
    artifact_root = root / "fixture_artifacts"
    bit = artifact_root / "ariane_xilinx.bit"
    ltx = artifact_root / "ariane_xilinx.ltx"
    touch(bit)
    touch(ltx)

    source_rows: list[dict[str, Any]] = []
    source_sidecar_rows: list[dict[str, Any]] = []
    semantic_rows: list[dict[str, Any]] = []
    fd_rows: list[dict[str, Any]] = []
    process_rows: list[dict[str, Any]] = []
    matrix_rows: list[dict[str, Any]] = []
    case_study_rows: list[dict[str, Any]] = []

    for sample_id in ALL_CCFA_SAMPLES:
        sample_dir = artifact_root / sample_id
        source = sample_dir / f"{sample_id}.c"
        touch(source, "int main(void) { return 0; }\n")
        trace = sample_dir / "trace.jsonl"
        semantic_events = sample_dir / "semantic_events.json"
        behavior_graph = sample_dir / "behavior_graph.json"
        code_map = sample_dir / "code_map.json"
        source_attr = sample_dir / "source_attribution_summary.json"
        integrated = sample_dir / "integrated_validation.json"
        for path in (trace, semantic_events, behavior_graph, code_map, source_attr, integrated):
            touch(path, "{}\n" if path.suffix == ".json" else "{\"evt\":\"fixture\"}\n")
        runtime_map = sample_dir / "runtime_process_map.json"
        write_json(
            runtime_map,
            {
                "schema": "rvmt.runtime_process_map.v1",
                "status": "PASS",
                "sample_id": sample_id,
                "owners": {"target_child": {"status": "PASS", "maps": [{"path": f"/tmp/{sample_id}"}]}},
            },
        )
        host = sample_dir / "host.strace.log"
        qemu = sample_dir / "qemu-riscv64.strace.log"
        touch(host, "1 write(1, \"x\", 1) = 1\n")
        touch(qemu, "1 write(1,0x1000,1) = 1\n")
        baseline = current / "samples" / sample_id / "baseline_logs.json"
        metric = current / "samples" / sample_id / "metric_summary.json"
        write_json(
            baseline,
            {
                "schema": "rvmt.sample_baseline_logs.v1",
                "sample_id": sample_id,
                "host_strace": {"present": True, "line_count": 1, "path": host.relative_to(root).as_posix()},
                "qemu_strace": {"present": True, "line_count": 1, "path": qemu.relative_to(root).as_posix()},
                "evidence": {
                    "trace": trace.relative_to(root).as_posix(),
                    "semantic_events": semantic_events.relative_to(root).as_posix(),
                    "behavior_graph": behavior_graph.relative_to(root).as_posix(),
                    "code_map": code_map.relative_to(root).as_posix(),
                    "source_attribution": source_attr.relative_to(root).as_posix(),
                    "runtime_process_map": runtime_map.relative_to(root).as_posix(),
                    "integrated_validation": integrated.relative_to(root).as_posix(),
                },
            },
        )
        write_json(metric, {"schema": "rvmt.sample_metric_summary.v1", "sample_id": sample_id, "metrics": {"unaccounted_drop": 0}})
        case_summary = current / "samples" / sample_id / "case_study_summary.json"
        expected_class = "p0_safe_synthetic" if sample_id in P0_SAMPLES else "malware_like_synthetic_syscall_only"
        write_json(
            case_summary,
            {
                "schema": "rvmt.ccfa.case_study_summary.v1",
                "status": "PASS",
                "sample_id": sample_id,
                "sample_class": expected_class,
                "real_malware": False,
                "case_study_complete": True,
                "non_claims": [
                    "This case study is not real malware validation.",
                    "Full hardware-derived pointer strings are not claimed.",
                ],
            },
        )
        case_study_rows.append(
            {
                "sample_id": sample_id,
                "sample_class": expected_class,
                "case_study_summary": case_summary.relative_to(root).as_posix(),
                "trace": trace.relative_to(root).as_posix(),
                "semantic_events": semantic_events.relative_to(root).as_posix(),
                "behavior_graph": behavior_graph.relative_to(root).as_posix(),
                "baseline_logs": baseline.relative_to(root).as_posix(),
                "audit_decision": "PASS_CONTROLLED_SAFE_WORKLOAD_AUDIT",
                "case_study_complete": True,
            }
        )
        matrix_rows.append(
            {
                "sample_id": sample_id,
                "trace": trace.relative_to(root).as_posix(),
                "semantic_events": semantic_events.relative_to(root).as_posix(),
                "behavior_graph": behavior_graph.relative_to(root).as_posix(),
                "baseline_logs": baseline.relative_to(root).as_posix(),
                "metric_summary": metric.relative_to(root).as_posix(),
                "continuous_trace": True,
                "unaccounted_drop": 0,
            }
        )
        expected = ["write"]
        if sample_id in EXPECTED_EXECVE_TARGETS:
            expected = ["execve"]
        if sample_id in EXPECTED_SAMPLE_SYSCALLS:
            expected = sorted(EXPECTED_SAMPLE_SYSCALLS[sample_id])
        has_openat = "openat" in expected
        has_execve = "execve" in expected
        has_write = "write" in expected
        semantic_rows.append(
            {
                "sample_id": sample_id,
                "expected_syscalls": expected,
                "expected_syscall_recall": 1.0,
                "syscall_precision": 1.0,
                "argument_reconstruction_accuracy": 1.0,
                "has_openat": has_openat,
                "openat_paths": ["/proc/self/status"] if has_openat else [],
                "openat_path_source": "qemu_guest_strace" if has_openat else "NOT_OBSERVED",
                "has_execve": has_execve,
                "execve_paths": ["/bin/true"] if has_execve else [],
                "execve_path_source": "qemu_guest_strace" if has_execve else "NOT_OBSERVED",
                "has_write": has_write,
                "write_buffer_prefix_recovered": has_write,
                "write_buffer_prefixes": ["x"] if has_write else [],
                "write_buffer_prefix_source": "host_or_control_strace" if has_write else "NOT_OBSERVED",
                "mmap_mprotect_behavior_node": sample_id == "dynamic_executable_memory",
                "anti_analysis_behavior_node": sample_id == "anti_debug_like",
                "ground_truth_alignment": {
                    "host_or_control_strace": host.relative_to(root).as_posix(),
                    "qemu_guest_strace": qemu.relative_to(root).as_posix(),
                    "strace": True,
                    "qemu_strace": True,
                },
                "trace_source": trace.relative_to(root).as_posix(),
            }
        )
        fd_rows.append(
            {
                "sample_id": sample_id,
                "fd_graph_complete": True,
                "unresolved_fd_count": 0,
                "has_openat": has_openat,
                "has_execve": has_execve,
                "graph": {"nodes": ["/bin/true"] if (has_openat or has_execve) else [], "edges": []},
            }
        )
        process_rows.append(
            {
                "sample_id": sample_id,
                "runtime_process_attribution_proven": True,
                "pid": 1,
                "tgid": 1,
                "executable_path": f"/tmp/{sample_id}",
                "target_elf_attributed_events": 1,
                "dynamic_library_events_correctly_separated": True,
                "runtime_process_map": runtime_map.relative_to(root).as_posix(),
            }
        )
        source_rows.append(
            {
                "sample_id": sample_id,
                "key_event_count": 1,
                "unknown_key_events": 0,
                "function_attribution_available": True,
                "source_line_sidecar": (current / "source_line_sidecar.json").relative_to(root).as_posix(),
                "source_line_sidecar_rate": 1.0,
            }
        )
        source_sidecar_rows.append(
            {
                "sample_id": sample_id,
                "source": source.relative_to(root).as_posix(),
                "expected_key_events": 1,
                "mapped_key_events": 1,
                "source_line_rate": 1.0,
                "events": [{"ordinal": 1, "syscall": expected[0], "source": source.relative_to(root).as_posix(), "line": 1}],
            }
        )

    write_json(current / "source_line_sidecar.json", {"expected_key_events": len(ALL_CCFA_SAMPLES), "mapped_key_events": len(ALL_CCFA_SAMPLES), "samples": source_sidecar_rows})
    write_json(
        current / "source_line_toolchain_probe.json",
        {
            "schema": SUMMARY_SCHEMAS["source_line_toolchain_probe.json"],
            "status": "PASS",
            "toolchain": {
                "docker_service": "linux-behavior",
                "compiler": "riscv64-linux-gnu-gcc fixture",
                "addr2line": "GNU addr2line fixture",
            },
            "probe": {
                "debug_sections_present": True,
                "debug_section_names": [".debug_info", ".debug_line"],
                "addr2line_source_line_available": True,
                "source_location_count": 1,
            },
            "current_board_elfs": [
                {"id": "phase4_uart_pass", "exists": True, "debug_sections_present": False},
                {"id": "phase4_onboard_uart_pass", "exists": True, "debug_sections_present": False},
                {"id": "p0_marker_hello_write", "exists": True, "debug_sections_present": False},
                {"id": "safe_surrogate_file_scan", "exists": True, "debug_sections_present": False},
            ],
            "claim_boundary": {
                "toolchain_source_line_probe_passed": True,
                "debug_counterpart_source_line_available": True,
                "current_board_elf_dwarf_available": False,
                "current_board_trace_source_line_available": False,
                "board_rerun_required_for_board_native_source_lines": True,
            },
        },
    )
    latest_roots = {
        "p0_continuous_trace": "results/board/genesys2_trace_validation/20260611-p0-continuous-136bit",
        "p0_bram_repetitions": "results/board/genesys2_trace_validation/20260612-p0-bram-repetitions",
        "safe_surrogate_bram_repetitions": "results/board/genesys2_trace_validation/20260624-current-safe-surrogate-cohort",
        "safe_surrogate_runtime_map": "results/board/genesys2_trace_validation/20260611-safe-surrogate-runtime-map",
        "pointer_snapshot_bram": "results/board/genesys2_trace_validation/20260612-pointer-snapshot-bram",
        "production_runtime_benchmark": "fixture_artifacts/runtime_benchmark",
    }
    write_json(
        current / "latest_manifest.json",
        {
            "schema": SUMMARY_SCHEMAS["latest_manifest.json"],
            "status": "PASS",
            "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
            "policy": {
                "latest_is_authoritative": True,
                "dated_run_roots_are_provenance_only": True,
                "do_not_select_by_chronological_order": True,
            },
            "active_run_roots": latest_roots,
        },
    )
    write_json(current / "trace_sink_summary.json", {"schema": SUMMARY_SCHEMAS["trace_sink_summary.json"], "status": "PASS", "samples": []})
    write_json(
        current / "safe_surrogate_bram_trace_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["safe_surrogate_bram_trace_summary.json"],
            "status": "PASS",
            "run_root": latest_roots["safe_surrogate_bram_repetitions"],
            "bitstream": bit.relative_to(root).as_posix(),
            "ltx": ltx.relative_to(root).as_posix(),
        },
    )
    write_json(
        current / "p0_bram_trace_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["p0_bram_trace_summary.json"],
            "status": "PASS",
            "run_root": latest_roots["p0_bram_repetitions"],
            "bitstream": bit.relative_to(root).as_posix(),
            "ltx": ltx.relative_to(root).as_posix(),
        },
    )
    write_json(
        current / "drop_accounting_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["drop_accounting_summary.json"],
            "status": "PASS",
            "p0_run_root": latest_roots["p0_continuous_trace"],
            "p0_bram_run_root": latest_roots["p0_bram_repetitions"],
            "safe_surrogate_bram_run_root": latest_roots["safe_surrogate_bram_repetitions"],
            "samples": [{"sample_id": sample_id, "unaccounted_drop": 0, "total_events": 1} for sample_id in ALL_CCFA_SAMPLES],
        },
    )
    write_json(current / "pointer_snapshot_guardrails.json", {"schema": SUMMARY_SCHEMAS["pointer_snapshot_guardrails.json"], "status": "PASS", "samples": []})
    benign_root = artifact_root / "benign_control"
    benign_samples: list[dict[str, Any]] = []
    for sample_id in ("hello", "ls", "cat", "cp", "sha256sum"):
        sample_dir = benign_root / sample_id
        trace = sample_dir / "host.strace.log"
        semantic = sample_dir / "semantic_events.json"
        graph = sample_dir / "behavior_graph.json"
        audit = sample_dir / "behavior_audit.json"
        for path in (trace,):
            touch(path, "write(1, \"x\", 1) = 1\n")
        write_json(semantic, {"schema": "rvmt.behavior.semantic.v1", "sample_class": "benign"})
        write_json(graph, {"schema": "rvmt.behavior.graph.v1", "sample_class": "benign", "real_malware": False, "nodes": [], "edges": []})
        write_json(audit, {"schema": "rvmt.behavior.audit.v1", "sample_class": "benign"})
        benign_samples.append(
            {
                "sample_id": sample_id,
                "sample_class": "benign",
                "status": "PASS",
                "false_positive": False,
                "unexpected_matched_rules": [],
                "strace_log": trace.relative_to(root).as_posix(),
                "semantic_events": semantic.relative_to(root).as_posix(),
                "behavior_graph": graph.relative_to(root).as_posix(),
                "behavior_audit": audit.relative_to(root).as_posix(),
            }
        )
    write_json(
        current / "benign_control_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["benign_control_summary.json"],
            "status": "PASS",
            "run_root": benign_root.relative_to(root).as_posix(),
            "aggregate": {
                "sample_count": 5,
                "non_network_sample_count": 5,
                "unexpected_false_positive_count": 0,
                "benign_false_positive_rate": 0.0,
            },
            "samples": benign_samples,
            "claim_boundary": {
                "local_linux_behavior_control": True,
                "genesys2_board_trace_claimed": False,
                "real_malware_validation_claimed": False,
            },
        },
    )
    write_json(
        current / "hardware_pointer_prefix_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["hardware_pointer_prefix_summary.json"],
            "status": "PASS",
            "run_root": latest_roots["pointer_snapshot_bram"],
            "trace_sink_mode": "bram_ring",
            "hardware_pointer_bytes_observed": True,
            "hardware_pointer_prefixes_claimed": True,
            "hardware_pointer_strings_claimed": False,
            "full_string_claimed": False,
            "companion_derived_strings_as_hardware": False,
            "total_repetitions": 30,
            "pointer_group_count": 30,
            "captured_byte_count": 90,
            "kernel_fragment_count": 0,
            "required_syscall_coverage": {"openat": True, "write": True, "execve": True},
            "non_claims": [
                "The current compact BRAM record format does not preserve full pointer strings.",
                "Trusted companion strings remain semantic sidecar evidence and are not reported as hardware-derived pointer strings.",
            ],
            "samples": [],
        },
    )
    write_json(
        current / "statistical_robustness_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["statistical_robustness_summary.json"],
            "status": "PASS",
            "claim_boundary": {
                "controlled_repetition_robustness_claimed": True,
                "randomized_workload_generalization_claimed": False,
                "real_malware_validation_claimed": False,
                "real_malware_generalization_claimed": False,
                "malware_detection_accuracy_claimed": False,
                "production_long_run_stability_claimed": False,
            },
        },
    )
    write_json(
        current / "streaming_dma_target_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["streaming_dma_target_summary.json"],
            "status": "PASS",
            "claim_boundary": {
                "streaming_dma_target_baseline_claimed": True,
                "production_streaming_dma_throughput_claimed": False,
                "real_malware_validation_claimed": False,
            },
        },
    )
    external_paths = [
        Path("tools/build_code_map.py"),
        Path("tools/join_trace_code_map.py"),
        Path("tools/audit_behavior.py"),
        Path("tools/package_benign_control_summary.py"),
        Path("docs/02-trace-architecture/trace_format.md"),
        Path("docs/02-trace-architecture/signal_map.md"),
        Path("docs/02-trace-architecture/trace_export_decision.md"),
        Path("rtl/trace/trace_top.sv"),
        Path("board/trace_validation/programs/hello_write.c"),
        Path("board/trace_validation/programs/file_open_read_write.c"),
        Path("board/trace_validation/programs/fork_exec.c"),
        Path("board/trace_validation/programs/illegal_instruction.c"),
        Path("experiments/linux_behavior/malware_like/programs/file_scan.c"),
        Path("experiments/linux_behavior/malware_like/programs/batch_open_read_write.c"),
        Path("experiments/linux_behavior/malware_like/programs/self_copy_sim.c"),
        Path("experiments/linux_behavior/malware_like/programs/abnormal_syscall_sequence.c"),
        Path("experiments/linux_behavior/malware_like/programs/illegal_trap.c"),
        Path("experiments/linux_behavior/malware_like/programs/process_chain.c"),
        Path("experiments/linux_behavior/malware_like/programs/dynamic_executable_memory.c"),
        Path("experiments/linux_behavior/malware_like/programs/anti_debug_like.c"),
    ]
    for path in external_paths:
        touch(root / path)

    def external_evidence(artifact_id: str, path: Path) -> dict[str, Any]:
        return {"id": artifact_id, "path": path.as_posix(), "exists": True, "sha256": "a" * 64}

    def external_record(record_id: str, readiness_status: str, evidence_paths: list[Path], *, sample_scope: bool = False, syscall_scope: bool = False) -> dict[str, Any]:
        row: dict[str, Any] = {
            "id": record_id,
            "current_status": "fixture",
            "readiness_status": readiness_status,
            "current_blocker": True,
            "completion_requires_external_state": True,
            "external_evidence_claimed": False,
            "existing_evidence": [external_evidence(path.stem, path) for path in evidence_paths],
            "required_external_artifacts": ["one", "two", "three", "four"],
            "acceptance_criteria": ["one", "two", "three", "four"],
            "future_checker_contract": {
                "required_summary_schema": f"rvmt.fixture.{record_id}.v1",
                "must_fail_until_external_artifacts_present": True,
                "required_fields": ["one", "two", "three", "four"],
            },
            "no_substitution_rule": "fixture evidence must not be substituted for external evidence",
        }
        if sample_scope:
            row["sample_scope"] = ALL_CCFA_SAMPLES
        if syscall_scope:
            row["syscall_scope"] = ["openat", "write", "execve"]
        return row

    write_json(
        current / "external_closure_readiness.json",
        {
            "schema": SUMMARY_SCHEMAS["external_closure_readiness.json"],
            "status": "PASS",
            "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
            "objective_exclusions": ["real_malware_validation"],
            "claim_boundary": {
                "readiness_contract_only": True,
                "real_malware_validation_claimed": False,
                "hardware_full_pointer_strings_claimed": False,
                "production_streaming_dma_throughput_claimed": False,
                "board_native_source_line_attribution_claimed": False,
                "genesys2_board_benign_control_claimed": False,
                "current_board_elf_dwarf_available": False,
                "current_board_trace_source_line_available": False,
                "full_string_claimed": False,
            },
            "external_blocker_count": 4,
            "records": [
                external_record(
                    "board_native_dwarf_source_lines",
                    "EXTERNAL_BOARD_RERUN_READY_NOT_EXECUTED",
                    [
                        Path("results/evaluation/genesys2-cva6/current/source_line_toolchain_probe.json"),
                        Path("results/evaluation/genesys2-cva6/current/source_line_attribution_summary.json"),
                        Path("results/evaluation/genesys2-cva6/current/source_line_sidecar.json"),
                        Path("tools/build_code_map.py"),
                        Path("tools/join_trace_code_map.py"),
                    ],
                    sample_scope=True,
                ),
                external_record(
                    "full_hardware_pointer_strings",
                    "RTL_EXTENSION_REQUIRED_NOT_EXECUTED",
                    [
                        Path("results/evaluation/genesys2-cva6/current/hardware_pointer_prefix_summary.json"),
                        Path("results/evaluation/genesys2-cva6/current/pointer_snapshot_guardrails.json"),
                        Path("docs/02-trace-architecture/trace_format.md"),
                        Path("docs/02-trace-architecture/signal_map.md"),
                    ],
                    syscall_scope=True,
                ),
                external_record(
                    "production_streaming_dma_trace_sink",
                    "STREAMING_DMA_EXPERIMENT_REQUIRED_NOT_EXECUTED",
                    [
                        Path("docs/02-trace-architecture/trace_export_decision.md"),
                        Path("results/evaluation/genesys2-cva6/current/trace_sink_summary.json"),
                        Path("results/evaluation/genesys2-cva6/current/drop_accounting_summary.json"),
                        Path("results/evaluation/genesys2-cva6/current/production_runtime_benchmark.json"),
                    ],
                ),
                external_record(
                    "genesys2_board_benign_control",
                    "BOARD_BENIGN_CONTROL_RUN_REQUIRED_NOT_EXECUTED",
                    [
                        Path("results/evaluation/genesys2-cva6/current/benign_control_summary.json"),
                        Path("results/evaluation/genesys2-cva6/current/behavior_audit_metrics.json"),
                        Path("tools/audit_behavior.py"),
                        Path("tools/package_benign_control_summary.py"),
                    ],
                ),
            ],
            "validation_commands": [
                "uv run python tools/package_genesys2_external_closure_readiness.py",
                "uv run python tools/check_genesys2_external_closure_readiness.py --root .",
            ],
            "interpretation": ["This readiness record does not upgrade current evidence."],
            "failures": [],
        },
    )
    write_json(
        current / "external_closure_intake.json",
        {
            "schema": SUMMARY_SCHEMAS["external_closure_intake.json"],
            "status": "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED",
            "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
            "external_summary_root": "results/evaluation/genesys2-cva6/current/external_closure",
            "scope": "optional external evidence intake for remaining non-real-malware Genesys2/CVA6 blockers",
            "objective_exclusions": ["real_malware_validation"],
            "closure_status": "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
            "accepted_external_blocker_count": 0,
            "open_external_blocker_count": 4,
            "invalid_external_blocker_count": 0,
            "claim_boundary": {
                "intake_gate_only": True,
                "all_non_real_external_blockers_closed": False,
                "real_malware_validation_claimed": False,
                "unvalidated_external_summary_accepted": False,
            },
            "records": [
                {
                    "id": record_id,
                    "required_summary_schema": schema,
                    "external_summary_path": path,
                    "external_summary_exists": False,
                    "external_summary_schema": None,
                    "external_summary_status": None,
                    "completion_status": "OPEN_NO_EXTERNAL_SUMMARY",
                    "completion_evidence_valid": False,
                    "current_blocker": True,
                    "completion_requires_external_state": True,
                    "validation_errors": [],
                    "acceptance_checker": "tools/check_genesys2_external_closure_intake.py",
                    "no_substitution_rule": "fixture evidence must not be substituted for external evidence",
                }
                for record_id, schema, path in (
                    (
                        "board_native_dwarf_source_lines",
                        "rvmt.genesys2.board_native_source_lines.v1",
                        "results/evaluation/genesys2-cva6/current/external_closure/board_native_source_lines_summary.json",
                    ),
                    (
                        "full_hardware_pointer_strings",
                        "rvmt.genesys2.hardware_pointer_strings.v1",
                        "results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json",
                    ),
                    (
                        "production_streaming_dma_trace_sink",
                        "rvmt.genesys2.streaming_dma_throughput.v1",
                        "results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json",
                    ),
                    (
                        "genesys2_board_benign_control",
                        "rvmt.genesys2.board_benign_control.v1",
                        "results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json",
                    ),
                )
            ],
            "validation_commands": [
                "uv run python tools/package_genesys2_external_closure_intake.py",
                "uv run python tools/check_genesys2_external_closure_intake.py --root .",
            ],
            "interpretation": ["This intake gate does not replace board, RTL, or reviewer execution."],
        },
    )

    def source_artifact(source_id: str, path_value: str, expected_schema: str, *, include_id: bool = False) -> dict[str, Any]:
        source_path = root / path_value
        source = load_json(source_path)
        row = {
            "path": path_value,
            "exists": True,
            "sha256": sha256_file(source_path),
            "schema": source.get("schema"),
            "expected_schema": expected_schema,
            "status": source.get("status"),
            "closure_status": source.get("closure_status"),
        }
        if include_id:
            row["id"] = source_id
        return row

    external_plan_records = []
    for record_id, schema, path in (
        (
            "board_native_dwarf_source_lines",
            "rvmt.genesys2.board_native_source_lines.v1",
            "results/evaluation/genesys2-cva6/current/external_closure/board_native_source_lines_summary.json",
        ),
        (
            "full_hardware_pointer_strings",
            "rvmt.genesys2.hardware_pointer_strings.v1",
            "results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json",
        ),
        (
            "production_streaming_dma_trace_sink",
            "rvmt.genesys2.streaming_dma_throughput.v1",
            "results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json",
        ),
        (
            "genesys2_board_benign_control",
            "rvmt.genesys2.board_benign_control.v1",
            "results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json",
        ),
    ):
        external_plan_records.append(
            {
                "id": record_id,
                "readiness_status": "FIXTURE_READY_NOT_EXECUTED",
                "intake_completion_status": "OPEN_NO_EXTERNAL_SUMMARY",
                "plan_status": "READY_TO_EXECUTE_WITH_EXTERNAL_STATE",
                "current_blocker": True,
                "external_summary_path": path,
                "required_summary_schema": schema,
                "acceptance_gate": "uv run python tools/check_genesys2_external_closure_intake.py --root .",
                "operator_inputs": ["fixture board access", "fixture raw artifacts", "fixture operator log"],
                "preflight_commands": ["uv run python tools/check_genesys2_external_closure_readiness.py --root .", "uv run python tools/check_genesys2_external_closure_intake.py --root ."],
                "collection_commands": ["collect external board/RTL evidence", "retain raw external transcripts"],
                "packaging_commands": ["write accepted external summary", "uv run python tools/package_genesys2_external_closure_intake.py"],
                "summary_template": {"schema": schema, "status": "TEMPLATE_NOT_EVIDENCE", "template_only": True},
                "required_raw_artifacts": ["fixture raw artifact A", "fixture raw artifact B"],
                "acceptance_criteria": ["fixture acceptance criterion A", "fixture acceptance criterion B"],
                "no_substitution_rule": "fixture evidence must not be substituted for external evidence",
                "exit_criteria": [
                    "completion_status=EXTERNAL_SUMMARY_ACCEPTED for this record",
                    "completion_evidence_valid=true for this record",
                ],
            }
        )
    write_json(
        current / "external_closure_plan.json",
        {
            "schema": SUMMARY_SCHEMAS["external_closure_plan.json"],
            "status": "PASS",
            "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
            "objective_exclusions": ["real_malware_validation"],
            "claim_boundary": {
                "plan_only": True,
                "external_execution_completed": False,
                "real_malware_validation_claimed": False,
                "all_non_real_external_blockers_closed": False,
            },
            "source_artifacts": [
                source_artifact(
                    "external_closure_readiness",
                    "results/evaluation/genesys2-cva6/current/external_closure_readiness.json",
                    "rvmt.genesys2.external_closure_readiness.v1",
                    include_id=True,
                ),
                source_artifact(
                    "external_closure_intake",
                    "results/evaluation/genesys2-cva6/current/external_closure_intake.json",
                    "rvmt.genesys2.external_closure_intake.v1",
                    include_id=True,
                ),
            ],
            "open_external_blocker_count": 4,
            "accepted_external_blocker_count": 0,
            "invalid_external_blocker_count": 0,
            "records": external_plan_records,
            "validation_commands": [
                "uv run python tools/package_genesys2_external_closure_plan.py",
                "uv run python tools/check_genesys2_external_closure_plan.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --self-test",
                "uv run python tools/check_genesys2_external_closure_intake.py --root .",
            ],
            "interpretation": ["Embedded summary templates are not evidence; this plan does not close external blockers."],
        },
    )
    operator_template_paths = {
        "board_native_dwarf_source_lines": "results/evaluation/genesys2-cva6/current/external_closure_templates/board_native_source_lines_summary.template.json",
        "full_hardware_pointer_strings": "results/evaluation/genesys2-cva6/current/external_closure_templates/hardware_pointer_strings_summary.template.json",
        "production_streaming_dma_trace_sink": "results/evaluation/genesys2-cva6/current/external_closure_templates/streaming_dma_throughput_summary.template.json",
        "genesys2_board_benign_control": "results/evaluation/genesys2-cva6/current/external_closure_templates/board_benign_control_summary.template.json",
    }
    operator_readiness_statuses = {
        "board_native_dwarf_source_lines": "EXTERNAL_BOARD_RERUN_READY_NOT_EXECUTED",
        "full_hardware_pointer_strings": "RTL_EXTENSION_REQUIRED_NOT_EXECUTED",
        "production_streaming_dma_trace_sink": "STREAMING_DMA_EXPERIMENT_REQUIRED_NOT_EXECUTED",
        "genesys2_board_benign_control": "BOARD_BENIGN_CONTROL_RUN_REQUIRED_NOT_EXECUTED",
    }
    for record in external_plan_records:
        write_json(
            root / operator_template_paths[str(record["id"])],
            {
                "schema": record["required_summary_schema"],
                "status": "TEMPLATE_NOT_EVIDENCE",
                "template_only": True,
            },
        )
    preflight_records = []
    for record in external_plan_records:
        record_id = str(record["id"])
        preflight_records.append(
            {
                "id": record_id,
                "status": "PASS_LOCAL_PREFLIGHT_EXTERNAL_OPEN",
                "external_summary_path": record["external_summary_path"],
                "external_summary_exists": False,
                "completion_status": "OPEN_NO_EXTERNAL_SUMMARY",
                "current_blocker": True,
                "local_preflight_ready": True,
                "tool_entrypoints_ready": True,
                "schema_path_ready": True,
                "external_execution_still_required": True,
                "no_substitution_rule_present": True,
                "operator_input_count": 3,
                "required_raw_artifact_count": 4,
                "acceptance_criteria_count": 4,
                "required_summary_schema": record["required_summary_schema"],
                "preflight_commands": [
                    {
                        "kind": "local_tool",
                        "command": "uv run python tools/check_genesys2_external_closure_plan.py --root .",
                        "script": "tools/check_genesys2_external_closure_plan.py",
                        "script_exists": True,
                        "dry_run_supported": "NOT_REQUESTED",
                        "code_map_supported": "NOT_REQUESTED",
                        "local_preflight_ready": True,
                    },
                    {
                        "kind": "local_tool",
                        "command": "uv run python tools/check_genesys2_external_closure_intake.py --root .",
                        "script": "tools/check_genesys2_external_closure_intake.py",
                        "script_exists": True,
                        "dry_run_supported": "NOT_REQUESTED",
                        "code_map_supported": "NOT_REQUESTED",
                        "local_preflight_ready": True,
                    },
                ],
                "collection_commands": [
                    {
                        "kind": "operator_collection_instruction",
                        "command": "collect external board, RTL, or host-transport artifacts",
                        "script": "NOT_APPLICABLE",
                        "script_exists": False,
                        "dry_run_supported": "NOT_REQUESTED",
                        "code_map_supported": "NOT_REQUESTED",
                        "local_preflight_ready": True,
                    },
                    {
                        "kind": "operator_collection_instruction",
                        "command": "retain raw transcripts and sha256-backed manifests",
                        "script": "NOT_APPLICABLE",
                        "script_exists": False,
                        "dry_run_supported": "NOT_REQUESTED",
                        "code_map_supported": "NOT_REQUESTED",
                        "local_preflight_ready": True,
                    },
                ],
                "packaging_commands": [
                    {
                        "kind": "local_tool",
                        "command": "uv run python tools/prepare_genesys2_external_summary.py --summary <candidate.json>",
                        "script": "tools/prepare_genesys2_external_summary.py",
                        "script_exists": True,
                        "dry_run_supported": "NOT_REQUESTED",
                        "code_map_supported": "NOT_REQUESTED",
                        "local_preflight_ready": True,
                    },
                    {
                        "kind": "local_tool",
                        "command": "uv run python tools/package_genesys2_external_closure_intake.py",
                        "script": "tools/package_genesys2_external_closure_intake.py",
                        "script_exists": True,
                        "dry_run_supported": "NOT_REQUESTED",
                        "code_map_supported": "NOT_REQUESTED",
                        "local_preflight_ready": True,
                    },
                ],
            }
        )
    write_json(
        current / "external_closure_preflight.json",
        {
            "schema": SUMMARY_SCHEMAS["external_closure_preflight.json"],
            "status": "PASS",
            "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
            "objective_exclusions": ["real_malware_validation"],
            "claim_boundary": {
                "local_preflight_only": True,
                "external_execution_completed": False,
                "all_non_real_external_blockers_closed": False,
                "real_malware_validation_claimed": False,
                "hardware_full_pointer_strings_claimed": False,
                "production_streaming_dma_throughput_claimed": False,
                "board_native_source_line_attribution_claimed": False,
                "genesys2_board_benign_control_claimed": False,
            },
            "source_artifacts": [
                source_artifact(
                    "external_closure_plan",
                    "results/evaluation/genesys2-cva6/current/external_closure_plan.json",
                    "rvmt.genesys2.external_closure_plan.v1",
                ),
                source_artifact(
                    "external_closure_intake",
                    "results/evaluation/genesys2-cva6/current/external_closure_intake.json",
                    "rvmt.genesys2.external_closure_intake.v1",
                ),
            ],
            "open_external_blocker_count": 4,
            "accepted_external_blocker_count": 0,
            "invalid_external_blocker_count": 0,
            "records": preflight_records,
            "validation_commands": [
                "uv run python tools/package_genesys2_external_closure_preflight.py",
                "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
                "uv run python tools/check_genesys2_external_closure_plan.py --root .",
                "uv run python tools/check_genesys2_external_closure_intake.py --root .",
            ],
            "interpretation": [
                "This preflight proves only local scripts, dry-run hooks, schemas, paths, and no-substitution guardrails are ready.",
                "It does not execute board, RTL, host receiver, or reviewer work and must not close external blockers by itself.",
                "The intake gate remains authoritative for accepting any future external summaries.",
            ],
        },
    )

    operator_records = []
    for index, record in enumerate(external_plan_records, start=1):
        record_id = str(record["id"])
        operator_records.append(
            {
                "id": record_id,
                "order": index,
                "plan_status": "READY_TO_EXECUTE_WITH_EXTERNAL_STATE",
                "plan_readiness_status": operator_readiness_statuses[record_id],
                "record_status": "OPEN_NO_EXTERNAL_SUMMARY_REQUIRES_EXTERNAL_COLLECTION",
                "readiness_status": "OPEN_NO_EXTERNAL_SUMMARY_REQUIRES_EXTERNAL_COLLECTION",
                "intake_completion_status": "OPEN_NO_EXTERNAL_SUMMARY",
                "completion_requires_external_state": True,
                "completion_evidence_valid": False,
                "execution_steps_required_to_close_record": True,
                "accepted_summary_supersedes_plan_readiness": False,
                "accepted_summary_must_remain_hash_valid": False,
                "external_summary_path": record["external_summary_path"],
                "template_path": operator_template_paths[record_id],
                "required_summary_schema": record["required_summary_schema"],
                "operator_inputs": ["fixture board/RTL access", "fixture raw artifacts", "fixture operator log"],
                "required_raw_artifacts": ["fixture raw artifact A", "fixture raw artifact B", "fixture raw artifact C", "fixture raw artifact D"],
                "required_evidence_artifact_kinds": ["fixture_manifest", "fixture_transcript", "fixture_summary"],
                "acceptance_criteria": [
                    "fixture acceptance criterion A",
                    "fixture acceptance criterion B",
                    "fixture acceptance criterion C",
                    "fixture acceptance criterion D",
                ],
                "no_substitution_rule": "fixture readiness must not be substituted for external completion evidence",
                "execution_steps": [
                    {"phase": "local_preflight", "commands": ["uv run python tools/check_genesys2_external_closure_preflight.py --root ."]},
                    {"phase": "external_collection", "commands": ["collect fixture external artifacts"], "requires_board_rtl_or_host_transport": True},
                    {"phase": "candidate_summary_packaging", "commands": ["write fixture candidate summary"]},
                    {"phase": "intake_acceptance", "commands": ["uv run python tools/check_genesys2_external_closure_intake.py --root ."]},
                ],
                "exit_criteria": [
                    "completion_status=EXTERNAL_SUMMARY_ACCEPTED for this record",
                    "completion_evidence_valid=true for this record",
                ],
            }
        )
    write_json(
        current / "external_operator_packet.json",
        {
            "schema": SUMMARY_SCHEMAS["external_operator_packet.json"],
            "status": "PASS",
            "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
            "objective_exclusions": ["real_malware_validation"],
            "closure_status": "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
            "accepted_external_blocker_count": 0,
            "open_external_blocker_count": 4,
            "invalid_external_blocker_count": 0,
            "claim_boundary": {
                "operator_packet_only": True,
                "external_execution_completed": False,
                "external_execution_completed_by_packet": False,
                "accepted_external_summaries_present": False,
                "accepted_external_summaries_hash_validated_by_intake": False,
                "open_or_invalid_external_blockers_remain": True,
                "external_readiness_substituted_for_completion": False,
                "all_non_real_external_blockers_closed": False,
                "real_malware_validation_claimed": False,
                "templates_treated_as_evidence": False,
                "external_artifact_paths_scoped_to_external_closure": True,
                "placeholder_values_treated_as_invalid": True,
            },
            "source_artifacts": {
                "external_closure_readiness": source_artifact(
                    "external_closure_readiness",
                    "results/evaluation/genesys2-cva6/current/external_closure_readiness.json",
                    "rvmt.genesys2.external_closure_readiness.v1",
                ),
                "external_closure_intake": source_artifact(
                    "external_closure_intake",
                    "results/evaluation/genesys2-cva6/current/external_closure_intake.json",
                    "rvmt.genesys2.external_closure_intake.v1",
                ),
                "external_closure_plan": source_artifact(
                    "external_closure_plan",
                    "results/evaluation/genesys2-cva6/current/external_closure_plan.json",
                    "rvmt.genesys2.external_closure_plan.v1",
                ),
                "external_closure_preflight": source_artifact(
                    "external_closure_preflight",
                    "results/evaluation/genesys2-cva6/current/external_closure_preflight.json",
                    "rvmt.genesys2.external_closure_preflight.v1",
                ),
            },
            "operator_sequence": [
                "Run the local preflight commands recorded for each external id.",
                "Execute the required board, RTL, or host-transport experiment outside the repository-only checker path.",
                "Write candidate summaries only from real external_closure artifacts with matching sha256-backed evidence rows and no template placeholders.",
                "Validate candidate summaries before moving them into the intake path.",
                "Regenerate external_closure_intake.json, then run the intake, operator packet, current-suite, and full reproduction checks.",
            ],
            "records": operator_records,
            "validation_commands": [
                "uv run python tools/package_genesys2_external_operator_packet.py",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/check_genesys2_external_closure_intake.py --root .",
                "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
            ],
        },
    )
    runtime_root = artifact_root / "runtime_benchmark"
    runtime_samples: list[dict[str, Any]] = []
    raw_repetitions: list[dict[str, Any]] = []
    runtime_modes = ["trace_off", "event_only", "bram_ring", "pointer_snapshot_disabled"]
    for sample_id in SAFE_SURROGATE_SAMPLES:
        modes: dict[str, Any] = {}
        for mode in runtime_modes:
            reps: list[dict[str, Any]] = []
            for rep in range(1, 4):
                log = runtime_root / sample_id / mode / f"rep_{rep:02d}" / "uart.log"
                touch(
                    log,
                    f"RVMT_RUNTIME_BENCH_START sample={sample_id} mode={mode} rep=rep_{rep:02d} ns=1000\n"
                    f"RVMT_RUNTIME_BENCH_DONE sample={sample_id} mode={mode} rep=rep_{rep:02d} rc=0 ns=2000\n",
                )
                row = {
                    "sample_id": sample_id,
                    "mode": mode,
                    "repetition_id": f"rep_{rep:02d}",
                    "rc": 0,
                    "duration_ns": 1000,
                    "program_log": log.relative_to(root).as_posix(),
                }
                reps.append(row)
                raw_repetitions.append(row)
            modes[mode] = {
                "count": 3,
                "median_ns": 1000,
                "p95_ns": 1000,
                "variance_ns2": 0.0,
                "slowdown_vs_trace_off_median": 1.0 if mode != "trace_off" else None,
                "repetitions": reps,
            }
        runtime_samples.append({"sample_id": sample_id, "modes": modes})
    write_json(
        current / "production_runtime_benchmark.json",
        {
            "schema": SUMMARY_SCHEMAS["production_runtime_benchmark.json"],
            "status": "PASS",
            "run_root": runtime_root.relative_to(root).as_posix(),
            "metric": UART_WALL_CLOCK_RUNTIME_METRIC,
            "minimum_repetitions_per_mode_sample": 3,
            "mode_stats": {
                mode: {"count": len(SAFE_SURROGATE_SAMPLES) * 3, "median_ns": 1000, "p95_ns": 1000, "variance_ns2": 0.0}
                for mode in runtime_modes
            },
            "samples": runtime_samples,
            "raw_repetitions": raw_repetitions,
        },
    )
    write_json(
        current / "semantic_reconstruction_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["semantic_reconstruction_summary.json"],
            "status": "PASS",
            "samples": semantic_rows,
            "non_claims": ["No hardware ARG_MEM/user-pointer byte snapshot is present.", "Real malware validation is not claimed."],
        },
    )
    write_json(current / "fd_path_graph_summary.json", {"schema": SUMMARY_SCHEMAS["fd_path_graph_summary.json"], "status": "PASS", "samples": fd_rows})
    write_json(current / "source_line_attribution_summary.json", {"schema": SUMMARY_SCHEMAS["source_line_attribution_summary.json"], "status": "PASS", "samples": source_rows})
    write_json(current / "process_elf_ownership_summary.json", {"schema": SUMMARY_SCHEMAS["process_elf_ownership_summary.json"], "status": "PASS", "samples": process_rows})
    write_json(current / "dynamic_mapping_attribution_summary.json", {"schema": SUMMARY_SCHEMAS["dynamic_mapping_attribution_summary.json"], "status": "PASS"})
    write_json(current / "workload_manifest.json", {"schema": SUMMARY_SCHEMAS["workload_manifest.json"], "status": "PASS", "samples": []})
    write_json(
        current / "resource_timing_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["resource_timing_summary.json"],
            "status": "PASS",
            "trace_bitstream": bit.relative_to(root).as_posix(),
            "trace_bitstream_sha256": sha256_file(bit),
            "ltx": ltx.relative_to(root).as_posix(),
            "ltx_sha256": sha256_file(ltx),
            "marker_window_cycle_summary": {"median": 1, "p95": 1, "variance": 0.0, "unit": "trace-cycle-or-index-delta"},
            "production_runtime_benchmark": (current / "production_runtime_benchmark.json").relative_to(root).as_posix(),
            "production_runtime_slowdown": {
                "claimed": False,
                "board_execution_smoke_claimed": True,
                "cycle_level_overhead_claimed": False,
                "production_runtime_slowdown_claimed": False,
                "benchmark": (current / "production_runtime_benchmark.json").relative_to(root).as_posix(),
                "metric": UART_WALL_CLOCK_RUNTIME_METRIC,
                "claim_boundary": {
                    "metric_is_cycle_level": False,
                    "wall_clock_uart_marker_metric": True,
                    "uart_wall_clock_promoted_to_overhead_claim": False,
                    "requires_native_cycle_or_hardware_counter_artifact": True,
                },
                "non_claims": [
                    "UART shell date markers are not a cycle-level perturbation or production slowdown claim.",
                ],
            },
            "runtime_overhead_scope": "board UART START/DONE markers are reported as runtime smoke only; cycle-level production slowdown is not claimed",
        },
    )
    write_json(
        current / "ccfa_evaluation_matrix.json",
        {
            "schema": SUMMARY_SCHEMAS["ccfa_evaluation_matrix.json"],
            "status": "PASS",
            "workload_manifest": (current / "workload_manifest.json").relative_to(root).as_posix(),
            "resource_timing_summary": (current / "resource_timing_summary.json").relative_to(root).as_posix(),
            "samples": matrix_rows,
        },
    )
    write_json(
        current / "baseline_alignment_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["baseline_alignment_summary.json"],
            "status": "PASS",
            "baselines": {
                "rv_maltrace_event_only": {"present": True, "alignment_pass": True, "command_transcript": (current / "safe_surrogate_bram_trace_summary.json").relative_to(root).as_posix()},
                "rv_maltrace_pointer_snapshot": {"present": True, "alignment_pass": True, "command_transcript": (current / "pointer_snapshot_guardrails.json").relative_to(root).as_posix()},
                "rv_maltrace_kernel_helper": {"present": True, "alignment_pass": True, "command_transcript": (current / "semantic_reconstruction_summary.json").relative_to(root).as_posix()},
            },
        },
    )
    write_json(
        current / "behavior_audit_metrics.json",
        {
            "schema": SUMMARY_SCHEMAS["behavior_audit_metrics.json"],
            "status": "PASS",
            "metrics": {"benign_false_positive_rate": 0.0},
            "benign_control_summary": (current / "benign_control_summary.json").relative_to(root).as_posix(),
        },
    )
    write_json(
        current / "case_study_manifest.json",
        {
            "schema": SUMMARY_SCHEMAS["case_study_manifest.json"],
            "status": "PASS",
            "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
            "case_study_count": len(ALL_CCFA_SAMPLES),
            "p0_case_study_count": len(P0_SAMPLES),
            "safe_surrogate_case_study_count": len(SAFE_SURROGATE_SAMPLES),
            "case_studies": case_study_rows,
            "claim_boundary": {
                "controlled_safe_surrogate_case_studies": True,
                "real_malware_validation_claimed": False,
                "malware_detection_accuracy_claimed": False,
                "hardware_full_pointer_strings_claimed": False,
                "board_native_source_line_attribution_claimed": False,
                "production_streaming_dma_throughput_claimed": False,
                "paper_ready_claimed": False,
            },
            "validation_commands": ["uv run python tools/check_ccfa_case_study_manifest.py --root ."],
        },
    )
    review_external_pairs = {
        "phase_b_full_hardware_pointer_strings": "full_hardware_pointer_strings",
        "phase_c_board_native_dwarf_source_lines": "board_native_dwarf_source_lines",
        "phase_d_genesys2_board_benign_control": "genesys2_board_benign_control",
        "phase_e_production_streaming_dma_trace_sink": "production_streaming_dma_trace_sink",
    }
    review_local_item_ids = [
        "phase_a_claim_boundary_convergence",
        "phase_a_baseline_board_acceptance",
        "phase_b_p0_and_safe_surrogate_hardware_trace",
        "phase_b_bounded_pointer_semantics",
        "phase_d_safe_surrogate_behavior_case_studies",
        "phase_d_local_benign_control",
        "phase_e_evaluation_matrix_and_baselines",
        "phase_e_statistical_robustness_audit",
        "phase_e_artifact_package_and_reproduction",
        "phase_e_streaming_dma_target_baseline",
    ]
    review_item_evidence = {
        "phase_a_claim_boundary_convergence": "docs/07-evaluation-evidence/reports/ccfa_readiness_matrix.md",
        "phase_a_baseline_board_acceptance": "docs/03-platform-architecture/genesys2/baseline_pass_criteria.md",
        "phase_b_p0_and_safe_surrogate_hardware_trace": "results/evaluation/genesys2-cva6/current/p0_bram_trace_summary.json",
        "phase_b_bounded_pointer_semantics": "results/evaluation/genesys2-cva6/current/hardware_pointer_prefix_summary.json",
        "phase_c_function_process_elf_attribution": "results/evaluation/genesys2-cva6/current/source_line_attribution_summary.json",
        "phase_d_safe_surrogate_behavior_case_studies": "results/evaluation/genesys2-cva6/current/case_study_manifest.json",
        "phase_d_local_benign_control": "results/evaluation/genesys2-cva6/current/benign_control_summary.json",
        "phase_e_evaluation_matrix_and_baselines": "results/evaluation/genesys2-cva6/current/ccfa_evaluation_matrix.json",
        "phase_e_statistical_robustness_audit": "results/evaluation/genesys2-cva6/current/statistical_robustness_summary.json",
        "phase_e_artifact_package_and_reproduction": "tools/reproduce_genesys2_current.py",
        "phase_e_streaming_dma_target_baseline": "results/evaluation/genesys2-cva6/current/streaming_dma_target_summary.json",
    }
    for path_value in review_item_evidence.values():
        path = root / path_value
        if not path.is_file():
            touch(path, "fixture\n")
    write_json(
        current / "real_malware_containment.json",
        {
            "schema": "rvmt.real_malware_containment.v1",
            "status": "PASS",
            "real_malware_payloads_present": False,
        },
    )

    def review_evidence(item_id: str, path_value: str) -> dict[str, Any]:
        path = root / path_value
        data = load_json(path) if path.suffix == ".json" else None
        schema = data.get("schema") if isinstance(data, dict) and isinstance(data.get("schema"), str) and data.get("schema") else "MISSING"
        status = data.get("status") if isinstance(data, dict) and isinstance(data.get("status"), str) and data.get("status") else "MISSING"
        if data is None:
            schema = "NOT_APPLICABLE"
            status = "NOT_APPLICABLE"
        return {
            "id": item_id,
            "path": path_value,
            "exists": True,
            "sha256": sha256_file(path),
            "schema": schema,
            "status": status,
        }

    intake_by_id = {
        str(row.get("id")): row
        for row in load_json(current / "external_closure_intake.json").get("records", [])
        if isinstance(row, dict) and row.get("id")
    }
    review_items = [
        {
            "id": item_id,
            "review_section": "fixture",
            "requirement": "fixture local review requirement",
            "status": "PASS_CURRENT",
            "evidence": [review_evidence(item_id, review_item_evidence[item_id])],
            "checker_commands": ["uv run python fixture.py --root ."],
        }
        for item_id in review_local_item_ids
    ]
    review_items.append(
        {
            "id": "phase_c_function_process_elf_attribution",
            "review_section": "fixture",
            "requirement": "fixture dynamic mapping review requirement",
            "status": "BLOCKED_BOARD_DYNAMIC_MAPPING_CASES",
            "evidence": [
                review_evidence(
                    "phase_c_function_process_elf_attribution",
                    "results/evaluation/genesys2-cva6/current/dynamic_mapping_attribution_summary.json",
                )
            ],
            "checker_commands": ["uv run python fixture.py --root ."],
        }
    )
    for item_id, external_id in review_external_pairs.items():
        state = intake_by_id[external_id]
        review_items.append(
            {
                "id": item_id,
                "review_section": "fixture",
                "requirement": "fixture external review requirement",
                "status": "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
                "external_id": external_id,
                "external_state": {
                    "completion_status": state.get("completion_status"),
                    "current_blocker": state.get("current_blocker"),
                    "external_summary_path": state.get("external_summary_path"),
                    "external_summary_exists": state.get("external_summary_exists"),
                    "completion_evidence_valid": state.get("completion_evidence_valid"),
                },
                "evidence": [review_evidence(item_id, "results/evaluation/genesys2-cva6/current/external_closure_intake.json")],
                "checker_commands": ["uv run python fixture.py --root ."],
            }
        )
    review_items.append(
        {
            "id": "phase_g_real_malware_validation",
            "review_section": "fixture",
            "requirement": "fixture real malware exclusion",
            "status": "EXCLUDED_BY_OBJECTIVE",
            "evidence": [review_evidence("phase_g_real_malware_validation", "results/evaluation/genesys2-cva6/current/real_malware_containment.json")],
            "checker_commands": ["uv run python fixture.py --root ."],
        }
    )
    write_json(
        current / "review_closure_audit.json",
        {
            "schema": SUMMARY_SCHEMAS["review_closure_audit.json"],
            "status": "PASS",
            "closure_status": "PASS_LOCAL_SCOPE_EXTERNAL_AND_BOARD_DYNAMIC_OPEN",
            "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
            "summary": {
                "local_item_count": 10,
                "local_items_evidence_present": True,
                "blocked_item_count": 1,
                "blocked_item_ids": ["phase_c_function_process_elf_attribution"],
                "blocked_items_evidence_present": True,
                "open_external_item_count": 4,
                "open_external_ids": sorted(review_external_pairs.values()),
                "excluded_item_count": 1,
                "objective_exclusions": ["real_malware_validation"],
            },
            "claim_boundary": {
                "real_malware_validation_claimed": False,
                "real_malware_validation_excluded_by_objective": True,
                "external_readiness_substituted_for_completion": False,
                "local_linux_benign_substituted_for_board_benign": False,
                "bounded_prefix_substituted_for_full_strings": False,
                "toolchain_probe_substituted_for_board_native_dwarf": False,
            },
            "items": review_items,
            "validation_commands": ["uv run python tools/check_genesys2_review_closure_audit.py --root ."],
        },
    )
    touch(
        root / "docs/07-evaluation-evidence/reports/ccfa_review_closure_audit.md",
        (
            "Status: `PASS_LOCAL_SCOPE_EXTERNAL_AND_BOARD_DYNAMIC_OPEN`\n"
            "## Remaining Non-Real External Items\n"
            "board_native_dwarf_source_lines\n"
            "full_hardware_pointer_strings\n"
            "genesys2_board_benign_control\n"
            "production_streaming_dma_trace_sink\n"
            "real malware validation\n"
        ),
    )
    write_json(
        current / "reproducibility_manifest.json",
        {
            "schema": SUMMARY_SCHEMAS["reproducibility_manifest.json"],
            "status": "PASS",
            "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
            "claim_boundary": {
                "controlled_safe_surrogate_evidence": True,
                "real_malware_validation_claimed": False,
                "hardware_full_pointer_strings_claimed": False,
                "production_streaming_dma_throughput_claimed": False,
            },
            "summary_artifacts": [
                {"id": "latest_manifest"},
                {"id": "hardware_pointer_prefixes"},
                {"id": "ccfa_evaluation_matrix"},
                {"id": "behavior_audit_metrics"},
                {"id": "statistical_robustness"},
                {"id": "case_study_manifest"},
                {"id": "review_closure_audit"},
                {"id": "external_closure_intake"},
                {"id": "external_closure_plan"},
                {"id": "external_closure_preflight"},
                {"id": "external_operator_packet"},
            ],
            "raw_artifact_roots": [
                {"id": "p0_bram_repetitions"},
                {"id": "safe_surrogate_bram_repetitions"},
                {"id": "pointer_snapshot_bram"},
            ],
            "validation_commands": ["uv run python tools/run_check_suite.py --suite genesys2-current"],
        },
    )
    artifact_files = [
        "tools/reproduce_genesys2_current.py",
        "tools/check_genesys2_artifact_package.py",
        "tools/package_genesys2_artifact_package.py",
        "tools/check_ccfa_current_quality.py",
        "tools/package_genesys2_reproducibility_manifest.py",
        "tools/check_genesys2_reproducibility_manifest.py",
        "tools/package_genesys2_statistical_robustness.py",
        "tools/check_genesys2_statistical_robustness.py",
        "tools/package_ccfa_case_study_manifest.py",
        "tools/check_ccfa_case_study_manifest.py",
        "tools/package_genesys2_external_closure_intake.py",
        "tools/check_genesys2_external_closure_intake.py",
        "tools/package_genesys2_external_closure_plan.py",
        "tools/check_genesys2_external_closure_plan.py",
        "tools/package_genesys2_external_closure_preflight.py",
        "tools/check_genesys2_external_closure_preflight.py",
        "tools/prepare_genesys2_external_summary.py",
        "tools/package_genesys2_external_operator_packet.py",
        "tools/check_genesys2_external_operator_packet.py",
        "tools/package_genesys2_review_closure_audit.py",
        "tools/check_genesys2_review_closure_audit.py",
        "results/evaluation/genesys2-cva6/current/review_closure_audit.json",
        "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json",
        "results/evaluation/genesys2-cva6/current/external_closure_preflight.json",
        "results/evaluation/genesys2-cva6/current/external_operator_packet.json",
        "docs/07-evaluation-evidence/reports/ccfa_external_operator_packet.md",
        "docs/07-evaluation-evidence/reports/ccfa_review_closure_audit.md",
        "docs/07-evaluation-evidence/reports/ccfa_readiness_matrix.md",
    ]
    for path_value in artifact_files:
        path = root / path_value
        if not path.is_file():
            touch(path, "fixture\n")
    planning_fixture = (
        "baseline board bring-up and Phase 5.3 minimal trace validation evidence are current.\n"
        "Remaining external boundaries: board-native DWARF/source-line, full hardware pointer strings, "
        "production streaming/DMA, and board benign-control.\n"
    )
    for relative in PLANNING_DOCS:
        touch(root / relative, planning_fixture)
    write_json(
        current / "artifact_package_manifest.json",
        {
            "schema": SUMMARY_SCHEMAS["artifact_package_manifest.json"],
            "status": "PASS",
            "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
            "generated_from": "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json",
            "fresh_clone_reproduction": {
                "script": "tools/reproduce_genesys2_current.py",
                "quick_command": "uv run python tools/reproduce_genesys2_current.py --quick",
                "full_command": "uv run python tools/reproduce_genesys2_current.py --full",
                "requires_board_or_vivado": False,
                "requires_network": False,
            },
            "included_files": [
                {
                    "path": path_value,
                    "exists": True,
                    "sha256": sha256_file(root / path_value),
                }
                for path_value in artifact_files
            ],
            "referenced_raw_artifact_roots": [
                {
                    "id": raw_id,
                    "path": "fixture_artifacts",
                    "exists": True,
                    "file_counts": {"logs": 1},
                    "release_policy": "referenced-by-manifest; raw board artifacts are not copied into this lightweight package",
                }
                for raw_id in ("p0_bram_repetitions", "safe_surrogate_bram_repetitions", "pointer_snapshot_bram")
            ],
            "validation_commands": [
                "uv run python tools/check_genesys2_artifact_package.py --root .",
                "uv run python tools/reproduce_genesys2_current.py --quick",
                "uv run python tools/reproduce_genesys2_current.py --full --dry-run",
            ],
            "claim_boundary": {
                "fresh_clone_reproduction_script_available": True,
                "lightweight_manifest_package": True,
                "raw_board_artifacts_copied": False,
                "real_malware_validation_claimed": False,
            },
        },
    )
    return current
