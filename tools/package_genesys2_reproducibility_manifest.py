from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    repo_rel_from,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "reproducibility_manifest.json"

SUMMARY_ARTIFACTS = [
    ("latest_manifest", "latest_manifest.json", "uv run python tools/check_genesys2_latest_standard.py --root ."),
    ("trace_sink", "trace_sink_summary.json", "uv run python tools/check_genesys2_bram_trace_sink.py --root ."),
    ("safe_surrogate_bram_trace", "safe_surrogate_bram_trace_summary.json", "uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root ."),
    ("p0_bram_trace", "p0_bram_trace_summary.json", "uv run python tools/check_genesys2_p0_bram_trace.py --root ."),
    ("strict_sret_board_smoke", "strict_sret_board_smoke_summary.json", "uv run python tools/check_genesys2_strict_sret_board_smoke.py --root ."),
    ("drop_accounting", "drop_accounting_summary.json", "uv run python tools/check_trace_drop_accounting.py --root ."),
    ("statistical_robustness", "statistical_robustness_summary.json", "uv run python tools/check_genesys2_statistical_robustness.py --root ."),
    ("streaming_dma_target", "streaming_dma_target_summary.json", "uv run python tools/check_genesys2_streaming_dma_target.py --root ."),
    ("streaming_dma_readiness", "streaming_dma_readiness_summary.json", "uv run python tools/check_genesys2_streaming_dma_readiness.py --root ."),
    ("pointer_snapshot_guardrails", "pointer_snapshot_guardrails.json", "uv run python tools/check_pointer_snapshot_guardrails.py --root ."),
    ("hardware_pointer_prefixes", "hardware_pointer_prefix_summary.json", "uv run python tools/check_hardware_pointer_prefixes.py --root ."),
    ("pointer_string_readiness", "pointer_string_readiness_summary.json", "uv run python tools/check_genesys2_pointer_string_readiness.py --root ."),
    ("benign_control", "benign_control_summary.json", "uv run python tools/check_benign_control_summary.py --root ."),
    ("board_benign_readiness", "board_benign_readiness_summary.json", "uv run python tools/check_genesys2_board_benign_readiness.py --root ."),
    ("production_runtime_benchmark", "production_runtime_benchmark.json", "uv run python tools/check_ccfa_current_quality.py --root ."),
    ("semantic_reconstruction", "semantic_reconstruction_summary.json", "uv run python tools/check_syscall_semantic_reconstruction.py --root ."),
    ("semantic_provenance", "semantic_provenance_summary.json", "uv run python tools/check_genesys2_semantic_provenance.py --root ."),
    ("fd_path_graph", "fd_path_graph_summary.json", "uv run python tools/check_fd_path_graph.py --root ."),
    ("source_line_attribution", "source_line_attribution_summary.json", "uv run python tools/check_source_line_attribution.py --root ."),
    ("source_line_sidecar", "source_line_sidecar.json", "uv run python tools/check_source_line_attribution.py --root ."),
    ("source_line_toolchain_probe", "source_line_toolchain_probe.json", "uv run python tools/check_source_line_toolchain_probe.py --root ."),
    ("debug_elf_readiness", "debug_elf_readiness_summary.json", "uv run python tools/check_genesys2_debug_elf_readiness.py --root ."),
    ("external_closure_readiness", "external_closure_readiness.json", "uv run python tools/check_genesys2_external_closure_readiness.py --root ."),
    ("external_closure_intake", "external_closure_intake.json", "uv run python tools/check_genesys2_external_closure_intake.py --root ."),
    ("external_closure_plan", "external_closure_plan.json", "uv run python tools/check_genesys2_external_closure_plan.py --root ."),
    ("external_closure_preflight", "external_closure_preflight.json", "uv run python tools/check_genesys2_external_closure_preflight.py --root ."),
    ("external_operator_packet", "external_operator_packet.json", "uv run python tools/check_genesys2_external_operator_packet.py --root ."),
    ("external_board_native_source_lines", "external_closure/board_native_source_lines_summary.json", "uv run python tools/check_genesys2_board_native_source_lines.py --root ."),
    ("external_hardware_pointer_strings", "external_closure/hardware_pointer_strings_summary.json", "uv run python tools/check_genesys2_hardware_pointer_strings.py --root ."),
    ("external_board_benign_control", "external_closure/board_benign_control_summary.json", "uv run python tools/check_genesys2_board_benign_control.py --root ."),
    ("external_template_board_native_source_lines", "external_closure_templates/board_native_source_lines_summary.template.json", "uv run python tools/prepare_genesys2_external_summary.py --check-templates"),
    ("external_template_hardware_pointer_strings", "external_closure_templates/hardware_pointer_strings_summary.template.json", "uv run python tools/prepare_genesys2_external_summary.py --check-templates"),
    ("external_template_streaming_dma_throughput", "external_closure_templates/streaming_dma_throughput_summary.template.json", "uv run python tools/prepare_genesys2_external_summary.py --check-templates"),
    ("external_template_board_benign_control", "external_closure_templates/board_benign_control_summary.template.json", "uv run python tools/prepare_genesys2_external_summary.py --check-templates"),
    ("process_elf_ownership", "process_elf_ownership_summary.json", "uv run python tools/check_process_elf_ownership.py --root ."),
    ("dynamic_mapping_attribution", "dynamic_mapping_attribution_summary.json", "uv run python tools/check_dynamic_mapping_attribution.py --root ."),
    ("ccfa_evaluation_matrix", "ccfa_evaluation_matrix.json", "uv run python tools/check_ccfa_evaluation_matrix.py --root ."),
    ("baseline_alignment", "baseline_alignment_summary.json", "uv run python tools/check_baseline_alignment.py --root ."),
    ("behavior_audit_metrics", "behavior_audit_metrics.json", "uv run python tools/check_behavior_audit_metrics.py --root ."),
    ("case_study_manifest", "case_study_manifest.json", "uv run python tools/check_ccfa_case_study_manifest.py --root ."),
    ("review_closure_audit", "review_closure_audit.json", "uv run python tools/check_genesys2_review_closure_audit.py --root ."),
    ("real_malware_containment", "real_malware_containment.json", "uv run python tools/check_real_malware_containment.py --root ."),
    ("cycle_counter_smoke", "cycle_counter_smoke_summary.json", "uv run python tools/check_genesys2_cycle_counter_smoke.py --root ."),
    ("cycle_source_probe", "cycle_source_probe_summary.json", "uv run python tools/check_genesys2_cycle_source_probe.py --root ."),
    ("counter_access_matrix", "counter_access_matrix_summary.json", "uv run python tools/check_genesys2_counter_access_matrix.py --root ."),
    ("cycle_source_diagnostics", "cycle_source_diagnostics_summary.json", "uv run python tools/check_genesys2_cycle_diagnostics.py --root ."),
    ("sdcard_linux_manifest", "sdcard_linux_manifest.json", "uv run python tools/check_genesys2_sdcard_linux_manifest.py --root ."),
    ("live_kernel_config_export", "live_kernel_config_export_summary.json", "uv run python tools/check_genesys2_live_kernel_config_export.py --root ."),
    ("sdcard_write_preflight", "sdcard_write_preflight_summary.json", "uv run python tools/check_genesys2_sdcard_write_preflight.py --root ."),
    ("linux_counter_path_preflight", "linux_counter_path_preflight.json", "uv run python tools/check_genesys2_linux_counter_path_preflight.py --root ."),
    ("host_vivado_check", "host_vivado_check_summary.json", "uv run python tools/check_ndss_host_vivado_check.py --root ."),
    ("trace_marker_programming", "trace_marker_programming_summary.json", "uv run python tools/check_genesys2_trace_marker_programming.py --root ."),
    ("host_latex_build", "host_latex_build_summary.json", "uv run python tools/check_ndss_host_latex_build.py --root ."),
    ("official_image_capability_matrix", "official_image_capability_matrix.json", "uv run python tools/check_genesys2_official_image_capability_matrix.py --root ."),
    ("official_image_workloads", "official_image_workload_summary.json", "uv run python tools/check_genesys2_official_image_workloads.py --root ."),
    ("official_image_runtime_map", "official_image_runtime_map_summary.json", "uv run python tools/check_genesys2_official_image_runtime_map.py --root ."),
    ("official_image_fork_exec_ownership", "official_image_fork_exec_ownership_summary.json", "uv run python tools/check_genesys2_fork_exec_ownership.py --root ."),
    ("official_image_aslr_pie", "official_image_aslr_pie_summary.json", "uv run python tools/check_genesys2_aslr_pie_probe.py --root ."),
    ("official_image_repeatability", "official_image_repeatability_summary.json", "uv run python tools/check_genesys2_board_repeatability.py --root ."),
    ("official_image_hardware_oracle_differential", "official_image_hardware_oracle_differential_summary.json", "uv run python tools/check_genesys2_hardware_oracle_differential.py --root ."),
    ("trace_correctness_directed", "trace_correctness_directed_summary.json", "uv run python tools/check_trace_correctness_directed.py --root ."),
    ("tracer_visibility_baseline", "tracer_visibility_baseline_summary.json", "uv run python tools/check_genesys2_tracer_visibility_baseline.py --root ."),
]

RAW_ROOT_PATTERNS = {
    "p0_bram_repetitions": {
        "bram_records": "*/*/bram_records.jsonl",
        "capture_logs": "*/*/capture.log",
        "uart_logs": "*/*/uart.log",
    },
    "safe_surrogate_bram_repetitions": {
        "bram_records": "*/*/bram_records.jsonl",
        "capture_logs": "*/*/capture.log",
        "uart_logs": "*/*/uart.log",
    },
    "pointer_snapshot_bram": {
        "bram_records": "*/*/bram_records.jsonl",
        "capture_logs": "*/*/capture.log",
        "uart_logs": "*/*/uart.log",
    },
    "p0_continuous_trace": {
        "decoded_traces": "*/trace.jsonl",
        "trace_summaries": "*/trace_summary.json",
        "uart_logs": "*/uart_run.log",
    },
    "safe_surrogate_runtime_map": {
        "runtime_process_maps": "*/runtime_process_map.json",
        "helper_logs": "*/runtime_process_map_helper.log",
    },
    "production_runtime_benchmark": {
        "program_logs": "**/uart.log",
    },
}
TEMPLATE_SUMMARY_IDS = {
    "external_template_board_native_source_lines",
    "external_template_hardware_pointer_strings",
    "external_template_streaming_dma_throughput",
    "external_template_board_benign_control",
}
TRUTHFUL_NONPASS_SUMMARY_IDS = {
    "external_closure_intake",
    "dynamic_mapping_attribution",
    "cycle_counter_smoke",
    "cycle_source_probe",
    "counter_access_matrix",
    "cycle_source_diagnostics",
    "live_kernel_config_export",
    "sdcard_write_preflight",
    "linux_counter_path_preflight",
    "official_image_workloads",
    "official_image_fork_exec_ownership",
    "official_image_aslr_pie",
    "official_image_repeatability",
    "official_image_hardware_oracle_differential",
}
TRUTHFUL_NONPASS_STATUSES = {
    "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED",
    "BLOCKED_BOARD_DYNAMIC_MAPPING_CASES",
    "BLOCKED_BOARD_RDCYCLE_UNAVAILABLE",
    "BLOCKED_BOARD_KERNEL_PERF_CYCLES_UNAVAILABLE",
    "BLOCKED_BOARD_CYCLE_COUNTER_UNAVAILABLE_NONCYCLE_TIME_AVAILABLE",
    "BLOCKED_BOARD_COUNTER_SOURCES_UNAVAILABLE",
    "BLOCKED_BOARD_KERNEL_PMU_AND_USER_CYCLE_UNAVAILABLE",
    "BLOCKED_LIVE_KERNEL_CONFIG_UNAVAILABLE",
    "BLOCKED_LIVE_KERNEL_CONFIG_COUNTER_OPTIONS_MISSING",
    "BLOCKED_SDCARD_IMAGE_MISSING",
    "BLOCKED_SDCARD_IMAGE_HASH_MISMATCH",
    "BLOCKED_HOST_DISK_ENUMERATION_UNAVAILABLE",
    "BLOCKED_NO_SAFE_SDCARD_TARGET",
    "BLOCKED_SDCARD_WRITE_TARGET_NOT_SELECTED",
    "BLOCKED_SDCARD_WRITE_TARGET_NOT_FOUND",
    "BLOCKED_SDCARD_WRITE_TARGET_UNSAFE",
    "BLOCKED_SD_CARD_LINUX_SOURCE_MISSING",
    "BLOCKED_BOARD_COUNTER_SOURCE_UNAVAILABLE_AFTER_REBUILD_PREFLIGHT",
    "BLOCKED_OFFICIAL_WORKLOAD_CORE_RING_DEPTH_INSUFFICIENT",
    "BLOCKED_FORK_EXEC_RUNTIME_CAPTURE_INCOMPLETE",
    "BLOCKED_TRACE_PID_TGID_NOT_EXPOSED_IN_BRAM_RECORDS",
    "BLOCKED_DYNAMIC_PIE_RUNTIME_UNAVAILABLE",
    "BLOCKED_DYNAMIC_PIE_BASE_NOT_RANDOMIZED",
    "BLOCKED_STATIC_EXEC_BASELINE_INCOMPLETE",
    "BLOCKED_OFFICIAL_WORKLOAD_REPEATABILITY_LIMITED_BY_BRAM_RING_DEPTH",
    "BLOCKED_OFFICIAL_WORKLOAD_REPEATABILITY_INCOMPLETE",
    "BLOCKED_QEMU_ORACLE_UNAVAILABLE",
    "BLOCKED_HARDWARE_ORACLE_ALIGNMENT_INCOMPLETE",
}
LOCAL_PASS_STATUSES_BY_ID = {
    "host_vivado_check": {"PASS_HOST_VIVADO_PREFLIGHT"},
    "trace_marker_programming": {"PASS_TRACE_MARKER_PROGRAMMED"},
    "tracer_visibility_baseline": {"PASS_LOCAL_SOFTWARE_TRACER_BASELINE"},
}


repo_rel = repo_rel_from(ROOT)


def artifact_row(current_root: Path, artifact_id: str, filename: str, checker: str) -> dict[str, Any]:
    path = current_root / filename
    data = load_json(path)
    return {
        "id": artifact_id,
        "path": repo_rel(path),
        "sha256": sha256_file(path),
        "schema": data.get("schema"),
        "status": data.get("status"),
        "checker_command": checker,
    }


def external_summary_accepted(current_root: Path, record_id: str) -> bool:
    path = current_root / "external_closure_intake.json"
    if not path.is_file():
        return False
    try:
        intake = load_json(path)
    except Exception:
        return False
    records = intake.get("records")
    if not isinstance(records, list):
        return False
    for row in records:
        if not isinstance(row, dict) or row.get("id") != record_id:
            continue
        return row.get("completion_status") == "EXTERNAL_SUMMARY_ACCEPTED" and row.get("completion_evidence_valid") is True
    return False


def count_glob(root: Path, pattern: str) -> int:
    return sum(1 for path in root.glob(pattern) if path.is_file())


def raw_root_rows(latest: dict[str, Any]) -> list[dict[str, Any]]:
    active_roots = latest.get("active_run_roots") if isinstance(latest.get("active_run_roots"), dict) else {}
    rows: list[dict[str, Any]] = []
    for root_id, patterns in RAW_ROOT_PATTERNS.items():
        value = active_roots.get(root_id)
        if not isinstance(value, str) or not value:
            rows.append({"id": root_id, "path": None, "exists": False, "file_counts": {}})
            continue
        path = ROOT / value
        rows.append(
            {
                "id": root_id,
                "path": value,
                "exists": path.is_dir(),
                "file_counts": {name: count_glob(path, pattern) for name, pattern in patterns.items()},
                "glob_patterns": patterns,
            }
        )
    return rows


def report_rows() -> list[dict[str, Any]]:
    return [
        {
            "id": "baseline_pass_criteria_current_status",
            "report": "docs/03-platform-architecture/genesys2/baseline_pass_criteria.md",
            "source_summary_ids": ["latest_manifest"],
            "raw_root_ids": [],
            "checker_commands": [
                "uv run python tools/check_baseline_pass_criteria.py --root .",
            ],
        },
        {
            "id": "readiness_claim_gates",
            "report": "docs/07-evaluation-evidence/reports/ccfa_readiness_matrix.md",
            "source_summary_ids": [
                "latest_manifest",
                "p0_bram_trace",
                "safe_surrogate_bram_trace",
                "statistical_robustness",
                "streaming_dma_target",
                "streaming_dma_readiness",
                "cycle_counter_smoke",
                "cycle_source_probe",
                "counter_access_matrix",
                "cycle_source_diagnostics",
                "sdcard_linux_manifest",
                "sdcard_write_preflight",
                "linux_counter_path_preflight",
                "pointer_snapshot_guardrails",
                "hardware_pointer_prefixes",
                "pointer_string_readiness",
                "benign_control",
                "board_benign_readiness",
                "drop_accounting",
                "semantic_reconstruction",
                "semantic_provenance",
                "fd_path_graph",
                "source_line_attribution",
                "source_line_toolchain_probe",
                "debug_elf_readiness",
                "external_closure_readiness",
                "external_closure_intake",
                "external_closure_plan",
                "external_closure_preflight",
                "external_operator_packet",
                "external_board_native_source_lines",
                "external_hardware_pointer_strings",
                "external_board_benign_control",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "external_template_board_benign_control",
                "process_elf_ownership",
                "ccfa_evaluation_matrix",
                "behavior_audit_metrics",
                "case_study_manifest",
                "statistical_robustness",
            ],
            "raw_root_ids": [
                "p0_bram_repetitions",
                "safe_surrogate_bram_repetitions",
                "pointer_snapshot_bram",
                "p0_continuous_trace",
                "safe_surrogate_runtime_map",
            ],
            "checker_commands": [
                "uv run python tools/run_check_suite.py --suite genesys2-current",
                "uv run python tools/check_ccfa_claim_boundaries.py --root .",
                "uv run python tools/check_source_line_toolchain_probe.py --root .",
                "uv run python tools/check_genesys2_debug_elf_readiness.py --root .",
                "uv run python tools/check_ccfa_case_study_manifest.py --root .",
                "uv run python tools/check_genesys2_board_benign_readiness.py --root .",
                "uv run python tools/check_genesys2_statistical_robustness.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
                "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                "uv run python tools/check_genesys2_hardware_pointer_strings.py --root .",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
            ],
        },
        {
            "id": "next_closure_completed_items",
            "report": "docs/07-evaluation-evidence/reports/ccfa_next_closure_plan.md",
            "source_summary_ids": [
                "latest_manifest",
                "p0_bram_trace",
                "safe_surrogate_bram_trace",
                "statistical_robustness",
                "streaming_dma_target",
                "streaming_dma_readiness",
                "pointer_snapshot_guardrails",
                "hardware_pointer_prefixes",
                "pointer_string_readiness",
                "benign_control",
                "board_benign_readiness",
                "case_study_manifest",
                "production_runtime_benchmark",
                "external_closure_plan",
                "external_closure_preflight",
                "external_operator_packet",
                "external_board_native_source_lines",
                "external_hardware_pointer_strings",
                "external_board_benign_control",
                "debug_elf_readiness",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "external_template_board_benign_control",
            ],
            "raw_root_ids": ["p0_bram_repetitions", "safe_surrogate_bram_repetitions", "pointer_snapshot_bram", "production_runtime_benchmark"],
            "checker_commands": [
                "uv run python tools/check_hardware_pointer_prefixes.py --root .",
                "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                "uv run python tools/check_ccfa_case_study_manifest.py --root .",
                "uv run python tools/check_ccfa_current_quality.py --root .",
                "uv run python tools/check_genesys2_statistical_robustness.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
                "uv run python tools/check_genesys2_debug_elf_readiness.py --root .",
                "uv run python tools/check_genesys2_board_benign_readiness.py --root .",
                "uv run python tools/check_genesys2_hardware_pointer_strings.py --root .",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
            ],
        },
        {
            "id": "evaluation_plan_current_status",
            "report": "docs/07-evaluation-evidence/evaluation_plan.md",
            "source_summary_ids": [
                "ccfa_evaluation_matrix",
                "baseline_alignment",
                "behavior_audit_metrics",
                "case_study_manifest",
                "statistical_robustness",
                "streaming_dma_target",
                "streaming_dma_readiness",
                "cycle_counter_smoke",
                "cycle_source_probe",
                "counter_access_matrix",
                "cycle_source_diagnostics",
                "sdcard_linux_manifest",
                "sdcard_write_preflight",
                "linux_counter_path_preflight",
                "pointer_string_readiness",
                "production_runtime_benchmark",
                "latest_manifest",
                "external_closure_readiness",
                "external_closure_intake",
                "external_closure_plan",
                "external_closure_preflight",
                "external_operator_packet",
                "board_benign_readiness",
                "external_board_native_source_lines",
                "external_hardware_pointer_strings",
                "external_board_benign_control",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "external_template_board_benign_control",
            ],
            "raw_root_ids": [
                "p0_bram_repetitions",
                "safe_surrogate_bram_repetitions",
                "pointer_snapshot_bram",
                "production_runtime_benchmark",
            ],
            "checker_commands": [
                "uv run python tools/check_evaluation_plan.py --root .",
                "uv run python tools/check_ccfa_evaluation_matrix.py --root .",
                "uv run python tools/check_baseline_alignment.py --root .",
                "uv run python tools/check_genesys2_statistical_robustness.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
                "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                "uv run python tools/check_genesys2_hardware_pointer_strings.py --root .",
                "uv run python tools/check_genesys2_board_benign_readiness.py --root .",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
            ],
        },
        {
            "id": "review_closure_audit",
            "report": "docs/07-evaluation-evidence/reports/ccfa_review_closure_audit.md",
            "source_summary_ids": [
                "review_closure_audit",
                "latest_manifest",
                "external_closure_readiness",
                "external_closure_intake",
                "external_closure_plan",
                "external_closure_preflight",
                "external_operator_packet",
                "external_board_native_source_lines",
                "external_hardware_pointer_strings",
                "external_board_benign_control",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "streaming_dma_target",
                "streaming_dma_readiness",
                "pointer_string_readiness",
                "external_template_board_benign_control",
                "board_benign_readiness",
            ],
            "raw_root_ids": [],
            "checker_commands": [
                "uv run python tools/package_genesys2_review_closure_audit.py",
                "uv run python tools/check_genesys2_review_closure_audit.py --root .",
                "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                "uv run python tools/check_genesys2_hardware_pointer_strings.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
            ],
        },
        {
            "id": "external_operator_packet_handoff",
            "report": "docs/07-evaluation-evidence/reports/ccfa_external_operator_packet.md",
            "source_summary_ids": [
                "external_operator_packet",
                "external_closure_readiness",
                "external_closure_intake",
                "external_closure_plan",
                "external_closure_preflight",
                "external_board_native_source_lines",
                "external_hardware_pointer_strings",
                "external_board_benign_control",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "external_template_board_benign_control",
            ],
            "raw_root_ids": [],
            "checker_commands": [
                "uv run python tools/package_genesys2_external_operator_packet.py",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/check_genesys2_external_closure_intake.py --root .",
                "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
            ],
        },
        {
            "id": "p0_evidence_chain",
            "report": "docs/07-evaluation-evidence/reports/genesys2_cva6_evidence_chain_20260611.md",
            "source_summary_ids": [
                "p0_bram_trace",
                "trace_sink",
                "safe_surrogate_bram_trace",
                "drop_accounting",
                "statistical_robustness",
                "streaming_dma_target",
                "streaming_dma_readiness",
                "pointer_string_readiness",
                "external_operator_packet",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "external_template_board_benign_control",
            ],
            "raw_root_ids": ["p0_bram_repetitions", "safe_surrogate_bram_repetitions", "p0_continuous_trace"],
            "checker_commands": [
                "uv run python tools/check_genesys2_p0_bram_trace.py --root .",
                "uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .",
                "uv run python tools/check_genesys2_statistical_robustness.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
                "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
            ],
        },
    ]


def package_manifest(current_root: Path) -> dict[str, Any]:
    latest = load_json(current_root / "latest_manifest.json")
    board_native_source_lines_accepted = external_summary_accepted(current_root, "board_native_dwarf_source_lines")
    board_benign_control_accepted = external_summary_accepted(current_root, "genesys2_board_benign_control")
    full_hardware_pointer_strings_accepted = external_summary_accepted(current_root, "full_hardware_pointer_strings")
    summary_rows = [artifact_row(current_root, artifact_id, filename, checker) for artifact_id, filename, checker in SUMMARY_ARTIFACTS]
    raw_rows = raw_root_rows(latest)
    status = "PASS"
    if latest.get("status") != "PASS":
        status = "FAIL"
    if any(
        row.get("status") != "PASS"
        and row.get("status") not in LOCAL_PASS_STATUSES_BY_ID.get(str(row.get("id")), set())
        for row in summary_rows
        if row.get("id") not in {"source_line_sidecar", *TEMPLATE_SUMMARY_IDS, *TRUTHFUL_NONPASS_SUMMARY_IDS}
    ):
        status = "FAIL"
    for row in summary_rows:
        if row.get("id") in TRUTHFUL_NONPASS_SUMMARY_IDS and row.get("status") not in {"PASS", *TRUTHFUL_NONPASS_STATUSES}:
            status = "FAIL"
    if any(row.get("status") != "TEMPLATE_NOT_EVIDENCE" for row in summary_rows if row.get("id") in TEMPLATE_SUMMARY_IDS):
        status = "FAIL"
    if any(row.get("exists") is not True for row in raw_rows):
        status = "FAIL"
    if any(not any(int(count) > 0 for count in row.get("file_counts", {}).values()) for row in raw_rows):
        status = "FAIL"
    return {
        "schema": "rvmt.genesys2.reproducibility_manifest.v1",
        "status": status,
        "canonical_evaluation_root": repo_rel(current_root),
        "latest_manifest": repo_rel(current_root / "latest_manifest.json"),
        "claim_boundary": {
            "controlled_safe_surrogate_evidence": True,
            "real_malware_validation_claimed": False,
            "hardware_full_pointer_strings_claimed": full_hardware_pointer_strings_accepted,
            "production_streaming_dma_throughput_claimed": False,
            "board_native_source_line_attribution_claimed": False,
            "genesys2_board_benign_control_claimed": False,
            "external_board_native_source_line_summary_accepted": board_native_source_lines_accepted,
            "external_genesys2_board_benign_control_summary_accepted": board_benign_control_accepted,
            "external_full_hardware_pointer_strings_summary_accepted": full_hardware_pointer_strings_accepted,
            "debug_toolchain_source_line_probe_available": True,
            "debug_no_pie_elf_readiness_available": True,
            "board_benign_readiness_available": True,
            "streaming_dma_readiness_available": True,
            "pointer_string_readiness_available": True,
            "dated_roots_are_provenance_only": True,
        },
        "summary_artifacts": summary_rows,
        "raw_artifact_roots": raw_rows,
        "report_rows": report_rows(),
        "validation_commands": [
            "uv run python tools/run_check_suite.py --suite genesys2-current",
            "uv run python tools/run_check_suite.py --suite genesys2-artifacts",
            "uv run python tools/run_check_suite.py --suite genesys2-self-test",
            "uv run python tools/run_check_suite.py --suite ccfa-gate-self-test",
        ],
        "non_claims": [
            "This manifest ties existing controlled board artifacts and summaries to checker commands; it does not add real-malware validation.",
            "Raw dated board directories are provenance and are selected only through current/latest_manifest.json.",
            "Full hardware pointer strings are claimed only when the external intake accepts the artifact-backed full_hardware_pointer_strings summary; pointer readiness and companion strings are not substitutes.",
            "The pointer string readiness summary prepares future gap-free hardware full-string collection but does not complete full hardware pointer-string evidence by itself.",
            "The source-line toolchain probe does not make current board traces DWARF source-line attributed.",
            "The debug ELF readiness summary prepares debug/no-PIE rerun candidates but does not make current board traces DWARF source-line attributed.",
            "Board-native DWARF source-line attribution is claimed only when the external intake accepts the artifact-backed board_native_dwarf_source_lines summary; sidecars and toolchain probes are not substitutes.",
            "The board benign readiness summary itself does not complete board benign false-positive evidence; Genesys2 board benign-control evidence is claimed only when the external intake accepts the artifact-backed genesys2_board_benign_control summary.",
            "The streaming/DMA readiness summary prepares future non-BRAM transport collection but does not complete production streaming/DMA throughput evidence.",
            "The external closure readiness contract records remaining non-real-malware blockers but does not complete them.",
            "The external closure intake gate validates optional future external summaries but remains open until board/RTL summaries are present.",
            "The external closure plan provides executable runbooks and templates but does not replace board/RTL execution.",
            "The external closure preflight proves only local scripts, dry-run hooks, schema paths, and guardrails are ready; it does not replace external execution.",
            "The external operator packet is an execution handoff and does not replace external board, RTL, host transport, or reviewer execution.",
            "The external summary templates are TEMPLATE_NOT_EVIDENCE scaffolding and must not be treated as accepted external summaries.",
            "The statistical robustness summary audits controlled repetitions and retained failures, but it does not make randomized workload or real-malware generalization claims.",
            "The streaming/DMA target summary is a cycle-normalized local target baseline only; it does not complete production streaming/DMA throughput evidence.",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        raw = root / "raw" / "p0"
        raw.mkdir(parents=True, exist_ok=True)
        for rel in (
            "sample/rep_01/bram_records.jsonl",
            "sample/rep_01/capture.log",
            "sample/rep_01/uart.log",
            "sample/trace.jsonl",
            "sample/trace_summary.json",
            "sample/uart_run.log",
            "sample/runtime_process_map.json",
            "sample/runtime_process_map_helper.log",
            "sample/mode/rep_01/uart.log",
        ):
            path = raw / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
        latest_roots = {key: "raw/p0" for key in RAW_ROOT_PATTERNS}
        write_json(current / "latest_manifest.json", {"schema": "rvmt.genesys2.latest_manifest.v1", "status": "PASS", "active_run_roots": latest_roots})
        for artifact_id, filename, _checker in SUMMARY_ARTIFACTS:
            path = current / filename
            if path.name == "latest_manifest.json":
                continue
            status = "TEMPLATE_NOT_EVIDENCE" if artifact_id in TEMPLATE_SUMMARY_IDS else "PASS"
            if artifact_id in LOCAL_PASS_STATUSES_BY_ID:
                status = sorted(LOCAL_PASS_STATUSES_BY_ID[artifact_id])[0]
            write_json(path, {"schema": f"rvmt.fixture.{path.stem}.v1", "status": status})
        old_root = globals()["ROOT"]
        try:
            globals()["ROOT"] = root
            manifest = package_manifest(current)
        finally:
            globals()["ROOT"] = old_root
    if manifest.get("status") != "PASS":
        print("[FAIL] expected reproducibility fixture to pass", file=sys.stderr)
        return 1
    if len(manifest.get("summary_artifacts", [])) != len(SUMMARY_ARTIFACTS):
        print("[FAIL] missing summary artifact rows", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 reproducibility manifest packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package current Genesys2/CVA6 reproducibility manifest.")
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    current_root = args.current_root
    try:
        manifest = package_manifest(current_root)
        write_json(args.out, manifest)
    except Exception as exc:
        print(f"package_genesys2_reproducibility_manifest: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{manifest['status']}] wrote Genesys2 reproducibility manifest to {args.out}")
    return 0 if manifest["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
