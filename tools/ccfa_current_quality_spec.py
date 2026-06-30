from __future__ import annotations

from pathlib import Path

DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")

UART_WALL_CLOCK_RUNTIME_METRIC = "wall_clock_ns_from_board_uart_date_markers"

SUMMARY_SCHEMAS = {
    "trace_sink_summary.json": "rvmt.genesys2.bram_trace_sink.v1",
    "safe_surrogate_bram_trace_summary.json": "rvmt.genesys2.safe_surrogate_bram_trace.v1",
    "p0_bram_trace_summary.json": "rvmt.genesys2.p0_bram_trace.v1",
    "drop_accounting_summary.json": "rvmt.trace_drop_accounting.v1",
    "statistical_robustness_summary.json": "rvmt.genesys2.statistical_robustness.v1",
    "streaming_dma_target_summary.json": "rvmt.genesys2.streaming_dma_target.v1",
    "pointer_snapshot_guardrails.json": "rvmt.pointer_snapshot_guardrails.v1",
    "hardware_pointer_prefix_summary.json": "rvmt.hardware_pointer_prefixes.v1",
    "benign_control_summary.json": "rvmt.genesys2.benign_control_summary.v1",
    "production_runtime_benchmark.json": "rvmt.genesys2.production_runtime_benchmark.v1",
    "semantic_reconstruction_summary.json": "rvmt.syscall_semantic_reconstruction.v1",
    "fd_path_graph_summary.json": "rvmt.fd_path_graph.v1",
    "source_line_attribution_summary.json": "rvmt.source_line_attribution.v1",
    "source_line_toolchain_probe.json": "rvmt.genesys2.source_line_toolchain_probe.v1",
    "process_elf_ownership_summary.json": "rvmt.process_elf_ownership.v1",
    "dynamic_mapping_attribution_summary.json": "rvmt.dynamic_mapping_attribution.v1",
    "ccfa_evaluation_matrix.json": "rvmt.ccfa_evaluation_matrix.v1",
    "baseline_alignment_summary.json": "rvmt.baseline_alignment.v1",
    "behavior_audit_metrics.json": "rvmt.behavior_audit_metrics.v1",
    "case_study_manifest.json": "rvmt.ccfa.case_study_manifest.v1",
    "review_closure_audit.json": "rvmt.genesys2.review_closure_audit.v1",
    "latest_manifest.json": "rvmt.genesys2.latest_manifest.v1",
    "reproducibility_manifest.json": "rvmt.genesys2.reproducibility_manifest.v1",
    "artifact_package_manifest.json": "rvmt.genesys2.artifact_package.v1",
    "external_closure_readiness.json": "rvmt.genesys2.external_closure_readiness.v1",
    "external_closure_intake.json": "rvmt.genesys2.external_closure_intake.v1",
    "external_closure_plan.json": "rvmt.genesys2.external_closure_plan.v1",
    "external_closure_preflight.json": "rvmt.genesys2.external_closure_preflight.v1",
    "external_operator_packet.json": "rvmt.genesys2.external_operator_packet.v1",
    "workload_manifest.json": "rvmt.ccfa.workload_manifest.v1",
    "resource_timing_summary.json": "rvmt.resource_timing_summary.v1",
}

EXPECTED_EXECVE_TARGETS = {
    "fork_exec": "/bin/true",
    "process_chain": "/bin/true",
}

EXPECTED_SAMPLE_SYSCALLS = {
    "dynamic_executable_memory": {"mmap", "mprotect", "munmap"},
    "anti_debug_like": {"clock_gettime", "ptrace", "openat", "read", "close"},
}

PLANNING_DOCS = (
    Path("docs/09-planning/two-week-plan.md"),
    Path("docs/09-planning/two-week-plan-2.md"),
    Path("docs/09-planning/diff-22.md"),
)

FORBIDDEN_PLANNING_TEXT = (
    "TODO(BOARD)",
    "TODO(SIM)",
    "TODO(HARNESS)",
    "board runtime 仍 TODO",
    "physical board evidence | clock/reset",
    "fuzz plan 和工具存在，但 case 仍是 TODO",
    "board physical clock/reset/UART/bare-metal 均未做",
)

REQUIRED_PLANNING_TEXT = (
    "baseline board bring-up",
    "board-native DWARF/source-line",
    "full hardware pointer strings",
    "production streaming/DMA",
    "board benign-control",
)
