from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
HOST_QEMU_STRACE_STATUS = "HOST_QEMU_STRACE_BASELINE_PASS_WITH_MISSING_ADVANCED_BASELINES"
SOFTWARE_INSTRUMENTATION_STATUS = "HOST_QEMU_STRACE_AND_SOFTWARE_INSTRUMENTATION_PASS_WITH_MISSING_EBPF_QEMU_PLUGIN"
SOFTWARE_INSTRUMENTATION_AND_EBPF_STATUS = "HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_AND_EBPF_PASS_WITH_MISSING_QEMU_PLUGIN"
SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS = "HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS"
ACCEPTED_BASELINE_STATUSES = {
    HOST_QEMU_STRACE_STATUS,
    SOFTWARE_INSTRUMENTATION_STATUS,
    SOFTWARE_INSTRUMENTATION_AND_EBPF_STATUS,
    SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS,
}
EXTENSION_PLAN_READY_STATUS = "READY_FOR_SYNTHETIC_EXTENSION_IMPLEMENTATION"
EXTENSION_SOURCE_IMPLEMENTED_STATUS = "IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING"
ACCEPTED_EXTENSION_STATUSES = {EXTENSION_PLAN_READY_STATUS, EXTENSION_SOURCE_IMPLEMENTED_STATUS}
EXTENSION_HOST_SMOKE_PASS_STATUS = "HOST_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED"
EXTENSION_HOST_SMOKE_BLOCKED_STATUS = "HOST_COMPILE_SMOKE_BLOCKED_CURRENT_ENVIRONMENT"
ACCEPTED_EXTENSION_HOST_SMOKE_STATUSES = {EXTENSION_HOST_SMOKE_PASS_STATUS, EXTENSION_HOST_SMOKE_BLOCKED_STATUS}
EXTENSION_TARGET_SMOKE_PASS_STATUS = "TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED"
EXTENSION_TARGET_SMOKE_BLOCKED_STATUS = "TARGET_COMPILE_SMOKE_BLOCKED_CURRENT_ENVIRONMENT"
ACCEPTED_EXTENSION_TARGET_SMOKE_STATUSES = {EXTENSION_TARGET_SMOKE_PASS_STATUS, EXTENSION_TARGET_SMOKE_BLOCKED_STATUS}
EXTENSION_BEHAVIOR_SMOKE_PASS_STATUS = "HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED"
EXTENSION_BEHAVIOR_SMOKE_BLOCKED_STATUS = "HOST_QEMU_BEHAVIOR_SMOKE_BLOCKED_CURRENT_ENVIRONMENT"
ACCEPTED_EXTENSION_BEHAVIOR_SMOKE_STATUSES = {EXTENSION_BEHAVIOR_SMOKE_PASS_STATUS, EXTENSION_BEHAVIOR_SMOKE_BLOCKED_STATUS}
EXTENSION_ENABLEMENT_PREFLIGHT_STATUS = "EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED"
POINTER_PREFLIGHT_STATUS = "SYNTHETIC_ARG_MEM_GUARDRAILS_PASS_SIDE_CHANNEL_CLOSURE_HARDWARE_POINTER_DEFERRED"
POINTER_SNAPSHOT_GATE_STATUS = "POINTER_SNAPSHOT_ENABLEMENT_GATES_RECORDED_NOT_ENABLED"
EVALUATION_TABLE_STATUS = "BOUNDED_EVALUATION_TABLE_READY_WITH_EBPF_AND_QEMU_PLUGIN"
QEMU_PLUGIN_BASELINE_STATUS = "QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES"
METRIC_COVERAGE_STATUS = "BOUNDED_METRIC_COVERAGE_READY_WITH_DEFERRED_FULL_ACCURACY"
THREAT_MODEL_STATUS = "TRUSTED_KERNEL_USER_MODE_THREAT_MODEL_BOUNDARY_SPECIFIED"
HARDWARE_TRACE_PROTOTYPE_STATUS = "HARDWARE_TRACE_PROTOTYPE_PASS_35T_SMALL_CAPACITY"
LOCAL_CODE_ANALYSIS_STATUS = "LOCAL_CODE_ANALYSIS_PROTOTYPE_PASS_WITH_BOUNDED_ATTRIBUTION"
MALWARE_BEHAVIOR_AUDIT_STATUS = "SYNTHETIC_MALWARE_LIKE_BEHAVIOR_AUDIT_PASS_REAL_MALWARE_DEFERRED"
EXPECTED_NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]
EXPECTED_MALWARE_SAMPLES = {
    "file_scan",
    "batch_open_read_write",
    "self_copy_sim",
    "abnormal_syscall_sequence",
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
    "anti_debug_like",
}
FORBIDDEN_POSITIVE_CLAIMS = [
    "real malware detector",
    "real malware detection accuracy",
    "validated CVA6",
    "CVA6 validation",
    "mature detector",
    "complete semantic reconstruction",
]


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def read_json(path: Path, failures: list[str], repo_root: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return {}
    try:
        return load_json(path)
    except Exception as exc:
        failures.append(f"invalid {label}: {rel(path, repo_root)}: {exc}")
        return {}


def read_text(path: Path, failures: list[str], repo_root: Path, label: str) -> str:
    if not path.exists():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return ""
    return path.read_text(encoding="utf-8")


def check_bool(checks: dict[str, bool], failures: list[str], prefix: str) -> None:
    for key, ok in checks.items():
        if not ok:
            failures.append(f"{prefix}: {key}")


def has_non_claims(value: dict[str, Any]) -> bool:
    text = "\n".join(str(item) for item in value.get("non_claims", []) if item)
    return all(item in text for item in EXPECTED_NON_CLAIMS)


def positive_forbidden_claims(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    negation_markers = (
        "no ",
        "not ",
        "does not",
        "do not",
        "cannot",
        "forbidden",
        "non-claim",
        "what this does not prove",
        "still deliberately not claimed",
        "without claiming",
        "wording that says or implies",
    )
    for phrase in FORBIDDEN_POSITIVE_CLAIMS:
        start = 0
        phrase_lower = phrase.lower()
        while True:
            index = lowered.find(phrase_lower, start)
            if index == -1:
                break
            context = lowered[max(0, index - 400) : min(len(lowered), index + len(phrase) + 120)]
            if not any(marker in context for marker in negation_markers):
                findings.append(phrase)
                break
            start = index + len(phrase)
    return findings


def fd_path_goal(fd_path: dict[str, Any], case_studies: dict[str, Any]) -> dict[str, Any]:
    flows = fd_path.get("flows", []) if isinstance(fd_path.get("flows"), list) else []
    closed_flows = [
        flow
        for flow in flows
        if isinstance(flow, dict) and flow.get("status") == "closed"
    ]
    source_types = {
        str(fd_path.get("selected_candidate", {}).get("source_type"))
        for _ in [None]
        if isinstance(fd_path.get("selected_candidate"), dict)
    }
    case_rows = case_studies.get("samples", {}) if isinstance(case_studies.get("samples"), dict) else {}
    checks = {
        "schema": fd_path.get("schema") == "rvmt.fd_path_flow.summary.v1",
        "status_pass": fd_path.get("status") == "PASS",
        "closed_flow": bool(closed_flows),
        "path_source_recorded": any(flow.get("path_source") for flow in closed_flows if isinstance(flow, dict)),
        "side_channel_or_semantic_source": bool(source_types & {"syscall_side_channel", "semantic_events"}),
        "case_studies_schema": case_studies.get("schema") == "rvmt.35t.fd_path_case_studies.v1",
        "case_studies_pass": case_studies.get("status") == "PASS",
        "case_studies_cover_required_samples": all(
            sample in case_rows and isinstance(case_rows.get(sample), dict) and case_rows[sample].get("status") == "PASS"
            for sample in ("file_scan", "batch_open_read_write", "self_copy_sim")
        ),
        "case_studies_side_channel_backed": all(
            isinstance(case_rows.get(sample), dict)
            and isinstance(case_rows[sample].get("selected_candidate"), dict)
            and case_rows[sample]["selected_candidate"].get("source_type") == "syscall_side_channel"
            for sample in ("file_scan", "batch_open_read_write", "self_copy_sim")
        ),
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    return {
        "id": "P1_fd_path_flow",
        "status": status,
        "checks": checks,
        "evidence": {
            "summary": "fd_path_flow_summary.json",
            "sample": fd_path.get("sample"),
            "closed_flow_count": len(closed_flows),
            "selected_candidate": fd_path.get("selected_candidate"),
            "case_studies": "fd_path_case_studies.json" if case_studies else None,
            "case_study_samples": sorted(case_rows),
        },
        "remaining_work": [
            "broaden from the three prioritized case-study samples to full-suite fd/path graph coverage",
            "keep trace-proven, inferred, and missing links separated",
        ],
    }


def process_tree_goal(process_tree: dict[str, Any], case_study: dict[str, Any]) -> dict[str, Any]:
    edges = process_tree.get("edges", []) if isinstance(process_tree.get("edges"), list) else []
    case_checks = case_study.get("checks", {}) if isinstance(case_study.get("checks"), dict) else {}
    checks = {
        "schema": process_tree.get("schema") == "rvmt.process_tree.summary.v1",
        "status_pass": process_tree.get("status") == "PASS",
        "closed_edge": bool(edges),
        "non_complete_parent_boundary": any(
            isinstance(edge, dict) and str(edge.get("parent_pid", "")).endswith("_unresolved") for edge in edges
        ),
        "case_study_schema": case_study.get("schema") == "rvmt.35t.process_tree_case_study.v1",
        "case_study_pass": case_study.get("status") == "PASS",
        "case_study_positive_child_pid": case_checks.get("positive_child_pid_recovered") is True,
        "case_study_exec_path": case_checks.get("execve_path_string_recovered") is True,
        "case_study_wait_pid": case_checks.get("parent_wait_pid_associated") is True,
        "case_study_graph": case_checks.get("parent_child_graph_output") is True,
        "case_study_side_channel_backed": case_checks.get("selected_from_board_side_channel") is True,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    return {
        "id": "P2_process_tree",
        "status": status,
        "checks": checks,
        "evidence": {
            "summary": "process_tree_summary.json",
            "sample": process_tree.get("sample"),
            "edge_count": len(edges),
            "case_study": "process_tree_case_study.json" if case_study else None,
        },
        "remaining_work": [
            "resolve target parent PID only when PID/SATP/ASID or equivalent runtime ownership evidence exists",
            "do not describe the representative graph as complete OS process ownership",
        ],
    }


def pointer_semantics_goal(
    routes: dict[str, Any],
    strategy: dict[str, Any],
    paper: dict[str, Any],
    pointer_preflight: dict[str, Any],
    pointer_snapshot_gate: dict[str, Any],
    pointer_design: dict[str, Any],
    threat_model: dict[str, Any],
    helper_alignment: dict[str, Any],
) -> dict[str, Any]:
    route_rows = routes.get("routes", []) if isinstance(routes.get("routes"), list) else []
    route_by_id = {str(row.get("id")): row for row in route_rows if isinstance(row, dict)}
    semantic = paper.get("semantic_closure", {}) if isinstance(paper.get("semantic_closure"), dict) else {}
    fd_path = semantic.get("fd_path", {}) if isinstance(semantic.get("fd_path"), dict) else {}
    process_tree = semantic.get("process_tree", {}) if isinstance(semantic.get("process_tree"), dict) else {}
    checks = {
        "routes_deferred": routes.get("status") == "DEFERRED_POST_FPGA",
        "trace_mem_default_none": routes.get("current_trace_mem_mode") == "TRACE_MEM_MODE_NONE",
        "selective_memory_route_present": "selective_memory_snapshot" in route_by_id,
        "helper_or_ebpf_route_present": "kernel_helper_metadata" in route_by_id and "ebpf_metadata_alignment" in route_by_id,
        "strategy_keeps_mvp_unblocked": strategy.get("current_mvp_policy") == "NO_EBPF_NO_KERNEL_HELPER_NO_MEMORY_SNAPSHOT",
        "side_channel_fd_path_closure_recorded": fd_path.get("status") == "PASS",
        "side_channel_process_closure_recorded": process_tree.get("status") == "PASS",
        "pointer_preflight_schema": pointer_preflight.get("schema") == "rvmt.35t.pointer_semantics_preflight.v1",
        "synthetic_arg_mem_guardrails_recorded": pointer_preflight.get("status") == POINTER_PREFLIGHT_STATUS,
        "hardware_pointer_snapshot_deferred": pointer_preflight.get("current_35t_pointer_semantics", {}).get("hardware_user_pointer_snapshot") == "DEFERRED"
        if isinstance(pointer_preflight.get("current_35t_pointer_semantics"), dict)
        else False,
        "pointer_snapshot_gate_schema": pointer_snapshot_gate.get("schema")
        == "rvmt.35t.pointer_snapshot_enablement_gate.check.v1",
        "pointer_snapshot_gate_recorded": pointer_snapshot_gate.get("status") == POINTER_SNAPSHOT_GATE_STATUS,
        "pointer_snapshot_gate_default_disabled": pointer_snapshot_gate.get("checks", {}).get(
            "current_policy_default_disabled"
        )
        is True
        if isinstance(pointer_snapshot_gate.get("checks"), dict)
        else False,
        "pointer_snapshot_gate_enablement_requirements": pointer_snapshot_gate.get("checks", {}).get(
            "all_required_requirements_present"
        )
        is True
        if isinstance(pointer_snapshot_gate.get("checks"), dict)
        else False,
        "pointer_snapshot_design_review_recorded": pointer_design.get("status")
        == "POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED",
        "pointer_design_default_disabled": pointer_design.get("checks", {}).get("current_policy_default_disabled") is True
        if isinstance(pointer_design.get("checks"), dict)
        else False,
        "threat_model_schema": threat_model.get("schema") == "rvmt.35t.threat_model_boundary.v1",
        "threat_model_ready": threat_model.get("status") == THREAT_MODEL_STATUS,
        "trusted_kernel_user_mode_boundary": (
            "linux_kernel" in set(threat_model.get("trusted_components", []))
            and "user_mode_malware_like_workload" in set(threat_model.get("in_scope", []))
            and "kernel_rootkit" in set(threat_model.get("out_of_scope", []))
        )
        if isinstance(threat_model.get("trusted_components"), list)
        and isinstance(threat_model.get("in_scope"), list)
        and isinstance(threat_model.get("out_of_scope"), list)
        else False,
        "trusted_helper_alignment_recorded": helper_alignment.get("status")
        == "TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL",
        "helper_alignment_preserves_hardware_pointer_deferral": "not a hardware user-pointer memory snapshot"
        in set(helper_alignment.get("no_substitution_rules", []))
        if isinstance(helper_alignment.get("no_substitution_rules"), list)
        else False,
    }
    status = "PARTIAL_BOUNDED_SYNTHETIC_ARG_MEM_GUARDRAILS" if all(checks.values()) else "FAIL"
    return {
        "id": "P3_pointer_argument_semantics",
        "status": status,
        "checks": checks,
        "evidence": {
            "routes": "experiments/linux_behavior/semantic_enrichment_routes.json",
            "strategy": "experiments/linux_behavior/semantic_enrichment_strategy.json",
            "paper_evidence": "paper_evidence_check.json",
            "pointer_preflight": "pointer_semantics_preflight.json" if pointer_preflight else None,
            "pointer_snapshot_gate": "pointer_snapshot_enablement_gate.json" if pointer_snapshot_gate else None,
            "pointer_snapshot_design_review": "pointer_snapshot_design_review.json" if pointer_design else None,
            "threat_model": "threat_model_boundary.json" if threat_model else None,
            "helper_alignment": "helper_alignment.json" if helper_alignment else None,
        },
        "completed_under_current_conditions": [
            "board syscall side-channel supplies representative path and process semantic closure",
            "trusted helper alignment is recorded for representative fd/path and process-tree evidence under dual-channel board validation",
            "synthetic ARG_MEM simulation covers pointer string and guardrail behavior",
            "bounded pointer snapshot design review records allowlist, limits, default-disabled policy, and non-substitution rules",
            "pointer snapshot enablement requirements are recorded while current 35T memory capture remains default-disabled",
            "semantic threat model is bounded to trusted kernel and user-mode malware-like workloads",
            "hardware user-pointer memory snapshot remains deferred and default-disabled",
        ],
        "remaining_work": [
            "implement gated selective user-pointer snapshot before claiming hardware pointer capture",
            "extend trusted helper alignment beyond representative case studies before claiming broad pointer semantic reconstruction",
            "measure timing, bandwidth, and noninterference before enabling any memory payload route",
        ],
    }


def baseline_goal(
    eval_plan: str,
    metrics: dict[str, Any],
    baseline_summary: dict[str, Any],
    baseline_check: dict[str, Any],
    baseline_execution_spec: dict[str, Any],
    advanced_preflight: dict[str, Any],
    qemu_plugin_build: dict[str, Any],
    qemu_plugin_baseline: dict[str, Any],
    evaluation_table: dict[str, Any],
    metric_coverage: dict[str, Any],
) -> dict[str, Any]:
    samples = metrics.get("samples", []) if isinstance(metrics.get("samples"), list) else []
    groundtruth_samples = [
        row
        for row in samples
        if isinstance(row, dict)
        and isinstance(row.get("groundtruth"), dict)
        and all(key in row["groundtruth"] for key in ("host_native", "host_strace", "qemu_native", "qemu_strace"))
    ]
    plan_tokens = [
        "`strace` / `ptrace`",
        "eBPF-only",
        "QEMU plugin",
        "software instrumentation",
        "RV-MalScope event-only",
        "RV-MalScope + pointer snapshot",
    ]
    checks = {
        "plan_lists_required_baselines": all(token in eval_plan for token in plan_tokens),
        "metrics_schema": metrics.get("schema") == "rvmt.35t.metrics.v1",
        "groundtruth_for_13_samples": len(groundtruth_samples) == 13,
        "baseline_summary_schema": baseline_summary.get("schema") == "rvmt.35t.baseline_evaluation.summary.v1",
        "baseline_summary_accepted": baseline_summary.get("status") in ACCEPTED_BASELINE_STATUSES,
        "baseline_check_pass": baseline_check.get("status") == "PASS",
        "baseline_execution_spec_schema": baseline_execution_spec.get("schema")
        == "rvmt.35t.baseline_execution_spec.check.v1",
        "baseline_execution_spec_pass": baseline_execution_spec.get("status") == "PASS",
        "baseline_execution_spec_covers_assessment": baseline_execution_spec.get("checks", {}).get(
            "assessment_baselines_covered"
        )
        is True
        if isinstance(baseline_execution_spec.get("checks"), dict)
        else False,
        "baseline_execution_spec_prevents_substitution": baseline_execution_spec.get("checks", {}).get(
            "substitution_rules_strict"
        )
        is True
        if isinstance(baseline_execution_spec.get("checks"), dict)
        else False,
        "advanced_preflight_schema": advanced_preflight.get("schema") in {None, "rvmt.35t.advanced_baseline_preflight.v1"},
        "qemu_plugin_build_preflight_recorded": qemu_plugin_build.get("status")
        == "QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED",
        "qemu_plugin_baseline_recorded": qemu_plugin_baseline.get("status") == QEMU_PLUGIN_BASELINE_STATUS
        and qemu_plugin_baseline.get("pass_count") == 13,
        "advanced_preflight_covers_remaining_baselines": (
            not advanced_preflight
            or (
                isinstance(advanced_preflight.get("baselines"), dict)
                and "ebpf_only" in advanced_preflight["baselines"]
                and "qemu_plugin" in advanced_preflight["baselines"]
            )
        ),
        "evaluation_table_schema": evaluation_table.get("schema") == "rvmt.35t.evaluation_table.v1",
        "evaluation_table_ready": evaluation_table.get("status") == EVALUATION_TABLE_STATUS,
        "evaluation_table_has_ebpf_and_qemu_plugin_pass": evaluation_table.get("checks", {}).get(
            "ebpf_baseline_pass"
        )
        is True
        and evaluation_table.get("checks", {}).get("qemu_plugin_baseline_pass")
        is True
        if isinstance(evaluation_table.get("checks"), dict)
        else False,
        "metric_coverage_schema": metric_coverage.get("schema") == "rvmt.35t.metric_coverage.v1",
        "metric_coverage_ready": metric_coverage.get("status") == METRIC_COVERAGE_STATUS,
        "metric_coverage_lists_required_metrics": len(metric_coverage.get("required_metrics", []))
        == 12
        if isinstance(metric_coverage.get("required_metrics"), list)
        else False,
    }
    if (
        checks["plan_lists_required_baselines"]
        and checks["metrics_schema"]
        and checks["groundtruth_for_13_samples"]
        and checks["evaluation_table_schema"]
        and checks["evaluation_table_ready"]
        and checks["evaluation_table_has_ebpf_and_qemu_plugin_pass"]
        and checks["qemu_plugin_baseline_recorded"]
        and checks["metric_coverage_schema"]
        and checks["metric_coverage_ready"]
        and checks["metric_coverage_lists_required_metrics"]
    ):
        status = (
            str(baseline_summary.get("status"))
            if checks["baseline_summary_accepted"]
            and checks["baseline_check_pass"]
            and checks["baseline_execution_spec_schema"]
            and checks["baseline_execution_spec_pass"]
            and checks["baseline_execution_spec_covers_assessment"]
            and checks["baseline_execution_spec_prevents_substitution"]
            else "PARTIAL_BASELINE_EVIDENCE"
        )
    else:
        status = "FAIL"
    return {
        "id": "P4_baseline_evaluation",
        "status": status,
        "checks": checks,
        "evidence": {
            "plan": "docs/07-evaluation-evidence/evaluation_plan.md",
            "metrics": f"results/experiments/35t/{RUN_ID}/aggregate/metrics.json",
            "groundtruth_sample_count": len(groundtruth_samples),
            "summary": "baseline_evaluation_summary.json" if baseline_summary else None,
            "check": "baseline_evaluation_check.json" if baseline_check else None,
            "execution_spec": "baseline_execution_spec_check.json" if baseline_execution_spec else None,
            "advanced_preflight": "advanced_baseline_preflight.json" if advanced_preflight else None,
            "qemu_plugin_build_preflight": "qemu_plugin_build_preflight.json" if qemu_plugin_build else None,
            "qemu_plugin_baseline": "qemu_plugin_baseline_summary.json" if qemu_plugin_baseline else None,
            "evaluation_table": "evaluation_table.json" if evaluation_table else None,
            "metric_coverage": "metric_coverage.json" if metric_coverage else None,
        },
        "completed_under_current_conditions": [
            "host native, host strace, QEMU native, and QEMU strace timing fields are present for the 13-sample 35T run",
            "software-instrumentation baseline is closed only when its independent summary reports 13/13 PASS",
            "bounded evaluation table combines timing, drop/cap, resource, anti-debug, eBPF baseline, and QEMU-plugin syscall-count evidence",
            "metric coverage table enumerates the assessment's required P4 metrics and marks measured, proxy, case-study, and deferred scopes",
            "baseline execution spec maps required baseline families to concrete current evidence, commands, and non-substitution rules",
            "QEMU-plugin system-mode build/load preflight records that a minimal plugin can be compiled and loaded",
            "QEMU-plugin is reported PASS only because qemu_plugin_baseline_summary.json records 13/13 plugin evidence",
            "bounded baseline summary/check prevent QEMU-plugin simulator evidence from being treated as hardware trace or real malware evidence",
        ],
        "remaining_work": [
            "extend advanced baselines beyond the current simulator/host software evidence only if the paper claim requires it",
            "keep QEMU-plugin evidence separated from hardware trace, DBI, and real malware claims",
        ],
    }


def sample_goal(
    manifest: dict[str, Any],
    eval_plan: str,
    extension_check: dict[str, Any],
    extension_host_smoke: dict[str, Any],
    extension_target_smoke: dict[str, Any],
    extension_behavior_smoke: dict[str, Any],
    extension_enablement: dict[str, Any],
) -> dict[str, Any]:
    samples = manifest.get("samples", []) if isinstance(manifest.get("samples"), list) else []
    sample_ids = {str(row.get("id")) for row in samples if isinstance(row, dict)}
    all_synthetic = all(row.get("real_malware") is False for row in samples if isinstance(row, dict))
    no_network = all(row.get("network_required") is False for row in samples if isinstance(row, dict))
    expansion_tokens = [
        "direct-syscall",
        "timing checks",
        "packed code",
        "mmap/mprotect executable memory",
        "fork/exec chains",
        "network workloads",
    ]
    checks = {
        "manifest_schema": manifest.get("sample_class") == "malware_like_synthetic",
        "expected_8_sample_suite": sample_ids == EXPECTED_MALWARE_SAMPLES,
        "all_real_malware_false": all_synthetic,
        "network_free_current_suite": no_network,
        "extension_topics_in_plan": all(token in eval_plan for token in expansion_tokens),
        "extension_check_schema": extension_check.get("schema") == "rvmt.35t.synthetic_suite_extension.check.v1",
        "extension_check_ready": extension_check.get("status") in ACCEPTED_EXTENSION_STATUSES,
        "extension_candidates_cover_topics": extension_check.get("checks", {}).get("candidate_topics_complete") is True
        if isinstance(extension_check.get("checks"), dict)
        else False,
        "real_malware_policy_gates_recorded": bool(extension_check.get("real_malware_policy_gates")),
        "extension_host_smoke_schema": extension_host_smoke.get("schema")
        == "rvmt.35t.synthetic_extension_host_smoke.v1",
        "extension_host_smoke_status_recorded": extension_host_smoke.get("status")
        in ACCEPTED_EXTENSION_HOST_SMOKE_STATUSES,
        "extension_host_smoke_no_execution": extension_host_smoke.get("checks", {}).get("no_execution_attempted") is True
        if isinstance(extension_host_smoke.get("checks"), dict)
        else False,
        "extension_host_smoke_no_35t_claim": extension_host_smoke.get("checks", {}).get("no_35t_gating_claim") is True
        if isinstance(extension_host_smoke.get("checks"), dict)
        else False,
        "extension_host_smoke_candidate_count_matches": extension_host_smoke.get("candidate_count")
        == extension_check.get("candidate_count"),
        "extension_target_smoke_schema": extension_target_smoke.get("schema")
        == "rvmt.35t.synthetic_extension_target_smoke.v1",
        "extension_target_smoke_status_recorded": extension_target_smoke.get("status")
        in ACCEPTED_EXTENSION_TARGET_SMOKE_STATUSES,
        "extension_target_smoke_no_execution": extension_target_smoke.get("checks", {}).get("no_execution_attempted") is True
        if isinstance(extension_target_smoke.get("checks"), dict)
        else False,
        "extension_target_smoke_no_35t_claim": extension_target_smoke.get("checks", {}).get("no_35t_gating_claim") is True
        if isinstance(extension_target_smoke.get("checks"), dict)
        else False,
        "extension_target_smoke_candidate_count_matches": extension_target_smoke.get("candidate_count")
        == extension_check.get("candidate_count"),
        "extension_behavior_smoke_schema": extension_behavior_smoke.get("schema")
        == "rvmt.35t.synthetic_extension_behavior_smoke.v1",
        "extension_behavior_smoke_status_recorded": extension_behavior_smoke.get("status")
        in ACCEPTED_EXTENSION_BEHAVIOR_SMOKE_STATUSES,
        "extension_behavior_smoke_executes_non_network": extension_behavior_smoke.get("summary_counts", {}).get("execution_pass_count") == 8
        if isinstance(extension_behavior_smoke.get("summary_counts"), dict)
        else False,
        "extension_behavior_smoke_skips_network": extension_behavior_smoke.get("summary_counts", {}).get("network_skipped_count") == 1
        if isinstance(extension_behavior_smoke.get("summary_counts"), dict)
        else False,
        "extension_behavior_smoke_expected_syscalls": extension_behavior_smoke.get("checks", {}).get("expected_syscalls_observed_for_executed")
        is True
        if isinstance(extension_behavior_smoke.get("checks"), dict)
        else False,
        "extension_behavior_smoke_no_35t_claim": extension_behavior_smoke.get("checks", {}).get("no_35t_execution_claim") is True
        if isinstance(extension_behavior_smoke.get("checks"), dict)
        else False,
        "extension_enablement_schema": extension_enablement.get("schema")
        == "rvmt.35t.extension_35t_enablement_preflight.v1",
        "extension_enablement_status_recorded": extension_enablement.get("status") == EXTENSION_ENABLEMENT_PREFLIGHT_STATUS,
        "extension_enablement_default_excludes_extensions": extension_enablement.get("checks", {}).get("default_dry_run_excludes_extensions")
        is True
        if isinstance(extension_enablement.get("checks"), dict)
        else False,
        "extension_enablement_explicit_selects_non_network": extension_enablement.get("checks", {}).get("explicit_dry_run_selects_non_network_extensions")
        is True
        if isinstance(extension_enablement.get("checks"), dict)
        else False,
        "extension_enablement_no_35t_claim": extension_enablement.get("checks", {}).get("no_expanded_35t_claim") is True
        if isinstance(extension_enablement.get("checks"), dict)
        else False,
    }
    if all(checks.values()) and extension_check.get("status") == EXTENSION_SOURCE_IMPLEMENTED_STATUS:
        status = EXTENSION_SOURCE_IMPLEMENTED_STATUS
    elif all(checks.values()):
        status = "CURRENT_SUITE_PASS_EXTENSION_READY"
    else:
        status = "FAIL"
    return {
        "id": "P5_synthetic_suite_extension",
        "status": status,
        "checks": checks,
        "evidence": {
            "manifest": "experiments/linux_behavior/malware_like/manifest.json",
            "extension_plan": "experiments/linux_behavior/malware_like/extension_plan.json" if extension_check else None,
            "extension_check": "synthetic_suite_extension_check.json" if extension_check else None,
            "current_samples": sorted(sample_ids),
            "candidate_count": extension_check.get("candidate_count"),
            "implemented_candidate_count": extension_check.get("implemented_candidate_count"),
            "candidate_topics": extension_check.get("candidate_topics"),
            "extension_source_files": extension_check.get("extension_source_files"),
            "host_smoke": "synthetic_extension_host_smoke.json" if extension_host_smoke else None,
            "host_smoke_status": extension_host_smoke.get("status"),
            "host_smoke_blocked_reasons": extension_host_smoke.get("host", {}).get("blocked_reasons")
            if isinstance(extension_host_smoke.get("host"), dict)
            else None,
            "host_smoke_compiled_candidate_count": extension_host_smoke.get("compiled_candidate_count"),
            "target_smoke": "synthetic_extension_target_smoke.json" if extension_target_smoke else None,
            "target_smoke_status": extension_target_smoke.get("status"),
            "target_smoke_compiled_candidate_count": extension_target_smoke.get("compiled_candidate_count"),
            "behavior_smoke": "synthetic_extension_behavior_smoke.json" if extension_behavior_smoke else None,
            "behavior_smoke_status": extension_behavior_smoke.get("status"),
            "behavior_smoke_summary_counts": extension_behavior_smoke.get("summary_counts"),
            "enablement_preflight": "extension_35t_enablement_preflight.json" if extension_enablement else None,
            "enablement_preflight_status": extension_enablement.get("status"),
            "selected_non_network_candidate_ids": extension_enablement.get("selected_non_network_candidate_ids"),
        },
        "completed_under_current_conditions": [
            "9 synthetic-only extension candidate sources are present, non-destructive, disabled by default, and policy-gated",
            "host compile smoke is recorded when Linux or WSL compile-only tooling is available; otherwise the current environment blocker is explicit",
            "RISC-V target cross-compile smoke is recorded when Docker target tooling is available; otherwise the current environment blocker is explicit",
            "host/QEMU behavior smoke executes non-network extension candidates and records expected QEMU guest syscall coverage when Docker tooling is available",
            "the 35T runner/rootfs/experiment CLI path now exposes extension candidates only through explicit selection, with default 13-sample coverage unchanged",
            "host/QEMU behavior smoke remains pre-board evidence and does not claim expanded 35T coverage",
        ],
        "remaining_work": [
            "refresh the board image if needed, then run the source-implemented synthetic extension candidates through the same 35T gates before claiming expanded coverage",
            "keep real malware legal, ethical, containment, and sanitization policy outside the current 35T success claim",
        ],
    }


def artifact_goal(
    manifest: dict[str, Any],
    bundle: dict[str, Any],
    artifact_readiness: dict[str, Any],
    paper_package: dict[str, Any],
    raw_sanitization: dict[str, Any],
    raw_escrow: dict[str, Any],
) -> dict[str, Any]:
    artifacts = manifest.get("committed_artifacts", []) if isinstance(manifest.get("committed_artifacts"), list) else []
    excluded = manifest.get("excluded_artifact_classes", []) if isinstance(manifest.get("excluded_artifact_classes"), list) else []
    checks = {
        "manifest_schema": manifest.get("schema") == "rvmt.35t.evidence_snapshot.v1",
        "committed_artifacts_present": len(artifacts) >= 30,
        "missing_artifacts_recorded": isinstance(manifest.get("missing_artifacts"), list),
        "large_outputs_excluded": all(
            item in excluded
            for item in ("large trace dumps", "raw UART logs", "bitstreams", "Vivado builds", "board build directories", "ELF binaries")
        ),
        "bundle_checked": bundle.get("schema") == "rvmt.35t.board_validation_bundle.v1" and bundle.get("status") == "PASS",
        "artifact_readiness_schema": artifact_readiness.get("schema") == "rvmt.35t.artifact_package_readiness.v1",
        "artifact_readiness_bounded_pass": artifact_readiness.get("status") == "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED",
        "artifact_readiness_classes_accounted": artifact_readiness.get("checks", {}).get("all_required_classes_accounted") is True
        if isinstance(artifact_readiness.get("checks"), dict)
        else False,
        "paper_package_schema": paper_package.get("schema") == "rvmt.35t.paper_artifact_package_manifest.v1",
        "paper_package_bounded_pass": paper_package.get("status") == "LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED",
        "paper_package_uses_readiness": paper_package.get("readiness", {}).get("status") == "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED"
        if isinstance(paper_package.get("readiness"), dict)
        else False,
        "raw_sanitization_schema": raw_sanitization.get("schema") == "rvmt.35t.raw_artifact_sanitization.v1",
        "raw_sanitization_hash_excerpt_ready": raw_sanitization.get("status")
        == "RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED",
        "raw_sanitization_keeps_full_raw_deferred": raw_sanitization.get("checks", {}).get("full_raw_release_deferred") is True
        if isinstance(raw_sanitization.get("checks"), dict)
        else False,
        "raw_escrow_schema": raw_escrow.get("schema") == "rvmt.35t.raw_artifact_escrow.v1",
        "raw_escrow_ready": raw_escrow.get("status") == "LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED",
        "raw_escrow_hash_verified": raw_escrow.get("checks", {}).get("payload_files_present_and_hashed") is True
        if isinstance(raw_escrow.get("checks"), dict)
        else False,
        "raw_escrow_public_release_deferred": raw_escrow.get("checks", {}).get("public_release_deferred") is True
        if isinstance(raw_escrow.get("checks"), dict)
        else False,
    }
    status = "LIGHTWEIGHT_ARTIFACT_PASS_FULL_REPRO_DEFERRED" if all(checks.values()) else "FAIL"
    return {
        "id": "P6_artifact_package",
        "status": status,
        "checks": checks,
        "evidence": {
            "snapshot_manifest": "evidence_manifest.json",
            "committed_artifact_count": len(artifacts),
            "validation_bundle_status": bundle.get("status"),
            "artifact_readiness": "artifact_package_readiness.json" if artifact_readiness else None,
            "artifact_readiness_status": artifact_readiness.get("status"),
            "artifact_class_count": artifact_readiness.get("class_count"),
            "paper_package_manifest": "paper_artifact_package_manifest.json" if paper_package else None,
            "paper_package_status": paper_package.get("status"),
            "raw_artifact_sanitization": "raw_artifact_sanitization.json" if raw_sanitization else None,
            "raw_artifact_sanitization_status": raw_sanitization.get("status"),
            "raw_artifact_escrow": "raw_artifact_escrow.json" if raw_escrow else None,
            "raw_artifact_escrow_status": raw_escrow.get("status"),
        },
        "remaining_work": [
            "turn the lightweight release-candidate package into a full release after raw traces and UART logs are approved for public or controlled external release",
            "keep generated bitstreams, board build directories, ELF binaries, and large raw artifacts out of the lightweight committed snapshot unless explicitly approved",
        ],
    }


def claim_boundary_goal(
    manifest: dict[str, Any],
    app_check: dict[str, Any],
    paper: dict[str, Any],
    paper_positioning: dict[str, Any],
    hardware_trace: dict[str, Any],
    local_code_analysis: dict[str, Any],
    malware_behavior_audit: dict[str, Any],
    closure_text: str,
    case_text: str,
) -> dict[str, Any]:
    combined_text = "\n".join([closure_text, case_text])
    checks = {
        "manifest_run_id": manifest.get("run_id") == RUN_ID,
        "manifest_scope": manifest.get("scope") == EXPECTED_SCOPE,
        "manifest_claim_level": manifest.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "real_malware_false": manifest.get("real_malware") is False,
        "cva6_out_of_scope": manifest.get("cva6_in_scope") is False,
        "non_claims_present": has_non_claims(manifest),
        "application_closure_check_pass": app_check.get("status") == "PASS",
        "paper_evidence_bounded": paper.get("paper_support_status") == "SUPPORTED_WITH_BOUNDED_CLAIMS",
        "paper_positioning_bounded": paper_positioning.get("status") == "BOUNDED_FEASIBILITY_POSITIONING_READY",
        "hardware_trace_prototype_pass": hardware_trace.get("status") == HARDWARE_TRACE_PROTOTYPE_STATUS
        and hardware_trace.get("trace_records") == 512
        and hardware_trace.get("sample_gate_pass_count") == 13
        and hardware_trace.get("decoded_trace_file_count") == 65,
        "local_code_analysis_bounded_pass": local_code_analysis.get("status") == LOCAL_CODE_ANALYSIS_STATUS
        and local_code_analysis.get("sample_count") == 13
        and local_code_analysis.get("complete_rep_count") == local_code_analysis.get("expected_rep_count"),
        "malware_behavior_audit_bounded_pass": malware_behavior_audit.get("status") == MALWARE_BEHAVIOR_AUDIT_STATUS
        and malware_behavior_audit.get("sample_count") == 8
        and malware_behavior_audit.get("rule_count") == 8
        and malware_behavior_audit.get("gate_expected_rule_pass_count") == 8,
        "no_positive_forbidden_claims": not positive_forbidden_claims(combined_text),
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    return {
        "id": "P0_claim_boundary",
        "status": status,
        "checks": checks,
        "evidence": {
            "manifest": "evidence_manifest.json",
            "application_closure_check": "application_closure_check.json",
            "paper_evidence_check": "paper_evidence_check.json",
            "paper_positioning": "paper_positioning.json",
            "hardware_trace_prototype": "hardware_trace_prototype.json",
            "local_code_analysis": "local_code_analysis.json",
            "malware_behavior_audit": "malware_behavior_audit.json",
        },
        "remaining_work": [
            "keep the 35T result phrased as a synthetic malware-like behavior audit prototype",
            "do not infer CVA6, real malware, classifier accuracy, or complete reconstruction claims",
        ],
    }


def build_report(repo_root: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    failures: list[str] = []
    warnings: list[str] = []

    manifest = read_json(evidence_root / "evidence_manifest.json", failures, repo_root, "evidence manifest")
    app_check = read_json(evidence_root / "application_closure_check.json", failures, repo_root, "application closure check")
    paper = read_json(evidence_root / "paper_evidence_check.json", failures, repo_root, "paper evidence check")
    paper_positioning = read_json(evidence_root / "paper_positioning.json", failures, repo_root, "paper positioning")
    hardware_trace = read_json(evidence_root / "hardware_trace_prototype.json", failures, repo_root, "hardware trace prototype")
    local_code_analysis = read_json(evidence_root / "local_code_analysis.json", failures, repo_root, "local code analysis")
    malware_behavior_audit = read_json(evidence_root / "malware_behavior_audit.json", failures, repo_root, "malware behavior audit")
    fd_path = read_json(evidence_root / "fd_path_flow_summary.json", failures, repo_root, "fd/path flow summary")
    fd_path_case_studies = read_json(evidence_root / "fd_path_case_studies.json", failures, repo_root, "fd/path case studies")
    process_tree = read_json(evidence_root / "process_tree_summary.json", failures, repo_root, "process tree summary")
    process_tree_case_study = read_json(evidence_root / "process_tree_case_study.json", failures, repo_root, "process tree case study")
    routes = read_json(repo_root / "experiments/linux_behavior/semantic_enrichment_routes.json", failures, repo_root, "semantic enrichment routes")
    strategy = read_json(repo_root / "experiments/linux_behavior/semantic_enrichment_strategy.json", failures, repo_root, "semantic enrichment strategy")
    malware_manifest = read_json(repo_root / "experiments/linux_behavior/malware_like/manifest.json", failures, repo_root, "malware-like manifest")
    metrics = read_json(repo_root / "results/experiments/35t" / RUN_ID / "aggregate/metrics.json", failures, repo_root, "35T metrics")
    baseline_summary = read_json(evidence_root / "baseline_evaluation_summary.json", [], repo_root, "baseline evaluation summary")
    baseline_check = read_json(evidence_root / "baseline_evaluation_check.json", [], repo_root, "baseline evaluation check")
    baseline_execution_spec = read_json(
        evidence_root / "baseline_execution_spec_check.json",
        [],
        repo_root,
        "baseline execution spec check",
    )
    advanced_preflight = read_json(evidence_root / "advanced_baseline_preflight.json", [], repo_root, "advanced baseline preflight")
    qemu_plugin_build = read_json(evidence_root / "qemu_plugin_build_preflight.json", [], repo_root, "QEMU-plugin build preflight")
    qemu_plugin_baseline = read_json(
        evidence_root / "qemu_plugin_baseline_summary.json",
        [],
        repo_root,
        "QEMU-plugin baseline summary",
    )
    evaluation_table = read_json(evidence_root / "evaluation_table.json", [], repo_root, "evaluation table")
    metric_coverage = read_json(evidence_root / "metric_coverage.json", [], repo_root, "metric coverage")
    artifact_readiness = read_json(evidence_root / "artifact_package_readiness.json", [], repo_root, "artifact package readiness")
    paper_package = read_json(evidence_root / "paper_artifact_package_manifest.json", [], repo_root, "paper artifact package manifest")
    raw_sanitization = read_json(evidence_root / "raw_artifact_sanitization.json", [], repo_root, "raw artifact sanitization")
    raw_escrow = read_json(evidence_root / "raw_artifact_escrow.json", [], repo_root, "raw artifact escrow")
    extension_check = read_json(evidence_root / "synthetic_suite_extension_check.json", [], repo_root, "synthetic suite extension check")
    extension_host_smoke = read_json(evidence_root / "synthetic_extension_host_smoke.json", [], repo_root, "synthetic extension host smoke")
    extension_target_smoke = read_json(evidence_root / "synthetic_extension_target_smoke.json", [], repo_root, "synthetic extension target smoke")
    extension_behavior_smoke = read_json(evidence_root / "synthetic_extension_behavior_smoke.json", [], repo_root, "synthetic extension behavior smoke")
    extension_enablement = read_json(
        evidence_root / "extension_35t_enablement_preflight.json",
        [],
        repo_root,
        "extension 35T enablement preflight",
    )
    pointer_preflight = read_json(evidence_root / "pointer_semantics_preflight.json", [], repo_root, "pointer semantics preflight")
    pointer_snapshot_gate = read_json(
        evidence_root / "pointer_snapshot_enablement_gate.json",
        [],
        repo_root,
        "pointer snapshot enablement gate",
    )
    pointer_design = read_json(evidence_root / "pointer_snapshot_design_review.json", [], repo_root, "pointer snapshot design review")
    helper_alignment = read_json(evidence_root / "helper_alignment.json", [], repo_root, "helper alignment")
    threat_model = read_json(evidence_root / "threat_model_boundary.json", [], repo_root, "threat model boundary")
    bundle = read_json(
        repo_root / "results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle/bundle_manifest.json",
        failures,
        repo_root,
        "targeted board-validation bundle",
    )
    closure_text = read_text(repo_root / "docs/08-publication/rv_maltrace_35t_application_closure.md", failures, repo_root, "closure result card")
    case_text = read_text(repo_root / "docs/08-publication/rv_maltrace_35t_application_case_studies.md", failures, repo_root, "case-study document")
    eval_plan = read_text(repo_root / "docs/07-evaluation-evidence/evaluation_plan.md", failures, repo_root, "evaluation plan")

    goals = [
        claim_boundary_goal(
            manifest,
            app_check,
            paper,
            paper_positioning,
            hardware_trace,
            local_code_analysis,
            malware_behavior_audit,
            closure_text,
            case_text,
        ),
        fd_path_goal(fd_path, fd_path_case_studies),
        process_tree_goal(process_tree, process_tree_case_study),
        pointer_semantics_goal(routes, strategy, paper, pointer_preflight, pointer_snapshot_gate, pointer_design, threat_model, helper_alignment),
        baseline_goal(
            eval_plan,
            metrics,
            baseline_summary,
            baseline_check,
            baseline_execution_spec,
            advanced_preflight,
            qemu_plugin_build,
            qemu_plugin_baseline,
            evaluation_table,
            metric_coverage,
        ),
        sample_goal(
            malware_manifest,
            eval_plan,
            extension_check,
            extension_host_smoke,
            extension_target_smoke,
            extension_behavior_smoke,
            extension_enablement,
        ),
        artifact_goal(manifest, bundle, artifact_readiness, paper_package, raw_sanitization, raw_escrow),
    ]
    for goal in goals:
        if goal["status"] == "FAIL":
            failures.append(f"{goal['id']} is not satisfied")

    if paper.get("warnings"):
        warnings.extend(str(item) for item in paper["warnings"] if item)

    return {
        "schema": "rvmt.35t.assessment_closure.v1",
        "status": "PASS_WITH_BOUNDED_REMAINING_WORK" if not failures else "FAIL",
        "run_id": RUN_ID,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "assessment_source": "D:/Download/rv_maltrace_35t_assessment.md",
        "interpretation": "All assessment goals are either closed with current 35T evidence or explicitly bounded as partial/deferred where hardware, baseline, or artifact conditions are not yet available.",
        "goals": goals,
        "non_claims": EXPECTED_NON_CLAIMS,
        "warnings": sorted(set(warnings)),
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Assessment Closure: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Scope: {report['scope']}.",
        "",
        f"Claim level: {report['claim_level']}.",
        "",
        report["interpretation"],
        "",
        "## Goals",
        "",
        "| Goal | Status | Evidence | Remaining boundary |",
        "| --- | --- | --- | --- |",
    ]
    for goal in report["goals"]:
        evidence = goal.get("evidence", {})
        evidence_bits = []
        if isinstance(evidence, dict):
            for key, value in evidence.items():
                if isinstance(value, (str, int, float, bool)) or value is None:
                    evidence_bits.append(f"{key}={value}")
        remaining = "; ".join(str(item) for item in goal.get("remaining_work", [])[:2])
        lines.append(f"| `{goal['id']}` | `{goal['status']}` | {', '.join(evidence_bits) or 'see JSON'} | {remaining} |")
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    lines += ["", "## Warnings", ""]
    lines.extend(f"- {item}" for item in report["warnings"] or ["none"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_report(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "assessment_closure.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "assessment_closure.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_self_test_fixture(root: Path) -> None:
    evidence = root / DEFAULT_EVIDENCE_ROOT
    evidence.mkdir(parents=True)
    write_json(
        evidence / "evidence_manifest.json",
        {
            "schema": "rvmt.35t.evidence_snapshot.v1",
            "run_id": RUN_ID,
            "scope": EXPECTED_SCOPE,
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "real_malware": False,
            "cva6_in_scope": False,
            "non_claims": EXPECTED_NON_CLAIMS,
            "committed_artifacts": [{"artifact": f"a{i}"} for i in range(30)],
            "missing_artifacts": [],
            "excluded_artifact_classes": [
                "large trace dumps",
                "raw UART logs",
                "bitstreams",
                "Vivado builds",
                "board build directories",
                "ELF binaries",
            ],
        },
    )
    write_json(evidence / "application_closure_check.json", {"status": "PASS"})
    write_json(
        evidence / "paper_evidence_check.json",
        {
            "paper_support_status": "SUPPORTED_WITH_BOUNDED_CLAIMS",
            "semantic_closure": {
                "fd_path": {"status": "PASS"},
                "process_tree": {"status": "PASS"},
            },
            "warnings": ["side-channel semantic capture has strict gate failures and is not used as the trace-gate channel"],
        },
    )
    write_json(
        evidence / "paper_positioning.json",
        {
            "schema": "rvmt.35t.paper_positioning.v1",
            "status": "BOUNDED_FEASIBILITY_POSITIONING_READY",
        },
    )
    write_json(
        evidence / "hardware_trace_prototype.json",
        {
            "schema": "rvmt.35t.hardware_trace_prototype.v1",
            "status": HARDWARE_TRACE_PROTOTYPE_STATUS,
            "trace_records": 512,
            "sample_gate_pass_count": 13,
            "sample_count": 13,
            "decoded_trace_file_count": 65,
        },
    )
    write_json(
        evidence / "local_code_analysis.json",
        {
            "schema": "rvmt.35t.local_code_analysis.v1",
            "status": LOCAL_CODE_ANALYSIS_STATUS,
            "sample_count": 13,
            "complete_rep_count": 65,
            "expected_rep_count": 65,
        },
    )
    write_json(
        evidence / "malware_behavior_audit.json",
        {
            "schema": "rvmt.35t.malware_behavior_audit.v1",
            "status": MALWARE_BEHAVIOR_AUDIT_STATUS,
            "sample_count": 8,
            "rule_count": 8,
            "gate_expected_rule_pass_count": 8,
        },
    )
    write_json(
        evidence / "fd_path_flow_summary.json",
        {
            "schema": "rvmt.fd_path_flow.summary.v1",
            "status": "PASS",
            "sample": "file_scan",
            "selected_candidate": {"source_type": "syscall_side_channel"},
            "flows": [{"status": "closed", "path_source": "board_syscall_side_channel"}],
        },
    )
    write_json(
        evidence / "fd_path_case_studies.json",
        {
            "schema": "rvmt.35t.fd_path_case_studies.v1",
            "status": "PASS",
            "samples": {
                "file_scan": {
                    "status": "PASS",
                    "selected_candidate": {"source_type": "syscall_side_channel"},
                    "closed_flow_count": 1,
                },
                "batch_open_read_write": {
                    "status": "PASS",
                    "selected_candidate": {"source_type": "syscall_side_channel"},
                    "closed_flow_count": 2,
                },
                "self_copy_sim": {
                    "status": "PASS",
                    "selected_candidate": {"source_type": "syscall_side_channel"},
                    "closed_flow_count": 2,
                },
            },
        },
    )
    write_json(
        evidence / "process_tree_summary.json",
        {
            "schema": "rvmt.process_tree.summary.v1",
            "status": "PASS",
            "sample": "process_chain",
            "edges": [{"parent_pid": "target_parent_unresolved", "child_pid": 203}],
        },
    )
    write_json(
        evidence / "process_tree_case_study.json",
        {
            "schema": "rvmt.35t.process_tree_case_study.v1",
            "status": "PASS",
            "checks": {
                "positive_child_pid_recovered": True,
                "execve_path_string_recovered": True,
                "parent_wait_pid_associated": True,
                "parent_child_graph_output": True,
                "selected_from_board_side_channel": True,
            },
        },
    )
    write_json(
        root / "experiments/linux_behavior/semantic_enrichment_routes.json",
        {
            "status": "DEFERRED_POST_FPGA",
            "current_trace_mem_mode": "TRACE_MEM_MODE_NONE",
            "routes": [
                {"id": "selective_memory_snapshot"},
                {"id": "kernel_helper_metadata"},
                {"id": "ebpf_metadata_alignment"},
            ],
        },
    )
    write_json(
        root / "experiments/linux_behavior/semantic_enrichment_strategy.json",
        {"current_mvp_policy": "NO_EBPF_NO_KERNEL_HELPER_NO_MEMORY_SNAPSHOT"},
    )
    write_json(
        evidence / "pointer_semantics_preflight.json",
        {
            "schema": "rvmt.35t.pointer_semantics_preflight.v1",
            "status": POINTER_PREFLIGHT_STATUS,
            "current_35t_pointer_semantics": {"hardware_user_pointer_snapshot": "DEFERRED"},
        },
    )
    write_json(
        evidence / "pointer_snapshot_enablement_gate.json",
        {
            "schema": "rvmt.35t.pointer_snapshot_enablement_gate.check.v1",
            "status": POINTER_SNAPSHOT_GATE_STATUS,
            "checks": {
                "all_required_requirements_present": True,
                "current_policy_default_disabled": True,
            },
        },
    )
    write_json(
        evidence / "pointer_snapshot_design_review.json",
        {
            "schema": "rvmt.35t.pointer_snapshot_design_review.check.v1",
            "status": "POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED",
            "checks": {"current_policy_default_disabled": True},
        },
    )
    write_json(
        evidence / "helper_alignment.json",
        {
            "schema": "rvmt.35t.helper_alignment.v1",
            "status": "TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL",
            "no_substitution_rules": ["not a hardware user-pointer memory snapshot"],
        },
    )
    write_json(
        evidence / "threat_model_boundary.json",
        {
            "schema": "rvmt.35t.threat_model_boundary.v1",
            "status": THREAT_MODEL_STATUS,
            "trusted_components": ["linux_kernel"],
            "in_scope": ["user_mode_malware_like_workload"],
            "out_of_scope": ["kernel_rootkit"],
        },
    )
    write_json(
        root / "experiments/linux_behavior/malware_like/manifest.json",
        {
            "sample_class": "malware_like_synthetic",
            "samples": [
                {"id": sample, "real_malware": False, "network_required": False}
                for sample in sorted(EXPECTED_MALWARE_SAMPLES)
            ],
        },
    )
    write_json(
        evidence / "synthetic_suite_extension_check.json",
        {
            "schema": "rvmt.35t.synthetic_suite_extension.check.v1",
            "status": EXTENSION_SOURCE_IMPLEMENTED_STATUS,
            "candidate_count": 9,
            "implemented_candidate_count": 9,
            "candidate_topics": ["direct-syscall", "timing checks", "packed code", "network workloads"],
            "extension_source_files": ["experiments/linux_behavior/malware_like/extension_programs/candidate.c"],
            "checks": {"candidate_topics_complete": True},
            "real_malware_policy_gates": {"sample_source_policy": "REQUIRED_BEFORE_SCOPE_EXPANSION"},
        },
    )
    write_json(
        evidence / "synthetic_extension_host_smoke.json",
        {
            "schema": "rvmt.35t.synthetic_extension_host_smoke.v1",
            "status": EXTENSION_HOST_SMOKE_BLOCKED_STATUS,
            "candidate_count": 9,
            "compiled_candidate_count": 0,
            "checks": {"no_execution_attempted": True, "no_35t_gating_claim": True},
            "host": {"blocked_reasons": ["host_platform_Windows_is_not_linux", "no_c_compiler_found"]},
        },
    )
    write_json(
        evidence / "synthetic_extension_target_smoke.json",
        {
            "schema": "rvmt.35t.synthetic_extension_target_smoke.v1",
            "status": EXTENSION_TARGET_SMOKE_PASS_STATUS,
            "candidate_count": 9,
            "compiled_candidate_count": 9,
            "checks": {"no_execution_attempted": True, "no_35t_gating_claim": True},
        },
    )
    write_json(
        evidence / "synthetic_extension_behavior_smoke.json",
        {
            "schema": "rvmt.35t.synthetic_extension_behavior_smoke.v1",
            "status": EXTENSION_BEHAVIOR_SMOKE_PASS_STATUS,
            "summary_counts": {"executed_candidate_count": 8, "execution_pass_count": 8, "network_skipped_count": 1},
            "checks": {
                "expected_syscalls_observed_for_executed": True,
                "no_35t_execution_claim": True,
                "no_expanded_35t_coverage_claim": True,
            },
        },
    )
    write_json(
        evidence / "extension_35t_enablement_preflight.json",
        {
            "schema": "rvmt.35t.extension_35t_enablement_preflight.v1",
            "status": EXTENSION_ENABLEMENT_PREFLIGHT_STATUS,
            "selected_non_network_candidate_ids": ["candidate"],
            "checks": {
                "default_dry_run_excludes_extensions": True,
                "explicit_dry_run_selects_non_network_extensions": True,
                "no_expanded_35t_claim": True,
            },
        },
    )
    write_json(
        root / "results/experiments/35t" / RUN_ID / "aggregate/metrics.json",
        {
            "schema": "rvmt.35t.metrics.v1",
            "samples": [
                {"sample_id": f"s{i}", "groundtruth": {"host_native": {}, "host_strace": {}, "qemu_native": {}, "qemu_strace": {}}}
                for i in range(13)
            ],
        },
    )
    write_json(
        evidence / "baseline_evaluation_summary.json",
        {
            "schema": "rvmt.35t.baseline_evaluation.summary.v1",
            "run_id": RUN_ID,
            "status": SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS,
        },
    )
    write_json(evidence / "baseline_evaluation_check.json", {"status": "PASS"})
    write_json(
        evidence / "baseline_execution_spec_check.json",
        {
            "schema": "rvmt.35t.baseline_execution_spec.check.v1",
            "status": "PASS",
            "checks": {
                "assessment_baselines_covered": True,
                "substitution_rules_strict": True,
            },
        },
    )
    write_json(
        evidence / "advanced_baseline_preflight.json",
        {
            "schema": "rvmt.35t.advanced_baseline_preflight.v1",
            "baselines": {"ebpf_only": {"status": "READY"}, "qemu_plugin": {"status": "BLOCKED_CURRENT_ENVIRONMENT"}},
        },
    )
    write_json(
        evidence / "qemu_plugin_build_preflight.json",
        {
            "schema": "rvmt.35t.qemu_plugin_build_preflight.v1",
            "status": "QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED",
        },
    )
    write_json(
        evidence / "qemu_plugin_baseline_summary.json",
        {
            "schema": "rvmt.35t.qemu_plugin_baseline.v1",
            "status": QEMU_PLUGIN_BASELINE_STATUS,
            "pass_count": 13,
        },
    )
    write_json(
        evidence / "evaluation_table.json",
        {
            "schema": "rvmt.35t.evaluation_table.v1",
            "status": EVALUATION_TABLE_STATUS,
            "checks": {"ebpf_baseline_pass": True, "qemu_plugin_baseline_pass": True},
        },
    )
    write_json(
        evidence / "metric_coverage.json",
        {
            "schema": "rvmt.35t.metric_coverage.v1",
            "status": METRIC_COVERAGE_STATUS,
            "required_metrics": [f"metric_{index}" for index in range(12)],
        },
    )
    write_json(
        root / "results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle/bundle_manifest.json",
        {"schema": "rvmt.35t.board_validation_bundle.v1", "status": "PASS"},
    )
    write_json(
        evidence / "artifact_package_readiness.json",
        {
            "schema": "rvmt.35t.artifact_package_readiness.v1",
            "status": "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED",
            "class_count": 17,
            "checks": {"all_required_classes_accounted": True},
        },
    )
    write_json(
        evidence / "paper_artifact_package_manifest.json",
        {
            "schema": "rvmt.35t.paper_artifact_package_manifest.v1",
            "status": "LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED",
            "readiness": {"status": "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED"},
        },
    )
    write_json(
        evidence / "raw_artifact_sanitization.json",
        {
            "schema": "rvmt.35t.raw_artifact_sanitization.v1",
            "status": "RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED",
            "checks": {"full_raw_release_deferred": True},
        },
    )
    write_json(
        evidence / "raw_artifact_escrow.json",
        {
            "schema": "rvmt.35t.raw_artifact_escrow.v1",
            "status": "LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED",
            "checks": {"payload_files_present_and_hashed": True, "public_release_deferred": True},
        },
    )
    (root / "docs/08-publication").mkdir(parents=True, exist_ok=True)
    (root / "docs/08-publication/rv_maltrace_35t_application_closure.md").write_text(
        "no real malware detection claim\n",
        encoding="utf-8",
    )
    (root / "docs/08-publication/rv_maltrace_35t_application_case_studies.md").write_text(
        "no CVA6 board claim\n",
        encoding="utf-8",
    )
    (root / "docs/05-semantic-analysis").mkdir(parents=True)
    (root / "docs/07-evaluation-evidence/evaluation_plan.md").write_text(
        "\n".join(
            [
                "`strace` / `ptrace`",
                "eBPF-only",
                "QEMU plugin",
                "software instrumentation",
                "RV-MalScope event-only",
                "RV-MalScope + pointer snapshot",
                "direct-syscall",
                "timing checks",
                "packed code",
                "mmap/mprotect executable memory",
                "fork/exec chains",
                "network workloads",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_self_test_fixture(root)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "PASS_WITH_BOUNDED_REMAINING_WORK":
            print("[FAIL] expected assessment closure fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_report(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "assessment_closure.md").exists():
            print("[FAIL] expected markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_self_test_fixture(root)
        fd_path = root / DEFAULT_EVIDENCE_ROOT / "fd_path_flow_summary.json"
        value = load_json(fd_path)
        value["status"] = "PARTIAL"
        fd_path.write_text(json.dumps(value), encoding="utf-8")
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL":
            print("[FAIL] expected fd/path regression to fail", file=sys.stderr)
            return 1
    print("[PASS] 35T assessment closure self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check 35T assessment closure status against bounded P0-P6 goals.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.evidence_root)
        if not args.no_write:
            write_report(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_assessment_closure: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T assessment closure check")
    for warning in report["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] != "FAIL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
