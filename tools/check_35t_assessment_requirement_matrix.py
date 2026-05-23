from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_ASSESSMENT = Path("D:/Download/rv_maltrace_35t_assessment.md")
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
SCHEMA = "rvmt.35t.assessment_requirement_matrix.v1"
STATUS = "ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK"
CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
SCOPE = "Artix-7 35T / LiteX / VexRiscv"
TRACEABILITY_STATUS = "PASS_WITH_BOUNDED_REMAINING_WORK"
HARDWARE_TRACE_STATUS = "HARDWARE_TRACE_PROTOTYPE_PASS_35T_SMALL_CAPACITY"
LOCAL_CODE_STATUS = "LOCAL_CODE_ANALYSIS_PROTOTYPE_PASS_WITH_BOUNDED_ATTRIBUTION"
MALWARE_AUDIT_STATUS = "SYNTHETIC_MALWARE_LIKE_BEHAVIOR_AUDIT_PASS_REAL_MALWARE_DEFERRED"
PAPER_POSITIONING_STATUS = "BOUNDED_FEASIBILITY_POSITIONING_READY"
RECONCILIATION_STATUS = "CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT"
GATE_CRITERIA_STATUS = "ASSESSMENT_GATE_CRITERIA_PASS"
REMAINING_STATUS = "PASS_CURRENT_EXTERNAL_CONDITIONS_RECORDED"
ARTIFACT_READINESS_STATUS = "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED"
PACKAGE_STATUS = "LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED"
RAW_ARTIFACT_SANITIZATION_STATUS = "RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED"
RAW_ARTIFACT_ESCROW_STATUS = "LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED"
P3_STATUS = "PARTIAL_BOUNDED_SYNTHETIC_ARG_MEM_GUARDRAILS"
P4_STATUS = "HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS"
P5_STATUS = "IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING"
P6_STATUS = "LIGHTWEIGHT_ARTIFACT_PASS_FULL_REPRO_DEFERRED"

REQUIRED_OPEN_EXTERNAL_IDS = {
    "p3_hardware_user_pointer_snapshot",
    "p5_extension_35t_gating",
    "p6_full_raw_artifact_release",
}
REQUIRED_SATISFIED_IDS = {
    "p3_pointer_snapshot_design_review",
    "p3_trusted_helper_or_ebpf_alignment",
    "p4_qemu_plugin_baseline",
    "p5_extension_host_qemu_behavior_smoke",
    "p6_local_raw_artifact_escrow",
}


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def read_json(path: Path, failures: list[str], repo_root: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return {}
    try:
        return load_json(path)
    except Exception as exc:
        failures.append(f"invalid {label}: {rel(path, repo_root)}: {exc}")
        return {}


def read_text(path: Path, failures: list[str], repo_root: Path, label: str) -> str:
    if not path.is_file():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return ""
    return path.read_text(encoding="utf-8")


def goal_statuses(closure: dict[str, Any]) -> dict[str, str]:
    goals = closure.get("goals", [])
    if not isinstance(goals, list):
        return {}
    return {
        str(goal.get("id")): str(goal.get("status"))
        for goal in goals
        if isinstance(goal, dict) and goal.get("id")
    }


def remaining_ids(remaining: dict[str, Any]) -> set[str]:
    records = remaining.get("records", [])
    if not isinstance(records, list):
        return set()
    return {
        str(record.get("id"))
        for record in records
        if isinstance(record, dict) and record.get("id")
    }


def satisfied_ids(remaining: dict[str, Any]) -> set[str]:
    records = remaining.get("satisfied_conditions", [])
    if not isinstance(records, list):
        return set()
    return {
        str(record.get("id"))
        for record in records
        if isinstance(record, dict) and record.get("id")
    }


def baseline_statuses(summary: dict[str, Any]) -> dict[str, str]:
    rows = summary.get("baselines", {})
    if not isinstance(rows, dict):
        return {}
    return {
        str(name): str(row.get("status"))
        for name, row in rows.items()
        if isinstance(row, dict)
    }


def file_exists(repo_root: Path, evidence_root: Path, value: str) -> bool:
    path = Path(value)
    if path.is_absolute():
        return path.is_file()
    if "/" in value or "\\" in value:
        return (repo_root / path).is_file()
    return (evidence_root / value).is_file()


def row(
    *,
    req_id: str,
    section: str,
    assessment_anchor: str,
    source_tokens: list[str],
    current_status: str,
    evidence: list[str],
    checks: dict[str, bool],
    boundary: str,
    assessment_text: str,
    repo_root: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    token_hits = {token: token in assessment_text for token in source_tokens}
    evidence_exists = {item: file_exists(repo_root, evidence_root, item) for item in evidence}
    all_checks = {
        "assessment_tokens_present": all(token_hits.values()),
        "evidence_files_exist": all(evidence_exists.values()),
        **checks,
    }
    return {
        "id": req_id,
        "section": section,
        "assessment_anchor": assessment_anchor,
        "status": "PASS" if all(all_checks.values()) else "FAIL",
        "current_status": current_status,
        "evidence": evidence,
        "boundary": boundary,
        "assessment_token_hits": token_hits,
        "evidence_file_exists": evidence_exists,
        "checks": all_checks,
        "failures": [key for key, ok in all_checks.items() if not ok],
    }


def build_rows(
    *,
    assessment_text: str,
    repo_root: Path,
    evidence_root: Path,
    manifest: dict[str, Any],
    closure: dict[str, Any],
    traceability: dict[str, Any],
    reconciliation: dict[str, Any],
    gate_criteria: dict[str, Any],
    hardware_trace: dict[str, Any],
    local_code: dict[str, Any],
    malware_audit: dict[str, Any],
    fd_cases: dict[str, Any],
    process_case: dict[str, Any],
    pointer_preflight: dict[str, Any],
    pointer_gate: dict[str, Any],
    pointer_design: dict[str, Any],
    threat_model: dict[str, Any],
    helper_alignment: dict[str, Any],
    baseline_summary: dict[str, Any],
    qemu_plugin_build: dict[str, Any],
    baseline_spec: dict[str, Any],
    evaluation_table: dict[str, Any],
    metric_coverage: dict[str, Any],
    extension_check: dict[str, Any],
    extension_smoke: dict[str, Any],
    extension_target_smoke: dict[str, Any],
    extension_behavior_smoke: dict[str, Any],
    extension_enablement: dict[str, Any],
    raw_sanitization: dict[str, Any],
    raw_escrow: dict[str, Any],
    artifact_readiness: dict[str, Any],
    package_manifest: dict[str, Any],
    remaining: dict[str, Any],
    paper_positioning: dict[str, Any],
    paper_evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    goals = goal_statuses(closure)
    open_remaining = remaining_ids(remaining)
    satisfied = satisfied_ids(remaining)
    baselines = baseline_statuses(baseline_summary)
    manifest_artifacts = {
        str(item.get("artifact"))
        for item in manifest.get("committed_artifacts", [])
        if isinstance(item, dict) and item.get("artifact")
    }
    package_files = {
        Path(str(path)).name
        for path in package_manifest.get("lightweight_evidence_files", [])
        if isinstance(path, str)
    }
    return [
        row(
            req_id="R1_overall_claim_boundary",
            section="1 总体结论",
            assessment_anchor="35T prototype claim and non-claims",
            source_tokens=[
                CLAIM_LEVEL,
                "RV-MalTrace 已经能检测或分析真实恶意软件",
                "当前结果验证了 CVA6",
                "当前系统已经完成完整 semantic reconstruction",
            ],
            current_status="BOUNDED_PROTOTYPE_CLAIM_FROZEN",
            evidence=[
                "evidence_manifest.json",
                "assessment_closure.json",
                "assessment_traceability.json",
                "paper_positioning.json",
                "paper_evidence_check.json",
            ],
            checks={
                "manifest_claim_level": manifest.get("claim_level") == CLAIM_LEVEL,
                "manifest_scope": manifest.get("scope") == SCOPE,
                "manifest_real_malware_false": manifest.get("real_malware") is False,
                "manifest_cva6_false": manifest.get("cva6_in_scope") is False,
                "closure_bounded": closure.get("status") == TRACEABILITY_STATUS,
                "traceability_bounded": traceability.get("status") == TRACEABILITY_STATUS,
                "paper_positioning_ready": paper_positioning.get("status") == PAPER_POSITIONING_STATUS,
                "paper_evidence_pass": paper_evidence.get("status") == "PASS",
            },
            boundary="The matrix preserves the assessment claim boundary and does not upgrade 35T evidence to real malware, CVA6, or complete semantic reconstruction.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R2_primary_35t_evidence_chain",
            section="2 当前 35T 已经成立的证据链",
            assessment_anchor="run_id, 512 records, 13 samples, synthetic-only gate",
            source_tokens=[
                RUN_ID,
                "trace_records: 512",
                "samples: 13",
                "gate: 13/13 PASS",
                "real_malware: false",
                "cva6_in_scope: false",
            ],
            current_status="PRIMARY_FULL_MATRIX_GATE_PASS",
            evidence=[
                "evidence_manifest.json",
                "assessment_gate_criteria.json",
                "hardware_trace_prototype.json",
                "sample_matrix_summary.json",
            ],
            checks={
                "gate_criteria_status": gate_criteria.get("status") == GATE_CRITERIA_STATUS,
                "hardware_trace_status": hardware_trace.get("status") == HARDWARE_TRACE_STATUS,
                "trace_records_512": hardware_trace.get("trace_records") == 512,
                "sample_gate_13_pass": hardware_trace.get("sample_gate_pass_count") == 13,
                "manifest_full_matrix_ready": manifest.get("full_matrix_ready") is True,
                "manifest_trace_records_512": manifest.get("trace_records") == 512,
            },
            boundary="The evidence chain is a 35T-only synthetic matrix under the fixed 512-record budget.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R3_sample_matrix_and_gate_conditions",
            section="2.2-2.3 matrix and gate",
            assessment_anchor="5 benign, 8 synthetic malware-like, marker/runtime/drop/cap/audit gates",
            source_tokens=[
                "`hello`, `ls`, `cat`, `cp`, `sha256sum`",
                "`file_scan`, `batch_open_read_write`, `self_copy_sim`",
                "marker scope",
                "runtime process attribution",
                "UNKNOWN/corrupt events",
                "benign expected overlap",
            ],
            current_status="GATE_CRITERIA_PASS",
            evidence=["assessment_gate_criteria.json", "malware_behavior_audit.json"],
            checks={
                "gate_status": gate_criteria.get("status") == GATE_CRITERIA_STATUS,
                "sample_rows_13": len(gate_criteria.get("sample_rows", [])) == 13
                if isinstance(gate_criteria.get("sample_rows"), list)
                else False,
                "gate_checks_all_true": all(gate_criteria.get("checks", {}).values())
                if isinstance(gate_criteria.get("checks"), dict)
                else False,
                "malware_audit_8_rules": malware_audit.get("rule_count") == 8
                and malware_audit.get("gate_expected_rule_pass_count") == 8,
            },
            boundary="The rule gate explains synthetic expected behavior and does not claim classifier quality or false-positive rate on real malware.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R4_hardware_trace_target",
            section="3.1 硬件 trace",
            assessment_anchor="35T hardware trace prototype under small-capacity profile policy",
            source_tokens=[
                "trace_profile_policy = 35t_small_capacity",
                "`illegal_trap` | `p0c_syscall_trap_drop`",
                "其他 12 个样本 | `p0a_syscall_drop`",
                "固定 512-record trace budget",
            ],
            current_status=str(hardware_trace.get("status")),
            evidence=["hardware_trace_prototype.json", "assessment_gate_criteria.json"],
            checks={
                "schema": hardware_trace.get("schema") == "rvmt.35t.hardware_trace_prototype.v1",
                "status": hardware_trace.get("status") == HARDWARE_TRACE_STATUS,
                "trace_profile_policy": hardware_trace.get("trace_profile_policy") == "35t_small_capacity",
                "decoded_trace_file_count": hardware_trace.get("decoded_trace_file_count") == 65,
                "no_cva6_extrapolation": manifest.get("cva6_in_scope") is False,
            },
            boundary="This is a 35T / LiteX / VexRiscv hardware trace prototype, not CVA6 validation.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R5_local_code_analysis_target",
            section="3.2 本地代码分析",
            assessment_anchor="ELF code map, trace-code join, runtime process map attribution",
            source_tokens=[
                "`tools/build_code_map.py`",
                "`tools/join_trace_code_map.py`",
                "`tools/recover_behavior.py`",
                "PC-in-ELF 只是静态 code-range evidence",
                "强归因仍依赖 marker scope + runtime process map",
            ],
            current_status=str(local_code.get("status")),
            evidence=["local_code_analysis.json", "paper_evidence_check.json"],
            checks={
                "schema": local_code.get("schema") == "rvmt.35t.local_code_analysis.v1",
                "status": local_code.get("status") == LOCAL_CODE_STATUS,
                "sample_count": local_code.get("sample_count") == 13,
                "all_reps_complete": local_code.get("complete_rep_count") == local_code.get("expected_rep_count"),
            },
            boundary="Local code analysis is bounded to prototype attribution; source-line and complete process ownership remain non-claims.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R6_malware_behavior_audit_boundary",
            section="3.3 Malware 分析",
            assessment_anchor="8 synthetic malware-like rules, real-malware claims deferred",
            source_tokens=[
                "`many_file_scan`",
                "`batch_file_read_write`",
                "`self_copy_simulation`",
                "`anti_analysis_indicator`",
                "real malware execution",
                "classifier accuracy claim",
            ],
            current_status=str(malware_audit.get("status")),
            evidence=["malware_behavior_audit.json", "assessment_gate_criteria.json"],
            checks={
                "schema": malware_audit.get("schema") == "rvmt.35t.malware_behavior_audit.v1",
                "status": malware_audit.get("status") == MALWARE_AUDIT_STATUS,
                "sample_count": malware_audit.get("sample_count") == 8,
                "rule_count": malware_audit.get("rule_count") == 8,
                "real_malware_false": manifest.get("real_malware") is False,
            },
            boundary="The malware-facing result is a controlled synthetic behavior audit, not real malware execution or detector accuracy.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R7_fd_path_and_process_case_studies",
            section="4.1-4.2 fd/path and process tree shortfalls",
            assessment_anchor="assessment snapshot partial, current representative case studies closed with bounded side-channel evidence",
            source_tokens=[
                "fd/path Flow Summary",
                "Status: PARTIAL",
                "Process Tree Summary",
                "Edges: none strictly closed",
                "openat(path) -> fd",
                "parent(pid=P) --clone--> child(pid=C)",
            ],
            current_status="REPRESENTATIVE_CASE_STUDIES_PASS_BOUNDED",
            evidence=[
                "fd_path_case_studies.json",
                "process_tree_case_study.json",
                "assessment_reconciliation.json",
            ],
            checks={
                "p1_goal_pass": goals.get("P1_fd_path_flow") == "PASS",
                "p2_goal_pass": goals.get("P2_process_tree") == "PASS",
                "fd_case_pass": fd_cases.get("status") == "PASS",
                "process_case_pass": process_case.get("status") == "PASS",
                "reconciliation_pass": reconciliation.get("status") == RECONCILIATION_STATUS,
            },
            boundary="P1/P2 are stronger than the original snapshot for representative case studies, but they are not full-suite hardware pointer semantic reconstruction.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R8_pointer_semantics_external_work",
            section="4.3 and P3 pointer semantics",
            assessment_anchor="hardware user-pointer snapshot and trusted helper/eBPF routes remain deferred",
            source_tokens=[
                "pointer 参数语义没有真正打通",
                "硬件 user-pointer memory snapshot",
                "trusted helper / eBPF companion",
                "trusted kernel, user-mode malware",
                "不能声称抵抗 kernel rootkit",
            ],
            current_status=goals.get("P3_pointer_argument_semantics", ""),
            evidence=[
                "pointer_semantics_preflight.json",
                "pointer_snapshot_enablement_gate.json",
                "pointer_snapshot_design_review.json",
                "threat_model_boundary.json",
                "helper_alignment.json",
                "remaining_external_work.json",
            ],
            checks={
                "p3_goal_bounded": goals.get("P3_pointer_argument_semantics") == P3_STATUS,
                "pointer_preflight_status": pointer_preflight.get("status")
                == "SYNTHETIC_ARG_MEM_GUARDRAILS_PASS_SIDE_CHANNEL_CLOSURE_HARDWARE_POINTER_DEFERRED",
                "pointer_gate_default_disabled": pointer_gate.get("status")
                == "POINTER_SNAPSHOT_ENABLEMENT_GATES_RECORDED_NOT_ENABLED",
                "pointer_design_review_status": pointer_design.get("status")
                == "POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED",
                "pointer_design_default_disabled": pointer_design.get("checks", {}).get("current_policy_default_disabled") is True
                if isinstance(pointer_design.get("checks"), dict)
                else False,
                "trusted_kernel_boundary": threat_model.get("status")
                == "TRUSTED_KERNEL_USER_MODE_THREAT_MODEL_BOUNDARY_SPECIFIED",
                "helper_alignment_status": helper_alignment.get("status")
                == "TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL",
                "remaining_ids": {"p3_hardware_user_pointer_snapshot"} <= open_remaining,
                "satisfied_ids": {"p3_pointer_snapshot_design_review", "p3_trusted_helper_or_ebpf_alignment"} <= satisfied,
            },
            boundary="P3 has representative trusted-helper alignment and pointer snapshot design-review evidence, but cannot be marked complete until enabled hardware pointer snapshot or broader pointer semantic reconstruction evidence exists.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R9_baseline_evaluation_external_work",
            section="4.4 and P4 baseline evaluation",
            assessment_anchor="strace/software instrumentation/eBPF and QEMU-plugin evidence recorded under bounded simulator/software claims",
            source_tokens=[
                "ebpf_only: BLOCKED",
                "qemu_plugin: BLOCKED",
                "software_instrumentation: BLOCKED",
                "syscall precision / recall",
                "anti-debug detectability",
            ],
            current_status=goals.get("P4_baseline_evaluation", ""),
            evidence=[
                "baseline_evaluation_summary.json",
                "baseline_execution_spec_check.json",
                "evaluation_table.json",
                "metric_coverage.json",
                "advanced_baseline_preflight.json",
                "qemu_plugin_build_preflight.json",
                "qemu_plugin_baseline_summary.json",
                "remaining_external_work.json",
            ],
            checks={
                "p4_goal_bounded": goals.get("P4_baseline_evaluation") == P4_STATUS,
                "host_strace_pass": baselines.get("host_strace") == "PASS",
                "software_instrumentation_pass": baselines.get("software_instrumentation") == "PASS",
                "ebpf_pass": baselines.get("ebpf_only") == "PASS",
                "qemu_plugin_pass": baselines.get("qemu_plugin") == "PASS",
                "qemu_plugin_build_preflight_recorded": qemu_plugin_build.get("status")
                == "QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED",
                "baseline_spec_status": baseline_spec.get("status")
                in {"PASS", "BASELINE_EXECUTION_SPEC_PASS_CURRENT_ENVIRONMENT_BOUNDED"},
                "evaluation_table_status": evaluation_table.get("status")
                == "BOUNDED_EVALUATION_TABLE_READY_WITH_EBPF_AND_QEMU_PLUGIN",
                "metric_coverage_status": metric_coverage.get("status")
                == "BOUNDED_METRIC_COVERAGE_READY_WITH_DEFERRED_FULL_ACCURACY",
                "satisfied_ids": {"p4_qemu_plugin_baseline"} <= satisfied,
            },
            boundary="P4 has bounded host/QEMU/strace, software-instrumentation, host eBPF, and QEMU-plugin simulator coverage; none of these substitute for hardware pointer snapshots, DBI, or real malware evaluation.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R10_synthetic_suite_extension_boundary",
            section="P5 synthetic suite extension",
            assessment_anchor="source candidates implemented, synthetic-only and default-disabled, 35T gating deferred",
            source_tokens=[
                "direct syscall",
                "TracerPid check",
                "self-modifying code",
                "network client behavior",
                "file encryption simulation without destructive payload",
                "artifact sanitization",
            ],
            current_status=goals.get("P5_synthetic_suite_extension", ""),
            evidence=[
                "synthetic_suite_extension_check.json",
                "synthetic_extension_host_smoke.json",
                "synthetic_extension_target_smoke.json",
                "synthetic_extension_behavior_smoke.json",
                "extension_35t_enablement_preflight.json",
                "remaining_external_work.json",
                "experiments/linux_behavior/malware_like/extension_plan.json",
            ],
            checks={
                "p5_goal_status": goals.get("P5_synthetic_suite_extension") == P5_STATUS,
                "extension_check_status": extension_check.get("status") == P5_STATUS,
                "extension_candidate_count": extension_check.get("candidate_count") == 9,
                "extension_sources_no_35t_claim": extension_check.get("checks", {}).get("no_expanded_claims") is True
                if isinstance(extension_check.get("checks"), dict)
                else False,
                "host_smoke_status_bounded": extension_smoke.get("status")
                in {
                    "HOST_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED",
                    "HOST_COMPILE_SMOKE_BLOCKED_CURRENT_ENVIRONMENT",
                },
                "target_smoke_status_bounded": extension_target_smoke.get("status")
                in {
                    "TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED",
                    "TARGET_COMPILE_SMOKE_BLOCKED_CURRENT_ENVIRONMENT",
                },
                "target_smoke_no_35t_claim": extension_target_smoke.get("checks", {}).get("no_35t_gating_claim") is True
                if isinstance(extension_target_smoke.get("checks"), dict)
                else False,
                "behavior_smoke_status_bounded": extension_behavior_smoke.get("status")
                in {
                    "HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED",
                    "HOST_QEMU_BEHAVIOR_SMOKE_BLOCKED_CURRENT_ENVIRONMENT",
                },
                "behavior_smoke_executes_non_network": extension_behavior_smoke.get("summary_counts", {}).get("execution_pass_count") == 8
                if isinstance(extension_behavior_smoke.get("summary_counts"), dict)
                else False,
                "behavior_smoke_expected_syscalls": extension_behavior_smoke.get("checks", {}).get("expected_syscalls_observed_for_executed")
                is True
                if isinstance(extension_behavior_smoke.get("checks"), dict)
                else False,
                "behavior_smoke_no_35t_claim": extension_behavior_smoke.get("checks", {}).get("no_35t_execution_claim") is True
                if isinstance(extension_behavior_smoke.get("checks"), dict)
                else False,
                "enablement_preflight_status": extension_enablement.get("status")
                == "EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED",
                "enablement_default_excludes_extensions": extension_enablement.get("checks", {}).get("default_dry_run_excludes_extensions")
                is True
                if isinstance(extension_enablement.get("checks"), dict)
                else False,
                "enablement_explicit_selects_non_network": extension_enablement.get("checks", {}).get("explicit_dry_run_selects_non_network_extensions")
                is True
                if isinstance(extension_enablement.get("checks"), dict)
                else False,
                "enablement_no_35t_claim": extension_enablement.get("checks", {}).get("no_expanded_35t_claim") is True
                if isinstance(extension_enablement.get("checks"), dict)
                else False,
                "remaining_35t_gating": "p5_extension_35t_gating" in open_remaining,
            },
            boundary="Implemented extension sources now have compile, host/QEMU behavior smoke, and explicit runner/rootfs/CLI preflight evidence, but remain outside the claimed 35T matrix until board gate evidence exists.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R11_artifact_package_boundary",
            section="4.5 and P6 artifact package",
            assessment_anchor="lightweight snapshot ready, full raw artifact release deferred",
            source_tokens=[
                "当前 snapshot 是轻量摘要",
                "raw_uart.log",
                "decoded trace.jsonl",
                "bitstream metadata",
                "哪些 artifact 可公开",
            ],
            current_status=goals.get("P6_artifact_package", ""),
            evidence=[
                "raw_artifact_sanitization.json",
                "raw_artifact_sanitization.md",
                "raw_artifact_escrow.json",
                "raw_artifact_escrow.md",
                "artifact_package_readiness.json",
                "paper_artifact_package_manifest.json",
                "paper_artifact_release_policy.json",
                "remaining_external_work.json",
            ],
            checks={
                "p6_goal_status": goals.get("P6_artifact_package") == P6_STATUS,
                "raw_sanitization_status": raw_sanitization.get("status") == RAW_ARTIFACT_SANITIZATION_STATUS,
                "raw_sanitization_full_raw_deferred": raw_sanitization.get("checks", {}).get("full_raw_release_deferred") is True
                if isinstance(raw_sanitization.get("checks"), dict)
                else False,
                "artifact_readiness_status": artifact_readiness.get("status") == ARTIFACT_READINESS_STATUS,
                "package_manifest_status": package_manifest.get("status") == PACKAGE_STATUS,
                "raw_escrow_status": raw_escrow.get("status") == RAW_ARTIFACT_ESCROW_STATUS,
                "raw_escrow_payload_hashed": raw_escrow.get("checks", {}).get("payload_files_present_and_hashed") is True
                if isinstance(raw_escrow.get("checks"), dict)
                else False,
                "raw_escrow_public_release_deferred": raw_escrow.get("checks", {}).get("public_release_deferred") is True
                if isinstance(raw_escrow.get("checks"), dict)
                else False,
                "no_missing_artifact_classes": artifact_readiness.get("missing_classes") == [],
                "matrix_in_manifest": "assessment_requirement_matrix.json" in manifest_artifacts,
                "matrix_in_package": "assessment_requirement_matrix.json" in package_files,
                "raw_sanitization_in_manifest": "raw_artifact_sanitization.json" in manifest_artifacts,
                "raw_sanitization_in_package": "raw_artifact_sanitization.json" in package_files,
                "raw_escrow_in_manifest": "raw_artifact_escrow.json" in manifest_artifacts,
                "raw_escrow_in_package": "raw_artifact_escrow.json" in package_files,
                "remaining_full_raw_release": "p6_full_raw_artifact_release" in open_remaining,
                "local_raw_escrow_satisfied": "p6_local_raw_artifact_escrow" in satisfied,
            },
            boundary="The lightweight package, hashes, sanitized excerpts, and local raw escrow package are ready; public or external raw release still needs approval or a controlled-release destination.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R12_ccfa_positioning",
            section="5 CCF-A positioning",
            assessment_anchor="35T supports feasibility/constrained-board case study, not standalone CCF-A main claim",
            source_tokens=[
                "35T 线不足以单独支撑 CCF-A 主论文观点",
                "low-cost FPGA feasibility / constrained-board prototype evaluation",
                "main malware detection result",
                "main architecture validation for CVA6",
            ],
            current_status=str(paper_positioning.get("status")),
            evidence=["paper_positioning.json", "paper_evidence_check.json", "remaining_external_work.json"],
            checks={
                "paper_positioning_status": paper_positioning.get("status") == PAPER_POSITIONING_STATUS,
                "supported_positioning_present": "low-cost FPGA feasibility / constrained-board prototype evaluation"
                in set(paper_positioning.get("supported_positioning", [])),
                "forbidden_positioning_present": "main CCF-A contribution by itself"
                in set(paper_positioning.get("forbidden_positioning", [])),
                "no_positive_forbidden_findings": paper_positioning.get("positive_forbidden_findings") == [],
                "required_open_external_ids_recorded": REQUIRED_OPEN_EXTERNAL_IDS <= open_remaining,
                "required_satisfied_ids_recorded": REQUIRED_SATISFIED_IDS <= satisfied,
            },
            boundary="35T may support a feasibility subsection or constrained-board case study, not the full CCF-A main contribution by itself.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R13_recommended_paper_organization",
            section="7 推荐论文组织方式",
            assessment_anchor="RISC-V trace, trace-to-semantics, evasion/perturbation, constrained-board feasibility",
            source_tokens=[
                "Contribution 1：RISC-V committed execution hardware trace",
                "Contribution 2：Trace-to-semantics reconstruction",
                "Contribution 3：Evasion-resistance / low-perturbation evaluation",
                "Contribution 4：Constrained-board feasibility",
                "35T 线可以作为这里的证据",
            ],
            current_status="PAPER_ORGANIZATION_BOUNDARY_RECORDED",
            evidence=["paper_positioning.json", "metric_coverage.json", "paper_evidence_check.json"],
            checks={
                "paper_positioning_ready": paper_positioning.get("status") == PAPER_POSITIONING_STATUS,
                "metric_coverage_ready": metric_coverage.get("status")
                == "BOUNDED_METRIC_COVERAGE_READY_WITH_DEFERRED_FULL_ACCURACY",
                "paper_evidence_supported": paper_evidence.get("paper_support_status") == "SUPPORTED_WITH_BOUNDED_CLAIMS",
            },
            boundary="The recommended organization is supported only with bounded feasibility wording and deferred anti-evasion/semantic completeness claims.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
        row(
            req_id="R14_final_judgment",
            section="8-9 final judgment",
            assessment_anchor="application goal achieved only for synthetic malware-like audit; real malware/CCF-A remain not achieved",
            source_tokens=[
                "硬件 trace + 本地代码分析 + synthetic malware-like behavior audit",
                "则当前 35T 线：\n\n```text\n已达到。",
                "真实 malware 分析/检测",
                "不能单独支撑 CCF-A 主论文观点",
                "下一步应优先补 fd/path、process tree、pointer semantics、baseline、低扰动/抗规避和 artifact package",
            ],
            current_status="FINAL_ASSESSMENT_RECONCILED_WITH_CURRENT_EVIDENCE",
            evidence=[
                "assessment_closure.json",
                "assessment_traceability.json",
                "assessment_reconciliation.json",
                "remaining_external_work.json",
            ],
            checks={
                "closure_status": closure.get("status") == TRACEABILITY_STATUS,
                "traceability_status": traceability.get("status") == TRACEABILITY_STATUS,
                "reconciliation_status": reconciliation.get("status") == RECONCILIATION_STATUS,
                "remaining_external_work_status": remaining
                and paper_positioning.get("checks", {}).get("remaining_external_work_recorded") is True
                if isinstance(paper_positioning.get("checks"), dict)
                else False,
                "current_goal_statuses_preserve_boundaries": goals.get("P3_pointer_argument_semantics") == P3_STATUS
                and goals.get("P4_baseline_evaluation") == P4_STATUS
                and goals.get("P5_synthetic_suite_extension") == P5_STATUS
                and goals.get("P6_artifact_package") == P6_STATUS,
            },
            boundary="The final answer is a bounded current-scope pass, not completion of real-malware, CVA6, complete semantics, or full raw-artifact release goals.",
            assessment_text=assessment_text,
            repo_root=repo_root,
            evidence_root=evidence_root,
        ),
    ]


def build_report(repo_root: Path, assessment_arg: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    assessment_path = repo_path(repo_root, assessment_arg).resolve()
    failures: list[str] = []
    assessment_text = read_text(assessment_path, failures, repo_root, "assessment document")
    manifest = read_json(evidence_root / "evidence_manifest.json", failures, repo_root, "evidence manifest")
    closure = read_json(evidence_root / "assessment_closure.json", failures, repo_root, "assessment closure")
    traceability = read_json(evidence_root / "assessment_traceability.json", failures, repo_root, "assessment traceability")
    reconciliation = read_json(evidence_root / "assessment_reconciliation.json", failures, repo_root, "assessment reconciliation")
    gate_criteria = read_json(evidence_root / "assessment_gate_criteria.json", failures, repo_root, "assessment gate criteria")
    hardware_trace = read_json(evidence_root / "hardware_trace_prototype.json", failures, repo_root, "hardware trace prototype")
    local_code = read_json(evidence_root / "local_code_analysis.json", failures, repo_root, "local code analysis")
    malware_audit = read_json(evidence_root / "malware_behavior_audit.json", failures, repo_root, "malware behavior audit")
    fd_cases = read_json(evidence_root / "fd_path_case_studies.json", failures, repo_root, "fd/path case studies")
    process_case = read_json(evidence_root / "process_tree_case_study.json", failures, repo_root, "process-tree case study")
    pointer_preflight = read_json(evidence_root / "pointer_semantics_preflight.json", failures, repo_root, "pointer preflight")
    pointer_gate = read_json(evidence_root / "pointer_snapshot_enablement_gate.json", failures, repo_root, "pointer snapshot gate")
    pointer_design = read_json(evidence_root / "pointer_snapshot_design_review.json", failures, repo_root, "pointer snapshot design review")
    threat_model = read_json(evidence_root / "threat_model_boundary.json", failures, repo_root, "threat model boundary")
    helper_alignment = read_json(evidence_root / "helper_alignment.json", failures, repo_root, "helper alignment")
    baseline_summary = read_json(evidence_root / "baseline_evaluation_summary.json", failures, repo_root, "baseline summary")
    qemu_plugin_build = read_json(evidence_root / "qemu_plugin_build_preflight.json", failures, repo_root, "QEMU-plugin build preflight")
    baseline_spec = read_json(evidence_root / "baseline_execution_spec_check.json", failures, repo_root, "baseline execution spec")
    evaluation_table = read_json(evidence_root / "evaluation_table.json", failures, repo_root, "evaluation table")
    metric_coverage = read_json(evidence_root / "metric_coverage.json", failures, repo_root, "metric coverage")
    extension_check = read_json(evidence_root / "synthetic_suite_extension_check.json", failures, repo_root, "synthetic extension check")
    extension_smoke = read_json(evidence_root / "synthetic_extension_host_smoke.json", failures, repo_root, "synthetic extension host smoke")
    extension_target_smoke = read_json(evidence_root / "synthetic_extension_target_smoke.json", failures, repo_root, "synthetic extension target smoke")
    extension_behavior_smoke = read_json(evidence_root / "synthetic_extension_behavior_smoke.json", failures, repo_root, "synthetic extension behavior smoke")
    extension_enablement = read_json(evidence_root / "extension_35t_enablement_preflight.json", failures, repo_root, "extension 35T enablement preflight")
    raw_sanitization = read_json(evidence_root / "raw_artifact_sanitization.json", failures, repo_root, "raw artifact sanitization")
    raw_escrow = read_json(evidence_root / "raw_artifact_escrow.json", failures, repo_root, "raw artifact escrow")
    artifact_readiness = read_json(evidence_root / "artifact_package_readiness.json", failures, repo_root, "artifact readiness")
    package_manifest = read_json(evidence_root / "paper_artifact_package_manifest.json", failures, repo_root, "paper artifact package manifest")
    remaining = read_json(evidence_root / "remaining_external_work.json", failures, repo_root, "remaining external work")
    paper_positioning = read_json(evidence_root / "paper_positioning.json", failures, repo_root, "paper positioning")
    paper_evidence = read_json(evidence_root / "paper_evidence_check.json", failures, repo_root, "paper evidence")

    rows = build_rows(
        assessment_text=assessment_text,
        repo_root=repo_root,
        evidence_root=evidence_root,
        manifest=manifest,
        closure=closure,
        traceability=traceability,
        reconciliation=reconciliation,
        gate_criteria=gate_criteria,
        hardware_trace=hardware_trace,
        local_code=local_code,
        malware_audit=malware_audit,
        fd_cases=fd_cases,
        process_case=process_case,
        pointer_preflight=pointer_preflight,
        pointer_gate=pointer_gate,
        pointer_design=pointer_design,
        threat_model=threat_model,
        helper_alignment=helper_alignment,
        baseline_summary=baseline_summary,
        qemu_plugin_build=qemu_plugin_build,
        baseline_spec=baseline_spec,
        evaluation_table=evaluation_table,
        metric_coverage=metric_coverage,
        extension_check=extension_check,
        extension_smoke=extension_smoke,
        extension_target_smoke=extension_target_smoke,
        extension_behavior_smoke=extension_behavior_smoke,
        extension_enablement=extension_enablement,
        raw_sanitization=raw_sanitization,
        raw_escrow=raw_escrow,
        artifact_readiness=artifact_readiness,
        package_manifest=package_manifest,
        remaining=remaining,
        paper_positioning=paper_positioning,
        paper_evidence=paper_evidence,
    )
    for item in rows:
        for failure in item["failures"]:
            failures.append(f"{item['id']}: {failure}")
    high_level_checks = {
        "all_requirements_pass": all(item["status"] == "PASS" for item in rows),
        "requirement_count": len(rows) == 14,
        "bounded_external_records_complete": REQUIRED_OPEN_EXTERNAL_IDS <= remaining_ids(remaining),
        "bounded_satisfied_conditions_complete": REQUIRED_SATISFIED_IDS <= satisfied_ids(remaining),
        "no_row_upgrades_external_work": all(
            item["current_status"] not in {"COMPLETE", "UNBOUNDED_PASS"} for item in rows
        ),
    }
    for key, ok in high_level_checks.items():
        if not ok:
            failures.append(f"matrix high-level check failed: {key}")
    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "status": STATUS if not failures else "FAIL",
        "assessment_source": str(assessment_path),
        "evidence_root": rel(evidence_root, repo_root),
        "scope": SCOPE,
        "claim_level": CLAIM_LEVEL,
        "high_level_checks": high_level_checks,
        "requirements": rows,
        "requirement_count": len(rows),
        "interpretation": [
            "the source assessment is covered section-by-section by current evidence rows",
            "current-scope 35T hardware trace, local code analysis, and synthetic malware-like audit evidence pass under bounded claims",
            "P3/P4/P5/P6 external conditions remain explicit and are not silently treated as completed work",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Assessment Requirement Matrix: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Scope: {report['scope']}.",
        "",
        f"Claim level: {report['claim_level']}.",
        "",
        "## High-Level Checks",
        "",
    ]
    for key, ok in report["high_level_checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Requirements",
        "",
        "| ID | Section | Status | Current Status | Evidence | Boundary |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in report["requirements"]:
        evidence = ", ".join(f"`{Path(path).name}`" for path in item["evidence"])
        lines.append(
            f"| `{item['id']}` | {item['section']} | `{item['status']}` | `{item['current_status']}` | {evidence} | {item['boundary']} |"
        )
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "assessment_requirement_matrix.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "assessment_requirement_matrix.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def fixture_assessment(path: Path, *, missing_token: bool = False) -> None:
    tokens = [
        CLAIM_LEVEL,
        "RV-MalTrace 已经能检测或分析真实恶意软件",
        "当前结果验证了 CVA6",
        "当前系统已经完成完整 semantic reconstruction",
        RUN_ID,
        "trace_records: 512",
        "samples: 13",
        "gate: 13/13 PASS",
        "real_malware: false",
        "cva6_in_scope: false",
        "`hello`, `ls`, `cat`, `cp`, `sha256sum`",
        "`file_scan`, `batch_open_read_write`, `self_copy_sim`",
        "marker scope",
        "runtime process attribution",
        "UNKNOWN/corrupt events",
        "benign expected overlap",
        "trace_profile_policy = 35t_small_capacity",
        "`illegal_trap` | `p0c_syscall_trap_drop`",
        "其他 12 个样本 | `p0a_syscall_drop`",
        "固定 512-record trace budget",
        "`tools/build_code_map.py`",
        "`tools/join_trace_code_map.py`",
        "`tools/recover_behavior.py`",
        "PC-in-ELF 只是静态 code-range evidence",
        "强归因仍依赖 marker scope + runtime process map",
        "`many_file_scan`",
        "`batch_file_read_write`",
        "`self_copy_simulation`",
        "`anti_analysis_indicator`",
        "real malware execution",
        "classifier accuracy claim",
        "fd/path Flow Summary",
        "Status: PARTIAL",
        "Process Tree Summary",
        "Edges: none strictly closed",
        "openat(path) -> fd",
        "parent(pid=P) --clone--> child(pid=C)",
        "pointer 参数语义没有真正打通",
        "硬件 user-pointer memory snapshot",
        "trusted helper / eBPF companion",
        "trusted kernel, user-mode malware",
        "不能声称抵抗 kernel rootkit",
        "ebpf_only: BLOCKED",
        "qemu_plugin: BLOCKED",
        "software_instrumentation: BLOCKED",
        "syscall precision / recall",
        "anti-debug detectability",
        "direct syscall",
        "TracerPid check",
        "self-modifying code",
        "network client behavior",
        "file encryption simulation without destructive payload",
        "artifact sanitization",
        "当前 snapshot 是轻量摘要",
        "raw_uart.log",
        "decoded trace.jsonl",
        "bitstream metadata",
        "哪些 artifact 可公开",
        "35T 线不足以单独支撑 CCF-A 主论文观点",
        "low-cost FPGA feasibility / constrained-board prototype evaluation",
        "main malware detection result",
        "main architecture validation for CVA6",
        "Contribution 1：RISC-V committed execution hardware trace",
        "Contribution 2：Trace-to-semantics reconstruction",
        "Contribution 3：Evasion-resistance / low-perturbation evaluation",
        "Contribution 4：Constrained-board feasibility",
        "35T 线可以作为这里的证据",
        "硬件 trace + 本地代码分析 + synthetic malware-like behavior audit",
        "则当前 35T 线：\n\n```text\n已达到。",
        "真实 malware 分析/检测",
        "不能单独支撑 CCF-A 主论文观点",
        "下一步应优先补 fd/path、process tree、pointer semantics、baseline、低扰动/抗规避和 artifact package",
    ]
    if missing_token:
        tokens.remove("trace_records: 512")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(tokens) + "\n", encoding="utf-8")


def write_fixture(root: Path, *, omit_external: bool = False, missing_token: bool = False) -> None:
    evidence = root / DEFAULT_EVIDENCE_ROOT
    evidence.mkdir(parents=True, exist_ok=True)
    fixture_assessment(root / "assessment.md", missing_token=missing_token)
    artifacts = [
        "evidence_manifest.json",
        "assessment_closure.json",
        "assessment_traceability.json",
        "assessment_reconciliation.json",
        "assessment_gate_criteria.json",
        "hardware_trace_prototype.json",
        "local_code_analysis.json",
        "malware_behavior_audit.json",
        "fd_path_case_studies.json",
        "process_tree_case_study.json",
        "pointer_semantics_preflight.json",
        "pointer_snapshot_enablement_gate.json",
        "pointer_snapshot_design_review.json",
        "threat_model_boundary.json",
        "helper_alignment.json",
        "baseline_evaluation_summary.json",
        "qemu_plugin_build_preflight.json",
        "baseline_execution_spec_check.json",
        "evaluation_table.json",
        "metric_coverage.json",
        "advanced_baseline_preflight.json",
        "synthetic_suite_extension_check.json",
        "synthetic_extension_host_smoke.json",
        "raw_artifact_sanitization.json",
        "raw_artifact_sanitization.md",
        "raw_artifact_escrow.json",
        "raw_artifact_escrow.md",
        "artifact_package_readiness.json",
        "paper_artifact_package_manifest.json",
        "paper_artifact_release_policy.json",
        "remaining_external_work.json",
        "paper_positioning.json",
        "paper_evidence_check.json",
        "sample_matrix_summary.json",
    ]
    for name in artifacts:
        (evidence / name).write_text("{}", encoding="utf-8")
    extension_plan = root / "experiments/linux_behavior/malware_like/extension_plan.json"
    extension_plan.parent.mkdir(parents=True, exist_ok=True)
    extension_plan.write_text("{}", encoding="utf-8")
    write_json(
        evidence / "evidence_manifest.json",
        {
            "schema": "rvmt.35t.evidence_snapshot.v1",
            "run_id": RUN_ID,
            "scope": SCOPE,
            "claim_level": CLAIM_LEVEL,
            "real_malware": False,
            "cva6_in_scope": False,
            "full_matrix_ready": True,
            "trace_records": 512,
            "committed_artifacts": [
                {"artifact": "assessment_requirement_matrix.json"},
                {"artifact": "assessment_requirement_matrix.md"},
                {"artifact": "pointer_snapshot_design_review.json"},
                {"artifact": "raw_artifact_sanitization.json"},
                {"artifact": "raw_artifact_sanitization.md"},
                {"artifact": "raw_artifact_escrow.json"},
                {"artifact": "raw_artifact_escrow.md"},
            ],
        },
    )
    write_json(
        evidence / "assessment_closure.json",
        {
            "schema": "rvmt.35t.assessment_closure.v1",
            "status": TRACEABILITY_STATUS,
            "goals": [
                {"id": "P1_fd_path_flow", "status": "PASS"},
                {"id": "P2_process_tree", "status": "PASS"},
                {"id": "P3_pointer_argument_semantics", "status": P3_STATUS},
                {"id": "P4_baseline_evaluation", "status": P4_STATUS},
                {"id": "P5_synthetic_suite_extension", "status": P5_STATUS},
                {"id": "P6_artifact_package", "status": P6_STATUS},
            ],
        },
    )
    write_json(evidence / "assessment_traceability.json", {"schema": "rvmt.35t.assessment_traceability.v1", "status": TRACEABILITY_STATUS})
    write_json(evidence / "assessment_reconciliation.json", {"schema": "rvmt.35t.assessment_reconciliation.v1", "status": RECONCILIATION_STATUS})
    write_json(
        evidence / "assessment_gate_criteria.json",
        {
            "schema": "rvmt.35t.assessment_gate_criteria.v1",
            "status": GATE_CRITERIA_STATUS,
            "sample_rows": [{"sample_id": str(index)} for index in range(13)],
            "checks": {"fixture": True},
        },
    )
    write_json(
        evidence / "hardware_trace_prototype.json",
        {
            "schema": "rvmt.35t.hardware_trace_prototype.v1",
            "status": HARDWARE_TRACE_STATUS,
            "trace_records": 512,
            "trace_profile_policy": "35t_small_capacity",
            "sample_gate_pass_count": 13,
            "decoded_trace_file_count": 65,
        },
    )
    write_json(
        evidence / "local_code_analysis.json",
        {
            "schema": "rvmt.35t.local_code_analysis.v1",
            "status": LOCAL_CODE_STATUS,
            "sample_count": 13,
            "complete_rep_count": 65,
            "expected_rep_count": 65,
        },
    )
    write_json(
        evidence / "malware_behavior_audit.json",
        {
            "schema": "rvmt.35t.malware_behavior_audit.v1",
            "status": MALWARE_AUDIT_STATUS,
            "sample_count": 8,
            "rule_count": 8,
            "gate_expected_rule_pass_count": 8,
        },
    )
    write_json(evidence / "fd_path_case_studies.json", {"schema": "rvmt.35t.fd_path_case_studies.v1", "status": "PASS"})
    write_json(evidence / "process_tree_case_study.json", {"schema": "rvmt.35t.process_tree_case_study.v1", "status": "PASS"})
    write_json(
        evidence / "pointer_semantics_preflight.json",
        {
            "schema": "rvmt.35t.pointer_semantics_preflight.v1",
            "status": "SYNTHETIC_ARG_MEM_GUARDRAILS_PASS_SIDE_CHANNEL_CLOSURE_HARDWARE_POINTER_DEFERRED",
        },
    )
    write_json(
        evidence / "pointer_snapshot_enablement_gate.json",
        {
            "schema": "rvmt.35t.pointer_snapshot_enablement_gate.check.v1",
            "status": "POINTER_SNAPSHOT_ENABLEMENT_GATES_RECORDED_NOT_ENABLED",
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
        evidence / "threat_model_boundary.json",
        {"schema": "rvmt.35t.threat_model_boundary.v1", "status": "TRUSTED_KERNEL_USER_MODE_THREAT_MODEL_BOUNDARY_SPECIFIED"},
    )
    write_json(
        evidence / "helper_alignment.json",
        {"schema": "rvmt.35t.helper_alignment.v1", "status": "TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL"},
    )
    write_json(
        evidence / "baseline_evaluation_summary.json",
        {
            "schema": "rvmt.35t.baseline_evaluation.summary.v1",
            "status": P4_STATUS,
            "baselines": {
                "host_strace": {"status": "PASS"},
                "software_instrumentation": {"status": "PASS"},
                "ebpf_only": {"status": "PASS"},
                "qemu_plugin": {"status": "PASS"},
            },
        },
    )
    write_json(
        evidence / "qemu_plugin_baseline_summary.json",
        {"schema": "rvmt.35t.qemu_plugin_baseline.v1", "status": "QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES", "pass_count": 13},
    )
    write_json(
        evidence / "qemu_plugin_build_preflight.json",
        {
            "schema": "rvmt.35t.qemu_plugin_build_preflight.v1",
            "status": "QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED",
        },
    )
    write_json(
        evidence / "baseline_execution_spec_check.json",
        {"schema": "rvmt.35t.baseline_execution_spec.check.v1", "status": "BASELINE_EXECUTION_SPEC_PASS_CURRENT_ENVIRONMENT_BOUNDED"},
    )
    write_json(
        evidence / "evaluation_table.json",
        {"schema": "rvmt.35t.evaluation_table.v1", "status": "BOUNDED_EVALUATION_TABLE_READY_WITH_EBPF_AND_QEMU_PLUGIN"},
    )
    write_json(
        evidence / "metric_coverage.json",
        {"schema": "rvmt.35t.metric_coverage.v1", "status": "BOUNDED_METRIC_COVERAGE_READY_WITH_DEFERRED_FULL_ACCURACY"},
    )
    write_json(
        evidence / "synthetic_suite_extension_check.json",
        {"schema": "rvmt.35t.synthetic_suite_extension.check.v1", "status": P5_STATUS, "candidate_count": 9, "checks": {"no_expanded_claims": True}},
    )
    write_json(
        evidence / "synthetic_extension_host_smoke.json",
        {"schema": "rvmt.35t.synthetic_extension_host_smoke.v1", "status": "HOST_COMPILE_SMOKE_BLOCKED_CURRENT_ENVIRONMENT"},
    )
    write_json(
        evidence / "synthetic_extension_target_smoke.json",
        {
            "schema": "rvmt.35t.synthetic_extension_target_smoke.v1",
            "status": "TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED",
            "checks": {"no_35t_gating_claim": True},
        },
    )
    write_json(
        evidence / "synthetic_extension_behavior_smoke.json",
        {
            "schema": "rvmt.35t.synthetic_extension_behavior_smoke.v1",
            "status": "HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED",
            "summary_counts": {"executed_candidate_count": 8, "execution_pass_count": 8, "network_skipped_count": 1},
            "checks": {"expected_syscalls_observed_for_executed": True, "no_35t_execution_claim": True},
        },
    )
    write_json(
        evidence / "extension_35t_enablement_preflight.json",
        {
            "schema": "rvmt.35t.extension_35t_enablement_preflight.v1",
            "status": "EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED",
            "checks": {
                "default_dry_run_excludes_extensions": True,
                "explicit_dry_run_selects_non_network_extensions": True,
                "no_expanded_35t_claim": True,
            },
        },
    )
    write_json(
        evidence / "raw_artifact_sanitization.json",
        {
            "schema": "rvmt.35t.raw_artifact_sanitization.v1",
            "status": RAW_ARTIFACT_SANITIZATION_STATUS,
            "checks": {"full_raw_release_deferred": True},
        },
    )
    write_json(
        evidence / "raw_artifact_escrow.json",
        {
            "schema": "rvmt.35t.raw_artifact_escrow.v1",
            "status": RAW_ARTIFACT_ESCROW_STATUS,
            "checks": {"payload_files_present_and_hashed": True, "public_release_deferred": True},
        },
    )
    write_json(
        evidence / "artifact_package_readiness.json",
        {"schema": "rvmt.35t.artifact_package_readiness.v1", "status": ARTIFACT_READINESS_STATUS, "missing_classes": []},
    )
    write_json(
        evidence / "paper_artifact_package_manifest.json",
        {
            "schema": "rvmt.35t.paper_artifact_package_manifest.v1",
            "status": PACKAGE_STATUS,
            "lightweight_evidence_files": [
                "docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_requirement_matrix.json",
                "docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_requirement_matrix.md",
                "docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_sanitization.json",
                "docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_sanitization.md",
                "docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_escrow.json",
                "docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_escrow.md",
            ],
        },
    )
    write_json(evidence / "paper_artifact_release_policy.json", {"schema": "rvmt.35t.paper_artifact_release_policy.v1", "status": "PASS"})
    external = sorted(REQUIRED_OPEN_EXTERNAL_IDS)
    if omit_external:
        external.remove("p3_hardware_user_pointer_snapshot")
    write_json(
        evidence / "remaining_external_work.json",
        {
            "schema": "rvmt.35t.remaining_external_work.v1",
            "status": REMAINING_STATUS,
            "records": [{"id": item} for item in external],
            "satisfied_conditions": [{"id": item} for item in sorted(REQUIRED_SATISFIED_IDS)],
        },
    )
    write_json(
        evidence / "paper_positioning.json",
        {
            "schema": "rvmt.35t.paper_positioning.v1",
            "status": PAPER_POSITIONING_STATUS,
            "supported_positioning": ["low-cost FPGA feasibility / constrained-board prototype evaluation"],
            "forbidden_positioning": ["main CCF-A contribution by itself"],
            "positive_forbidden_findings": [],
            "checks": {"remaining_external_work_recorded": True},
        },
    )
    write_json(
        evidence / "paper_evidence_check.json",
        {
            "schema": "rvmt.35t.paper_evidence_check.v1",
            "status": "PASS",
            "paper_support_status": "SUPPORTED_WITH_BOUNDED_CLAIMS",
        },
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(root, root / "assessment.md", DEFAULT_EVIDENCE_ROOT)
        if report["status"] != STATUS:
            print("[FAIL] expected requirement matrix fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2, ensure_ascii=False), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "assessment_requirement_matrix.md").is_file():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, omit_external=True)
        report = build_report(root, root / "assessment.md", DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL" or not any("remaining_ids" in item for item in report["failures"]):
            print("[FAIL] expected omitted external-work fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2, ensure_ascii=False), file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, missing_token=True)
        report = build_report(root, root / "assessment.md", DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL" or not any("assessment_tokens_present" in item for item in report["failures"]):
            print("[FAIL] expected missing source token fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2, ensure_ascii=False), file=sys.stderr)
            return 1
    print("[PASS] 35T assessment requirement matrix self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check source-assessment section requirements against current 35T evidence.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--assessment", type=Path, default=DEFAULT_ASSESSMENT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.assessment, args.evidence_root)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_assessment_requirement_matrix: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T assessment requirement matrix")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
