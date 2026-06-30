from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    file_digest,
    load_json,
    read_json,
    rel,
    repo_path,
    write_json,
)


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
EXPECTED_STATUS = "PASS"
EXPECTED_CLOSURE_STATUS = "PASS_WITH_BOUNDED_REMAINING_WORK"
EXPECTED_ARTIFACT_READINESS_STATUS = "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED"
EXPECTED_PACKAGE_STATUS = "LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED"
EXPECTED_REMAINING_EXTERNAL_WORK_STATUS = "PASS_CURRENT_EXTERNAL_CONDITIONS_RECORDED"
EXPECTED_POINTER_DESIGN_REVIEW_STATUS = "POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED"
EXPECTED_PAPER_POSITIONING_STATUS = "BOUNDED_FEASIBILITY_POSITIONING_READY"
EXPECTED_ASSESSMENT_RECONCILIATION_STATUS = "CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT"
EXPECTED_ASSESSMENT_GATE_CRITERIA_STATUS = "ASSESSMENT_GATE_CRITERIA_PASS"
EXPECTED_ASSESSMENT_REQUIREMENT_MATRIX_STATUS = "ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK"
EXPECTED_HARDWARE_TRACE_PROTOTYPE_STATUS = "HARDWARE_TRACE_PROTOTYPE_PASS_35T_SMALL_CAPACITY"
EXPECTED_LOCAL_CODE_ANALYSIS_STATUS = "LOCAL_CODE_ANALYSIS_PROTOTYPE_PASS_WITH_BOUNDED_ATTRIBUTION"
EXPECTED_MALWARE_BEHAVIOR_AUDIT_STATUS = "SYNTHETIC_MALWARE_LIKE_BEHAVIOR_AUDIT_PASS_REAL_MALWARE_DEFERRED"
EXPECTED_RAW_ARTIFACT_SANITIZATION_STATUS = "RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED"
EXPECTED_RAW_ARTIFACT_ESCROW_STATUS = "LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED"
EXPECTED_HELPER_ALIGNMENT_STATUS = "TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL"
EXPECTED_QEMU_PLUGIN_BUILD_PREFLIGHT_STATUS = "QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED"
EXPECTED_QEMU_PLUGIN_BASELINE_STATUS = "QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES"
EXPECTED_EXTENSION_ENABLEMENT_PREFLIGHT_STATUS = "EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED"
EXPECTED_EXTENSION_BEHAVIOR_SMOKE_STATUS = "HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED"


def manifest_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    rows = manifest.get("committed_artifacts", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def goal_by_id(closure: dict[str, Any]) -> dict[str, dict[str, Any]]:
    goals = closure.get("goals", [])
    return {
        str(goal.get("id")): goal
        for goal in goals
        if isinstance(goal, dict) and goal.get("id")
    } if isinstance(goals, list) else {}


def trace_goal_by_id(traceability: dict[str, Any]) -> dict[str, dict[str, Any]]:
    goals = traceability.get("goals", [])
    return {
        str(goal.get("id")): goal
        for goal in goals
        if isinstance(goal, dict) and goal.get("id")
    } if isinstance(goals, list) else {}


def evidence_files(evidence_root: Path) -> set[str]:
    if not evidence_root.is_dir():
        return set()
    return {
        path.name
        for path in evidence_root.iterdir()
        if path.is_file() and path.name != "evidence_manifest.json"
    }


def manifest_hash_errors(repo_root: Path, rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for row in rows:
        artifact = str(row.get("artifact") or "")
        committed_path = row.get("committed_path")
        if not artifact:
            errors.append("manifest row missing artifact name")
            continue
        if artifact in seen:
            errors.append(f"duplicate manifest artifact: {artifact}")
        seen.add(artifact)
        if not isinstance(committed_path, str) or not committed_path:
            errors.append(f"{artifact}: missing committed_path")
            continue
        path = repo_path(repo_root, Path(committed_path))
        if path.name != artifact:
            errors.append(f"{artifact}: artifact name does not match committed_path basename {path.name}")
        if not path.is_file():
            errors.append(f"{artifact}: committed_path does not exist: {rel(path, repo_root)}")
            continue
        if row.get("bytes") != path.stat().st_size:
            errors.append(f"{artifact}: byte count mismatch")
        if row.get("sha256") != file_digest(path):
            errors.append(f"{artifact}: sha256 mismatch")
    return errors


def package_files_exist(repo_root: Path, package_manifest: dict[str, Any]) -> bool:
    files = package_manifest.get("lightweight_evidence_files", [])
    if not isinstance(files, list) or not files:
        return False
    return all(isinstance(path, str) and repo_path(repo_root, Path(path)).is_file() for path in files)


def package_includes_required_files(package_manifest: dict[str, Any]) -> bool:
    files = {
        Path(str(path)).name
        for path in package_manifest.get("lightweight_evidence_files", [])
        if isinstance(path, str)
    }
    required = {
        "assessment_closure.json",
        "assessment_closure.md",
        "assessment_traceability.json",
        "assessment_traceability.md",
        "assessment_requirement_matrix.json",
        "assessment_requirement_matrix.md",
        "assessment_reconciliation.json",
        "assessment_reconciliation.md",
        "assessment_gate_criteria.json",
        "assessment_gate_criteria.md",
        "hardware_trace_prototype.json",
        "hardware_trace_prototype.md",
        "local_code_analysis.json",
        "local_code_analysis.md",
        "malware_behavior_audit.json",
        "malware_behavior_audit.md",
        "raw_artifact_sanitization.json",
        "raw_artifact_sanitization.md",
        "raw_artifact_escrow.json",
        "raw_artifact_escrow.md",
        "artifact_package_readiness.json",
        "artifact_package_readiness.md",
        "paper_evidence_check.json",
        "paper_evidence_check.md",
        "paper_positioning.json",
        "paper_positioning.md",
        "ebpf_baseline_summary.json",
        "ebpf_baseline_summary.md",
        "pointer_snapshot_design_review.json",
        "pointer_snapshot_design_review.md",
        "qemu_plugin_build_preflight.json",
        "qemu_plugin_build_preflight.md",
        "qemu_plugin_baseline_summary.json",
        "qemu_plugin_baseline_summary.md",
        "extension_35t_enablement_preflight.json",
        "extension_35t_enablement_preflight.md",
        "synthetic_extension_target_smoke.json",
        "synthetic_extension_target_smoke.md",
        "synthetic_extension_behavior_smoke.json",
        "synthetic_extension_behavior_smoke.md",
        "helper_alignment.json",
        "helper_alignment.md",
        "remaining_external_work.json",
        "remaining_external_work.md",
    }
    return required <= files


def command_list_contains(manifest: dict[str, Any], key: str, needle: str) -> bool:
    commands = manifest.get(key, [])
    return any(isinstance(command, str) and needle in command for command in commands) if isinstance(commands, list) else False


def text_contains(path: Path, needle: str) -> bool:
    return path.is_file() and needle in path.read_text(encoding="utf-8")


def build_report(repo_root: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    failures: list[str] = []
    manifest = read_json(evidence_root / "evidence_manifest.json", failures, repo_root, "evidence manifest")
    closure = read_json(evidence_root / "assessment_closure.json", failures, repo_root, "assessment closure")
    traceability = read_json(evidence_root / "assessment_traceability.json", failures, repo_root, "assessment traceability")
    requirement_matrix = read_json(evidence_root / "assessment_requirement_matrix.json", failures, repo_root, "assessment requirement matrix")
    reconciliation = read_json(evidence_root / "assessment_reconciliation.json", failures, repo_root, "assessment reconciliation")
    gate_criteria = read_json(evidence_root / "assessment_gate_criteria.json", failures, repo_root, "assessment gate criteria")
    hardware_trace = read_json(evidence_root / "hardware_trace_prototype.json", failures, repo_root, "hardware trace prototype")
    local_code_analysis = read_json(evidence_root / "local_code_analysis.json", failures, repo_root, "local code analysis")
    malware_behavior_audit = read_json(evidence_root / "malware_behavior_audit.json", failures, repo_root, "malware behavior audit")
    raw_artifact_sanitization = read_json(evidence_root / "raw_artifact_sanitization.json", failures, repo_root, "raw artifact sanitization")
    raw_artifact_escrow = read_json(evidence_root / "raw_artifact_escrow.json", failures, repo_root, "raw artifact escrow")
    pointer_design = read_json(evidence_root / "pointer_snapshot_design_review.json", failures, repo_root, "pointer snapshot design review")
    remaining_external_work = read_json(evidence_root / "remaining_external_work.json", failures, repo_root, "remaining external work")
    helper_alignment = read_json(evidence_root / "helper_alignment.json", failures, repo_root, "helper alignment")
    qemu_plugin_build = read_json(evidence_root / "qemu_plugin_build_preflight.json", failures, repo_root, "QEMU-plugin build preflight")
    qemu_plugin_baseline = read_json(evidence_root / "qemu_plugin_baseline_summary.json", failures, repo_root, "QEMU-plugin baseline")
    extension_enablement = read_json(evidence_root / "extension_35t_enablement_preflight.json", failures, repo_root, "extension 35T enablement preflight")
    extension_behavior = read_json(evidence_root / "synthetic_extension_behavior_smoke.json", failures, repo_root, "synthetic extension behavior smoke")
    paper_positioning = read_json(evidence_root / "paper_positioning.json", failures, repo_root, "paper positioning")
    artifact_readiness = read_json(evidence_root / "artifact_package_readiness.json", failures, repo_root, "artifact package readiness")
    package_manifest = read_json(evidence_root / "paper_artifact_package_manifest.json", failures, repo_root, "paper artifact package manifest")

    rows = manifest_rows(manifest)
    manifest_names = {str(row.get("artifact")) for row in rows if row.get("artifact")}
    actual_names = evidence_files(evidence_root)
    hash_errors = manifest_hash_errors(repo_root, rows)

    closure_goals = goal_by_id(closure)
    trace_goals = trace_goal_by_id(traceability)
    p6 = closure_goals.get("P6_artifact_package", {})
    p6_evidence = p6.get("evidence", {}) if isinstance(p6.get("evidence"), dict) else {}

    closure_status_by_goal = {key: str(value.get("status")) for key, value in closure_goals.items()}
    trace_status_by_goal = {key: str(value.get("status")) for key, value in trace_goals.items()}

    workflow = repo_root / ".github/workflows/35t-closure.yml"
    paper_evidence_tool = repo_root / "tools/check_35t_paper_evidence.py"
    readiness_tool = repo_root / "tools/check_35t_artifact_package_readiness.py"
    packager_tool = repo_root / "tools/package_35t_paper_artifacts.py"
    remaining_tool = "tools/check_35t_remaining_external_work.py"
    consistency_tool = "tools/check_35t_evidence_consistency.py"
    positioning_tool = "tools/check_35t_paper_positioning.py"
    reconciliation_tool = "tools/check_35t_assessment_reconciliation.py"
    gate_criteria_tool = "tools/check_35t_assessment_gate_criteria.py"
    requirement_matrix_tool = "tools/check_35t_assessment_requirement_matrix.py"
    hardware_trace_tool = "tools/check_35t_hardware_trace_prototype.py"
    local_code_analysis_tool = "tools/check_35t_local_code_analysis.py"
    malware_behavior_audit_tool = "tools/check_35t_malware_behavior_audit.py"
    raw_artifact_sanitization_tool = "tools/check_35t_raw_artifact_sanitization.py"
    raw_artifact_escrow_tool = "tools/check_35t_raw_artifact_escrow.py"
    synthetic_extension_target_tool = "tools/check_35t_synthetic_extension_target_smoke.py"
    synthetic_extension_behavior_tool = "tools/check_35t_synthetic_extension_behavior_smoke.py"
    extension_enablement_tool = "tools/check_35t_extension_35t_enablement.py"
    helper_alignment_tool = "tools/check_35t_helper_alignment.py"
    qemu_plugin_build_tool = "tools/check_35t_qemu_plugin_build_preflight.py"
    qemu_plugin_baseline_tool = "tools/run_35t_qemu_plugin_baseline.py"
    pointer_design_tool = "tools/check_35t_pointer_snapshot_design_review.py"

    checks = {
        "evidence_root_exists": evidence_root.is_dir(),
        "manifest_schema": manifest.get("schema") == "rvmt.35t.evidence_snapshot.v1",
        "manifest_rows_nonempty": bool(rows),
        "manifest_hashes_match": not hash_errors,
        "manifest_covers_current_evidence_files": manifest_names == actual_names,
        "closure_schema": closure.get("schema") == "rvmt.35t.assessment_closure.v1",
        "closure_status": closure.get("status") == EXPECTED_CLOSURE_STATUS,
        "traceability_schema": traceability.get("schema") == "rvmt.35t.assessment_traceability.v1",
        "traceability_status_matches_closure": traceability.get("status") == closure.get("status"),
        "traceability_goal_statuses_match_closure": trace_status_by_goal == closure_status_by_goal,
        "assessment_requirement_matrix_schema": requirement_matrix.get("schema") == "rvmt.35t.assessment_requirement_matrix.v1",
        "assessment_requirement_matrix_status": requirement_matrix.get("status") == EXPECTED_ASSESSMENT_REQUIREMENT_MATRIX_STATUS,
        "assessment_requirement_matrix_count": requirement_matrix.get("requirement_count") == 14,
        "assessment_reconciliation_schema": reconciliation.get("schema") == "rvmt.35t.assessment_reconciliation.v1",
        "assessment_reconciliation_status": reconciliation.get("status") == EXPECTED_ASSESSMENT_RECONCILIATION_STATUS,
        "assessment_gate_criteria_schema": gate_criteria.get("schema") == "rvmt.35t.assessment_gate_criteria.v1",
        "assessment_gate_criteria_status": gate_criteria.get("status") == EXPECTED_ASSESSMENT_GATE_CRITERIA_STATUS,
        "hardware_trace_prototype_schema": hardware_trace.get("schema") == "rvmt.35t.hardware_trace_prototype.v1",
        "hardware_trace_prototype_status": hardware_trace.get("status") == EXPECTED_HARDWARE_TRACE_PROTOTYPE_STATUS,
        "local_code_analysis_schema": local_code_analysis.get("schema") == "rvmt.35t.local_code_analysis.v1",
        "local_code_analysis_status": local_code_analysis.get("status") == EXPECTED_LOCAL_CODE_ANALYSIS_STATUS,
        "malware_behavior_audit_schema": malware_behavior_audit.get("schema") == "rvmt.35t.malware_behavior_audit.v1",
        "malware_behavior_audit_status": malware_behavior_audit.get("status") == EXPECTED_MALWARE_BEHAVIOR_AUDIT_STATUS,
        "raw_artifact_sanitization_schema": raw_artifact_sanitization.get("schema") == "rvmt.35t.raw_artifact_sanitization.v1",
        "raw_artifact_sanitization_status": raw_artifact_sanitization.get("status") == EXPECTED_RAW_ARTIFACT_SANITIZATION_STATUS,
        "raw_artifact_sanitization_full_raw_deferred": raw_artifact_sanitization.get("checks", {}).get("full_raw_release_deferred") is True
        if isinstance(raw_artifact_sanitization.get("checks"), dict)
        else False,
        "raw_artifact_escrow_schema": raw_artifact_escrow.get("schema") == "rvmt.35t.raw_artifact_escrow.v1",
        "raw_artifact_escrow_status": raw_artifact_escrow.get("status") == EXPECTED_RAW_ARTIFACT_ESCROW_STATUS,
        "raw_artifact_escrow_payload_hashed": raw_artifact_escrow.get("checks", {}).get("payload_files_present_and_hashed") is True
        if isinstance(raw_artifact_escrow.get("checks"), dict)
        else False,
        "raw_artifact_escrow_public_release_deferred": raw_artifact_escrow.get("checks", {}).get("public_release_deferred") is True
        if isinstance(raw_artifact_escrow.get("checks"), dict)
        else False,
        "pointer_snapshot_design_review_schema": pointer_design.get("schema") == "rvmt.35t.pointer_snapshot_design_review.check.v1",
        "pointer_snapshot_design_review_status": pointer_design.get("status") == EXPECTED_POINTER_DESIGN_REVIEW_STATUS,
        "pointer_snapshot_design_review_default_disabled": pointer_design.get("checks", {}).get("current_policy_default_disabled") is True
        if isinstance(pointer_design.get("checks"), dict)
        else False,
        "remaining_external_work_schema": remaining_external_work.get("schema") == "rvmt.35t.remaining_external_work.v1",
        "remaining_external_work_status": remaining_external_work.get("status") == EXPECTED_REMAINING_EXTERNAL_WORK_STATUS,
        "helper_alignment_schema": helper_alignment.get("schema") == "rvmt.35t.helper_alignment.v1",
        "helper_alignment_status": helper_alignment.get("status") == EXPECTED_HELPER_ALIGNMENT_STATUS,
        "qemu_plugin_build_preflight_schema": qemu_plugin_build.get("schema") == "rvmt.35t.qemu_plugin_build_preflight.v1",
        "qemu_plugin_build_preflight_status": qemu_plugin_build.get("status") == EXPECTED_QEMU_PLUGIN_BUILD_PREFLIGHT_STATUS,
        "qemu_plugin_baseline_schema": qemu_plugin_baseline.get("schema") == "rvmt.35t.qemu_plugin_baseline.v1",
        "qemu_plugin_baseline_status": qemu_plugin_baseline.get("status") == EXPECTED_QEMU_PLUGIN_BASELINE_STATUS,
        "qemu_plugin_baseline_pass_count": qemu_plugin_baseline.get("pass_count") == 13,
        "extension_enablement_preflight_schema": extension_enablement.get("schema")
        == "rvmt.35t.extension_35t_enablement_preflight.v1",
        "extension_enablement_preflight_status": extension_enablement.get("status")
        == EXPECTED_EXTENSION_ENABLEMENT_PREFLIGHT_STATUS,
        "extension_behavior_smoke_schema": extension_behavior.get("schema")
        == "rvmt.35t.synthetic_extension_behavior_smoke.v1",
        "extension_behavior_smoke_status": extension_behavior.get("status") == EXPECTED_EXTENSION_BEHAVIOR_SMOKE_STATUS,
        "extension_behavior_smoke_counts": extension_behavior.get("summary_counts", {}).get("execution_pass_count") == 8
        and extension_behavior.get("summary_counts", {}).get("network_skipped_count") == 1
        if isinstance(extension_behavior.get("summary_counts"), dict)
        else False,
        "extension_behavior_smoke_expected_syscalls": extension_behavior.get("checks", {}).get("expected_syscalls_observed_for_executed")
        is True
        if isinstance(extension_behavior.get("checks"), dict)
        else False,
        "extension_behavior_smoke_no_35t_claim": extension_behavior.get("checks", {}).get("no_35t_execution_claim") is True
        if isinstance(extension_behavior.get("checks"), dict)
        else False,
        "paper_positioning_schema": paper_positioning.get("schema") == "rvmt.35t.paper_positioning.v1",
        "paper_positioning_status": paper_positioning.get("status") == EXPECTED_PAPER_POSITIONING_STATUS,
        "p6_committed_artifact_count_matches_manifest": p6_evidence.get("committed_artifact_count") == len(rows),
        "p6_artifact_readiness_status_matches": p6_evidence.get("artifact_readiness_status") == artifact_readiness.get("status"),
        "p6_paper_package_status_matches": p6_evidence.get("paper_package_status") == package_manifest.get("status"),
        "artifact_readiness_status": artifact_readiness.get("status") == EXPECTED_ARTIFACT_READINESS_STATUS,
        "package_status": package_manifest.get("status") == EXPECTED_PACKAGE_STATUS,
        "package_readiness_status_matches": package_manifest.get("readiness", {}).get("status") == artifact_readiness.get("status")
        if isinstance(package_manifest.get("readiness"), dict)
        else False,
        "package_lightweight_files_exist": package_files_exist(repo_root, package_manifest),
        "package_includes_required_evidence": package_includes_required_files(package_manifest),
        "package_validation_includes_remaining_external_work": command_list_contains(package_manifest, "validation_commands", remaining_tool),
        "package_reproduction_includes_remaining_external_work": command_list_contains(package_manifest, "reproduction_commands", remaining_tool),
        "package_validation_includes_paper_positioning": command_list_contains(package_manifest, "validation_commands", positioning_tool),
        "package_reproduction_includes_paper_positioning": command_list_contains(package_manifest, "reproduction_commands", positioning_tool),
        "package_validation_includes_assessment_reconciliation": command_list_contains(package_manifest, "validation_commands", reconciliation_tool),
        "package_reproduction_includes_assessment_reconciliation": command_list_contains(package_manifest, "reproduction_commands", reconciliation_tool),
        "package_validation_includes_assessment_gate_criteria": command_list_contains(package_manifest, "validation_commands", gate_criteria_tool),
        "package_reproduction_includes_assessment_gate_criteria": command_list_contains(package_manifest, "reproduction_commands", gate_criteria_tool),
        "package_validation_includes_assessment_requirement_matrix": command_list_contains(package_manifest, "validation_commands", requirement_matrix_tool),
        "package_reproduction_includes_assessment_requirement_matrix": command_list_contains(package_manifest, "reproduction_commands", requirement_matrix_tool),
        "package_validation_includes_hardware_trace_prototype": command_list_contains(package_manifest, "validation_commands", hardware_trace_tool),
        "package_reproduction_includes_hardware_trace_prototype": command_list_contains(package_manifest, "reproduction_commands", hardware_trace_tool),
        "package_validation_includes_local_code_analysis": command_list_contains(package_manifest, "validation_commands", local_code_analysis_tool),
        "package_reproduction_includes_local_code_analysis": command_list_contains(package_manifest, "reproduction_commands", local_code_analysis_tool),
        "package_validation_includes_malware_behavior_audit": command_list_contains(package_manifest, "validation_commands", malware_behavior_audit_tool),
        "package_reproduction_includes_malware_behavior_audit": command_list_contains(package_manifest, "reproduction_commands", malware_behavior_audit_tool),
        "package_validation_includes_raw_artifact_sanitization": command_list_contains(package_manifest, "validation_commands", raw_artifact_sanitization_tool),
        "package_reproduction_includes_raw_artifact_sanitization": command_list_contains(package_manifest, "reproduction_commands", raw_artifact_sanitization_tool),
        "package_validation_includes_raw_artifact_escrow": command_list_contains(package_manifest, "validation_commands", raw_artifact_escrow_tool),
        "package_reproduction_includes_raw_artifact_escrow": command_list_contains(package_manifest, "reproduction_commands", raw_artifact_escrow_tool),
        "package_validation_includes_synthetic_extension_target_smoke": command_list_contains(package_manifest, "validation_commands", synthetic_extension_target_tool),
        "package_reproduction_includes_synthetic_extension_target_smoke": command_list_contains(package_manifest, "reproduction_commands", synthetic_extension_target_tool),
        "package_validation_includes_synthetic_extension_behavior_smoke": command_list_contains(package_manifest, "validation_commands", synthetic_extension_behavior_tool),
        "package_reproduction_includes_synthetic_extension_behavior_smoke": command_list_contains(package_manifest, "reproduction_commands", synthetic_extension_behavior_tool),
        "package_validation_includes_extension_enablement_preflight": command_list_contains(package_manifest, "validation_commands", extension_enablement_tool),
        "package_reproduction_includes_extension_enablement_preflight": command_list_contains(package_manifest, "reproduction_commands", extension_enablement_tool),
        "package_validation_includes_helper_alignment": command_list_contains(package_manifest, "validation_commands", helper_alignment_tool),
        "package_reproduction_includes_helper_alignment": command_list_contains(package_manifest, "reproduction_commands", helper_alignment_tool),
        "package_validation_includes_qemu_plugin_build_preflight": command_list_contains(package_manifest, "validation_commands", qemu_plugin_build_tool),
        "package_reproduction_includes_qemu_plugin_build_preflight": command_list_contains(package_manifest, "reproduction_commands", qemu_plugin_build_tool),
        "package_validation_includes_qemu_plugin_baseline": command_list_contains(package_manifest, "validation_commands", qemu_plugin_baseline_tool),
        "package_reproduction_includes_qemu_plugin_baseline": command_list_contains(package_manifest, "reproduction_commands", qemu_plugin_baseline_tool),
        "package_validation_includes_pointer_design_review": command_list_contains(package_manifest, "validation_commands", pointer_design_tool),
        "package_reproduction_includes_pointer_design_review": command_list_contains(package_manifest, "reproduction_commands", pointer_design_tool),
        "package_validation_includes_consistency": command_list_contains(package_manifest, "validation_commands", consistency_tool),
        "package_reproduction_includes_consistency": command_list_contains(package_manifest, "reproduction_commands", consistency_tool),
        "workflow_runs_remaining_external_work_self_test": text_contains(workflow, f"{remaining_tool} --self-test"),
        "workflow_runs_remaining_external_work_no_write": text_contains(workflow, f"{remaining_tool} --no-write"),
        "workflow_runs_consistency_self_test": text_contains(workflow, f"{consistency_tool} --self-test"),
        "workflow_runs_consistency_no_write": text_contains(workflow, f"{consistency_tool} --no-write"),
        "workflow_runs_paper_positioning_self_test": text_contains(workflow, f"{positioning_tool} --self-test"),
        "workflow_runs_assessment_reconciliation_self_test": text_contains(workflow, f"{reconciliation_tool} --self-test"),
        "workflow_runs_assessment_gate_criteria_self_test": text_contains(workflow, f"{gate_criteria_tool} --self-test"),
        "workflow_runs_assessment_requirement_matrix_self_test": text_contains(workflow, f"{requirement_matrix_tool} --self-test"),
        "workflow_runs_assessment_requirement_matrix_no_write": text_contains(workflow, f"{requirement_matrix_tool} --no-write"),
        "workflow_runs_hardware_trace_prototype_self_test": text_contains(workflow, f"{hardware_trace_tool} --self-test"),
        "workflow_runs_local_code_analysis_self_test": text_contains(workflow, f"{local_code_analysis_tool} --self-test"),
        "workflow_runs_malware_behavior_audit_self_test": text_contains(workflow, f"{malware_behavior_audit_tool} --self-test"),
        "workflow_runs_raw_artifact_sanitization_self_test": text_contains(workflow, f"{raw_artifact_sanitization_tool} --self-test"),
        "workflow_runs_raw_artifact_sanitization_no_write": text_contains(workflow, f"{raw_artifact_sanitization_tool} --no-write"),
        "workflow_runs_raw_artifact_escrow_self_test": text_contains(workflow, f"{raw_artifact_escrow_tool} --self-test"),
        "workflow_runs_raw_artifact_escrow_no_write": text_contains(workflow, f"{raw_artifact_escrow_tool} --no-write"),
        "workflow_runs_synthetic_extension_target_self_test": text_contains(workflow, f"{synthetic_extension_target_tool} --self-test"),
        "workflow_runs_synthetic_extension_target_no_write": text_contains(workflow, f"{synthetic_extension_target_tool} --no-write"),
        "workflow_runs_synthetic_extension_behavior_self_test": text_contains(workflow, f"{synthetic_extension_behavior_tool} --self-test"),
        "workflow_runs_extension_enablement_self_test": text_contains(workflow, f"{extension_enablement_tool} --self-test"),
        "workflow_runs_extension_enablement_no_write": text_contains(workflow, f"{extension_enablement_tool} --no-write"),
        "workflow_runs_helper_alignment_self_test": text_contains(workflow, f"{helper_alignment_tool} --self-test"),
        "workflow_runs_helper_alignment_no_write": text_contains(workflow, f"{helper_alignment_tool} --no-write"),
        "workflow_runs_qemu_plugin_build_preflight_self_test": text_contains(workflow, f"{qemu_plugin_build_tool} --self-test"),
        "workflow_runs_qemu_plugin_baseline_self_test": text_contains(workflow, f"{qemu_plugin_baseline_tool} --self-test"),
        "workflow_runs_pointer_snapshot_design_review_self_test": text_contains(workflow, f"{pointer_design_tool} --self-test"),
        "workflow_runs_pointer_snapshot_design_review_no_write": text_contains(workflow, f"{pointer_design_tool} --no-write"),
        "paper_evidence_requires_remaining_external_work_workflow": text_contains(paper_evidence_tool, "remaining_external_work_no_write"),
        "paper_evidence_requires_consistency_workflow": text_contains(paper_evidence_tool, "evidence_consistency_no_write"),
        "paper_evidence_requires_positioning_workflow": text_contains(paper_evidence_tool, "paper_positioning_self_test"),
        "paper_evidence_requires_reconciliation_workflow": text_contains(paper_evidence_tool, "assessment_reconciliation_self_test"),
        "paper_evidence_requires_gate_criteria_workflow": text_contains(paper_evidence_tool, "assessment_gate_criteria_self_test"),
        "paper_evidence_requires_requirement_matrix_workflow": text_contains(paper_evidence_tool, "assessment_requirement_matrix_self_test"),
        "paper_evidence_requires_hardware_trace_prototype_workflow": text_contains(paper_evidence_tool, "hardware_trace_prototype_self_test"),
        "paper_evidence_requires_local_code_analysis_workflow": text_contains(paper_evidence_tool, "local_code_analysis_self_test"),
        "paper_evidence_requires_malware_behavior_audit_workflow": text_contains(paper_evidence_tool, "malware_behavior_audit_self_test"),
        "paper_evidence_requires_raw_artifact_sanitization_workflow": text_contains(paper_evidence_tool, "raw_artifact_sanitization_self_test"),
        "paper_evidence_requires_raw_artifact_escrow_workflow": text_contains(paper_evidence_tool, "raw_artifact_escrow_self_test"),
        "paper_evidence_requires_synthetic_extension_behavior_workflow": text_contains(paper_evidence_tool, "synthetic_extension_behavior_smoke_self_test"),
        "paper_evidence_requires_gate_criteria": text_contains(paper_evidence_tool, "assessment_gate_criteria.json"),
        "paper_evidence_requires_requirement_matrix": text_contains(paper_evidence_tool, "assessment_requirement_matrix.json"),
        "paper_evidence_requires_hardware_trace_prototype": text_contains(paper_evidence_tool, "hardware_trace_prototype.json"),
        "paper_evidence_requires_local_code_analysis": text_contains(paper_evidence_tool, "local_code_analysis.json"),
        "paper_evidence_requires_malware_behavior_audit": text_contains(paper_evidence_tool, "malware_behavior_audit.json"),
        "paper_evidence_requires_raw_artifact_sanitization": text_contains(paper_evidence_tool, "raw_artifact_sanitization.json"),
        "paper_evidence_requires_raw_artifact_escrow": text_contains(paper_evidence_tool, "raw_artifact_escrow.json"),
        "artifact_readiness_lists_remaining_external_work_tool": text_contains(readiness_tool, remaining_tool),
        "artifact_readiness_lists_consistency_tool": text_contains(readiness_tool, consistency_tool),
        "artifact_readiness_lists_paper_positioning_tool": text_contains(readiness_tool, positioning_tool),
        "artifact_readiness_lists_assessment_reconciliation_tool": text_contains(readiness_tool, reconciliation_tool),
        "artifact_readiness_lists_assessment_gate_criteria_tool": text_contains(readiness_tool, gate_criteria_tool),
        "artifact_readiness_lists_assessment_requirement_matrix_tool": text_contains(readiness_tool, requirement_matrix_tool),
        "artifact_readiness_lists_hardware_trace_prototype_tool": text_contains(readiness_tool, hardware_trace_tool),
        "artifact_readiness_lists_local_code_analysis_tool": text_contains(readiness_tool, local_code_analysis_tool),
        "artifact_readiness_lists_malware_behavior_audit_tool": text_contains(readiness_tool, malware_behavior_audit_tool),
        "artifact_readiness_lists_raw_artifact_sanitization_tool": text_contains(readiness_tool, raw_artifact_sanitization_tool),
        "artifact_readiness_lists_raw_artifact_escrow_tool": text_contains(readiness_tool, raw_artifact_escrow_tool),
        "artifact_readiness_lists_synthetic_extension_target_tool": text_contains(readiness_tool, synthetic_extension_target_tool),
        "artifact_readiness_lists_synthetic_extension_behavior_tool": text_contains(readiness_tool, synthetic_extension_behavior_tool),
        "artifact_readiness_lists_extension_enablement_tool": text_contains(readiness_tool, extension_enablement_tool),
        "artifact_readiness_lists_helper_alignment_tool": text_contains(readiness_tool, helper_alignment_tool),
        "artifact_readiness_lists_qemu_plugin_build_preflight_tool": text_contains(readiness_tool, qemu_plugin_build_tool),
        "artifact_readiness_lists_qemu_plugin_baseline_tool": text_contains(readiness_tool, qemu_plugin_baseline_tool),
        "artifact_readiness_lists_pointer_design_review_tool": text_contains(readiness_tool, pointer_design_tool),
        "packager_lists_remaining_external_work_tool": text_contains(packager_tool, remaining_tool),
        "packager_lists_consistency_tool": text_contains(packager_tool, consistency_tool),
        "packager_lists_paper_positioning_tool": text_contains(packager_tool, positioning_tool),
        "packager_lists_assessment_reconciliation_tool": text_contains(packager_tool, reconciliation_tool),
        "packager_lists_assessment_gate_criteria_tool": text_contains(packager_tool, gate_criteria_tool),
        "packager_lists_assessment_requirement_matrix_tool": text_contains(packager_tool, requirement_matrix_tool),
        "packager_lists_hardware_trace_prototype_tool": text_contains(packager_tool, hardware_trace_tool),
        "packager_lists_local_code_analysis_tool": text_contains(packager_tool, local_code_analysis_tool),
        "packager_lists_malware_behavior_audit_tool": text_contains(packager_tool, malware_behavior_audit_tool),
        "packager_lists_raw_artifact_sanitization_tool": text_contains(packager_tool, raw_artifact_sanitization_tool),
        "packager_lists_raw_artifact_escrow_tool": text_contains(packager_tool, raw_artifact_escrow_tool),
        "packager_lists_synthetic_extension_target_tool": text_contains(packager_tool, synthetic_extension_target_tool),
        "packager_lists_synthetic_extension_behavior_tool": text_contains(packager_tool, synthetic_extension_behavior_tool),
        "packager_lists_extension_enablement_tool": text_contains(packager_tool, extension_enablement_tool),
        "packager_lists_helper_alignment_tool": text_contains(packager_tool, helper_alignment_tool),
        "packager_lists_qemu_plugin_build_preflight_tool": text_contains(packager_tool, qemu_plugin_build_tool),
        "packager_lists_qemu_plugin_baseline_tool": text_contains(packager_tool, qemu_plugin_baseline_tool),
        "packager_lists_pointer_design_review_tool": text_contains(packager_tool, pointer_design_tool),
    }

    for key, ok in checks.items():
        if not ok:
            failures.append(key)
    failures.extend(hash_errors)
    missing_from_manifest = sorted(actual_names - manifest_names)
    missing_from_disk = sorted(manifest_names - actual_names)
    for name in missing_from_manifest:
        failures.append(f"manifest missing current evidence file: {name}")
    for name in missing_from_disk:
        failures.append(f"manifest references absent evidence file: {name}")

    return {
        "schema": "rvmt.35t.evidence_consistency.v1",
        "run_id": RUN_ID,
        "status": EXPECTED_STATUS if not failures else "FAIL",
        "evidence_root": rel(evidence_root, repo_root),
        "checks": checks,
        "manifest_artifact_count": len(rows),
        "current_evidence_file_count": len(actual_names),
        "closure_goal_statuses": closure_status_by_goal,
        "traceability_goal_statuses": trace_status_by_goal,
        "failures": failures,
    }


def self_test_manifest(root: Path, evidence: Path, *, stale_count: bool = False) -> None:
    closure = {
        "schema": "rvmt.35t.assessment_closure.v1",
        "status": EXPECTED_CLOSURE_STATUS,
        "goals": [
            {"id": "P0_claim_boundary", "status": "PASS", "evidence": {}},
            {
                "id": "P6_artifact_package",
                "status": "LIGHTWEIGHT_ARTIFACT_PASS_FULL_REPRO_DEFERRED",
                "evidence": {
                    "committed_artifact_count": 40 if stale_count else 45,
                    "artifact_readiness_status": EXPECTED_ARTIFACT_READINESS_STATUS,
                    "paper_package_status": EXPECTED_PACKAGE_STATUS,
                },
            },
        ],
    }
    traceability = {
        "schema": "rvmt.35t.assessment_traceability.v1",
        "status": EXPECTED_CLOSURE_STATUS,
        "goals": [
            {"id": "P0_claim_boundary", "status": "PASS"},
            {"id": "P6_artifact_package", "status": "LIGHTWEIGHT_ARTIFACT_PASS_FULL_REPRO_DEFERRED"},
        ],
    }
    requirement_matrix = {
        "schema": "rvmt.35t.assessment_requirement_matrix.v1",
        "status": EXPECTED_ASSESSMENT_REQUIREMENT_MATRIX_STATUS,
        "requirement_count": 14,
    }
    reconciliation = {
        "schema": "rvmt.35t.assessment_reconciliation.v1",
        "status": EXPECTED_ASSESSMENT_RECONCILIATION_STATUS,
    }
    gate_criteria = {
        "schema": "rvmt.35t.assessment_gate_criteria.v1",
        "status": EXPECTED_ASSESSMENT_GATE_CRITERIA_STATUS,
    }
    hardware_trace = {
        "schema": "rvmt.35t.hardware_trace_prototype.v1",
        "status": EXPECTED_HARDWARE_TRACE_PROTOTYPE_STATUS,
    }
    local_code_analysis = {
        "schema": "rvmt.35t.local_code_analysis.v1",
        "status": EXPECTED_LOCAL_CODE_ANALYSIS_STATUS,
    }
    malware_behavior_audit = {
        "schema": "rvmt.35t.malware_behavior_audit.v1",
        "status": EXPECTED_MALWARE_BEHAVIOR_AUDIT_STATUS,
    }
    raw_artifact_sanitization = {
        "schema": "rvmt.35t.raw_artifact_sanitization.v1",
        "status": EXPECTED_RAW_ARTIFACT_SANITIZATION_STATUS,
        "checks": {"full_raw_release_deferred": True},
    }
    raw_artifact_escrow = {
        "schema": "rvmt.35t.raw_artifact_escrow.v1",
        "status": EXPECTED_RAW_ARTIFACT_ESCROW_STATUS,
        "checks": {"payload_files_present_and_hashed": True, "public_release_deferred": True},
    }
    pointer_design = {
        "schema": "rvmt.35t.pointer_snapshot_design_review.check.v1",
        "status": EXPECTED_POINTER_DESIGN_REVIEW_STATUS,
        "checks": {"current_policy_default_disabled": True},
    }
    readiness = {
        "schema": "rvmt.35t.artifact_package_readiness.v1",
        "status": EXPECTED_ARTIFACT_READINESS_STATUS,
    }
    remaining = {
        "schema": "rvmt.35t.remaining_external_work.v1",
        "status": EXPECTED_REMAINING_EXTERNAL_WORK_STATUS,
    }
    helper_alignment = {
        "schema": "rvmt.35t.helper_alignment.v1",
        "status": EXPECTED_HELPER_ALIGNMENT_STATUS,
    }
    qemu_plugin_build = {
        "schema": "rvmt.35t.qemu_plugin_build_preflight.v1",
        "status": EXPECTED_QEMU_PLUGIN_BUILD_PREFLIGHT_STATUS,
    }
    qemu_plugin_baseline = {
        "schema": "rvmt.35t.qemu_plugin_baseline.v1",
        "status": EXPECTED_QEMU_PLUGIN_BASELINE_STATUS,
        "pass_count": 13,
    }
    extension_enablement = {
        "schema": "rvmt.35t.extension_35t_enablement_preflight.v1",
        "status": EXPECTED_EXTENSION_ENABLEMENT_PREFLIGHT_STATUS,
    }
    extension_behavior = {
        "schema": "rvmt.35t.synthetic_extension_behavior_smoke.v1",
        "status": EXPECTED_EXTENSION_BEHAVIOR_SMOKE_STATUS,
        "summary_counts": {"executed_candidate_count": 8, "execution_pass_count": 8, "network_skipped_count": 1},
        "checks": {"expected_syscalls_observed_for_executed": True, "no_35t_execution_claim": True},
    }
    positioning = {
        "schema": "rvmt.35t.paper_positioning.v1",
        "status": EXPECTED_PAPER_POSITIONING_STATUS,
    }
    package = {
        "schema": "rvmt.35t.paper_artifact_package_manifest.v1",
        "status": EXPECTED_PACKAGE_STATUS,
        "readiness": {"status": EXPECTED_ARTIFACT_READINESS_STATUS},
        "lightweight_evidence_files": [
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_closure.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_closure.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_traceability.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_traceability.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_requirement_matrix.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_requirement_matrix.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_reconciliation.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_reconciliation.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_gate_criteria.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_gate_criteria.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/hardware_trace_prototype.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/hardware_trace_prototype.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/local_code_analysis.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/local_code_analysis.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/malware_behavior_audit.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/malware_behavior_audit.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_sanitization.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_sanitization.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_escrow.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_escrow.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/pointer_snapshot_design_review.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/pointer_snapshot_design_review.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/artifact_package_readiness.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/artifact_package_readiness.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/paper_evidence_check.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/paper_evidence_check.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/paper_positioning.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/paper_positioning.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/ebpf_baseline_summary.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/ebpf_baseline_summary.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/qemu_plugin_build_preflight.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/qemu_plugin_build_preflight.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/qemu_plugin_baseline_summary.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/qemu_plugin_baseline_summary.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/extension_35t_enablement_preflight.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/extension_35t_enablement_preflight.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/synthetic_extension_target_smoke.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/synthetic_extension_target_smoke.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/synthetic_extension_behavior_smoke.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/synthetic_extension_behavior_smoke.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/helper_alignment.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/helper_alignment.md",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/remaining_external_work.json",
            "docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/remaining_external_work.md",
        ],
        "validation_commands": [
            "uv run --no-sync python tools/check_35t_remaining_external_work.py --no-write",
            "uv run --no-sync python tools/check_35t_paper_positioning.py --no-write",
            "uv run --no-sync python tools/check_35t_assessment_reconciliation.py --no-write",
            "uv run --no-sync python tools/check_35t_assessment_gate_criteria.py --no-write",
            "uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --no-write",
            "uv run --no-sync python tools/check_35t_hardware_trace_prototype.py --no-write",
            "uv run --no-sync python tools/check_35t_local_code_analysis.py --no-write",
            "uv run --no-sync python tools/check_35t_malware_behavior_audit.py --no-write",
            "uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --no-write",
            "uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --no-write",
            "uv run --no-sync python tools/check_35t_pointer_snapshot_design_review.py --no-write",
            "uv run --no-sync python tools/check_35t_synthetic_extension_target_smoke.py --no-write",
            "uv run --no-sync python tools/check_35t_synthetic_extension_behavior_smoke.py --no-write",
            "uv run --no-sync python tools/check_35t_extension_35t_enablement.py --no-write",
            "uv run --no-sync python tools/check_35t_helper_alignment.py --no-write",
            "uv run --no-sync python tools/check_35t_qemu_plugin_build_preflight.py --self-test",
            "uv run --no-sync python tools/run_35t_qemu_plugin_baseline.py --self-test",
            "uv run --no-sync python tools/check_35t_evidence_consistency.py --no-write",
        ],
        "reproduction_commands": [
            "uv run --no-sync python tools/check_35t_remaining_external_work.py --repo-root .",
            "uv run --no-sync python tools/check_35t_paper_positioning.py --repo-root .",
            "uv run --no-sync python tools/check_35t_assessment_reconciliation.py --repo-root .",
            "uv run --no-sync python tools/check_35t_assessment_gate_criteria.py --repo-root .",
            "uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --repo-root .",
            "uv run --no-sync python tools/check_35t_hardware_trace_prototype.py --repo-root .",
            "uv run --no-sync python tools/check_35t_local_code_analysis.py --repo-root .",
            "uv run --no-sync python tools/check_35t_malware_behavior_audit.py --repo-root .",
            "uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --repo-root .",
            "uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --repo-root .",
            "uv run --no-sync python tools/check_35t_pointer_snapshot_design_review.py --repo-root .",
            "uv run --no-sync python tools/check_35t_synthetic_extension_target_smoke.py --repo-root .",
            "uv run --no-sync python tools/check_35t_synthetic_extension_behavior_smoke.py --repo-root .",
            "uv run --no-sync python tools/check_35t_extension_35t_enablement.py --repo-root .",
            "uv run --no-sync python tools/check_35t_helper_alignment.py --repo-root .",
            "uv run --no-sync python tools/check_35t_qemu_plugin_build_preflight.py --repo-root .",
            "uv run --no-sync python tools/run_35t_qemu_plugin_baseline.py --repo-root . --reps 3",
            "uv run --no-sync python tools/check_35t_evidence_consistency.py --repo-root .",
        ],
    }
    for name, value in [
        ("assessment_closure.json", closure),
        ("assessment_traceability.json", traceability),
        ("assessment_requirement_matrix.json", requirement_matrix),
        ("assessment_reconciliation.json", reconciliation),
        ("assessment_gate_criteria.json", gate_criteria),
        ("hardware_trace_prototype.json", hardware_trace),
        ("local_code_analysis.json", local_code_analysis),
        ("malware_behavior_audit.json", malware_behavior_audit),
        ("raw_artifact_sanitization.json", raw_artifact_sanitization),
        ("raw_artifact_escrow.json", raw_artifact_escrow),
        ("pointer_snapshot_design_review.json", pointer_design),
        ("remaining_external_work.json", remaining),
        ("helper_alignment.json", helper_alignment),
        ("qemu_plugin_build_preflight.json", qemu_plugin_build),
        ("qemu_plugin_baseline_summary.json", qemu_plugin_baseline),
        ("extension_35t_enablement_preflight.json", extension_enablement),
        ("synthetic_extension_behavior_smoke.json", extension_behavior),
        ("paper_positioning.json", positioning),
        ("ebpf_baseline_summary.json", {"schema": "rvmt.35t.ebpf_baseline.v1", "status": "PASS"}),
        (
            "synthetic_extension_target_smoke.json",
            {"schema": "rvmt.35t.synthetic_extension_target_smoke.v1", "status": "TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED"},
        ),
        ("artifact_package_readiness.json", readiness),
        ("paper_artifact_package_manifest.json", package),
    ]:
        write_json(evidence / name, value)
    for name in [
        "assessment_closure.md",
        "assessment_traceability.md",
        "assessment_requirement_matrix.md",
        "assessment_reconciliation.md",
        "assessment_gate_criteria.md",
        "hardware_trace_prototype.md",
        "local_code_analysis.md",
        "malware_behavior_audit.md",
        "raw_artifact_sanitization.md",
        "raw_artifact_escrow.md",
        "pointer_snapshot_design_review.md",
        "remaining_external_work.md",
        "helper_alignment.md",
        "qemu_plugin_build_preflight.md",
        "qemu_plugin_baseline_summary.md",
        "extension_35t_enablement_preflight.md",
        "artifact_package_readiness.md",
        "paper_evidence_check.json",
        "paper_evidence_check.md",
        "paper_positioning.md",
        "ebpf_baseline_summary.md",
        "synthetic_extension_target_smoke.md",
        "synthetic_extension_behavior_smoke.md",
    ]:
        (evidence / name).write_text("fixture\n", encoding="utf-8")
    workflow = root / ".github/workflows/35t-closure.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "uv run --no-sync python tools/check_35t_remaining_external_work.py --self-test\n"
        "uv run --no-sync python tools/check_35t_remaining_external_work.py --no-write\n"
        "uv run --no-sync python tools/check_35t_evidence_consistency.py --self-test\n"
        "uv run --no-sync python tools/check_35t_evidence_consistency.py --no-write\n"
        "uv run --no-sync python tools/check_35t_paper_positioning.py --self-test\n"
        "uv run --no-sync python tools/check_35t_assessment_reconciliation.py --self-test\n"
        "uv run --no-sync python tools/check_35t_assessment_gate_criteria.py --self-test\n"
        "uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --self-test\n"
        "uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --no-write\n"
        "uv run --no-sync python tools/check_35t_hardware_trace_prototype.py --self-test\n"
        "uv run --no-sync python tools/check_35t_local_code_analysis.py --self-test\n"
        "uv run --no-sync python tools/check_35t_malware_behavior_audit.py --self-test\n"
        "uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --self-test\n"
        "uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --no-write\n"
        "uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --self-test\n"
        "uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --no-write\n"
        "uv run --no-sync python tools/check_35t_pointer_snapshot_design_review.py --self-test\n"
        "uv run --no-sync python tools/check_35t_pointer_snapshot_design_review.py --no-write\n"
        "uv run --no-sync python tools/check_35t_synthetic_extension_target_smoke.py --self-test\n"
        "uv run --no-sync python tools/check_35t_synthetic_extension_target_smoke.py --no-write\n"
        "uv run --no-sync python tools/check_35t_synthetic_extension_behavior_smoke.py --self-test\n"
        "uv run --no-sync python tools/check_35t_extension_35t_enablement.py --self-test\n"
        "uv run --no-sync python tools/check_35t_extension_35t_enablement.py --no-write\n"
        "uv run --no-sync python tools/check_35t_helper_alignment.py --self-test\n"
        "uv run --no-sync python tools/check_35t_helper_alignment.py --no-write\n"
        "uv run --no-sync python tools/check_35t_qemu_plugin_build_preflight.py --self-test\n"
        "uv run --no-sync python tools/run_35t_qemu_plugin_baseline.py --self-test\n",
        encoding="utf-8",
    )
    for path, text in [
        (
            root / "tools/check_35t_paper_evidence.py",
            "remaining_external_work_no_write\nevidence_consistency_no_write\npaper_positioning_self_test\nassessment_reconciliation_self_test\nassessment_gate_criteria_self_test\nassessment_requirement_matrix_self_test\nhardware_trace_prototype_self_test\nlocal_code_analysis_self_test\nmalware_behavior_audit_self_test\nraw_artifact_sanitization_self_test\nraw_artifact_escrow_self_test\nsynthetic_extension_behavior_smoke_self_test\nassessment_gate_criteria.json\nassessment_requirement_matrix.json\nhardware_trace_prototype.json\nlocal_code_analysis.json\nmalware_behavior_audit.json\nraw_artifact_sanitization.json\nraw_artifact_escrow.json\n",
        ),
        (
            root / "tools/check_35t_artifact_package_readiness.py",
            "tools/check_35t_remaining_external_work.py\ntools/check_35t_evidence_consistency.py\ntools/check_35t_paper_positioning.py\ntools/check_35t_assessment_reconciliation.py\ntools/check_35t_assessment_gate_criteria.py\ntools/check_35t_assessment_requirement_matrix.py\ntools/check_35t_hardware_trace_prototype.py\ntools/check_35t_local_code_analysis.py\ntools/check_35t_malware_behavior_audit.py\ntools/check_35t_raw_artifact_sanitization.py\ntools/check_35t_raw_artifact_escrow.py\ntools/check_35t_pointer_snapshot_design_review.py\ntools/check_35t_synthetic_extension_target_smoke.py\ntools/check_35t_synthetic_extension_behavior_smoke.py\ntools/check_35t_extension_35t_enablement.py\ntools/check_35t_helper_alignment.py\ntools/check_35t_qemu_plugin_build_preflight.py\ntools/run_35t_qemu_plugin_baseline.py\n",
        ),
        (
            root / "tools/package_35t_paper_artifacts.py",
            "tools/check_35t_remaining_external_work.py\ntools/check_35t_evidence_consistency.py\ntools/check_35t_paper_positioning.py\ntools/check_35t_assessment_reconciliation.py\ntools/check_35t_assessment_gate_criteria.py\ntools/check_35t_assessment_requirement_matrix.py\ntools/check_35t_hardware_trace_prototype.py\ntools/check_35t_local_code_analysis.py\ntools/check_35t_malware_behavior_audit.py\ntools/check_35t_raw_artifact_sanitization.py\ntools/check_35t_raw_artifact_escrow.py\ntools/check_35t_pointer_snapshot_design_review.py\ntools/check_35t_synthetic_extension_target_smoke.py\ntools/check_35t_synthetic_extension_behavior_smoke.py\ntools/check_35t_extension_35t_enablement.py\ntools/check_35t_helper_alignment.py\ntools/check_35t_qemu_plugin_build_preflight.py\ntools/run_35t_qemu_plugin_baseline.py\n",
        ),
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    rows = []
    for path in sorted(evidence.iterdir(), key=lambda p: p.name):
        if path.name == "evidence_manifest.json" or not path.is_file():
            continue
        rows.append(
            {
                "artifact": path.name,
                "bytes": path.stat().st_size,
                "committed_path": rel(path, root),
                "sha256": file_digest(path),
            }
        )
    write_json(
        evidence / "evidence_manifest.json",
        {
            "schema": "rvmt.35t.evidence_snapshot.v1",
            "run_id": RUN_ID,
            "committed_artifacts": rows,
        },
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        evidence.mkdir(parents=True)
        self_test_manifest(root, evidence)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != EXPECTED_STATUS:
            print("[FAIL] expected consistency fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        evidence.mkdir(parents=True)
        self_test_manifest(root, evidence, stale_count=True)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL" or "p6_committed_artifact_count_matches_manifest" not in report["failures"]:
            print("[FAIL] expected stale P6 artifact count to fail", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1

    print("[PASS] 35T evidence consistency self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check internal consistency across 35T evidence manifests and closure reports.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true", help="accepted for workflow symmetry; this checker is always read-only")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        report = build_report(args.repo_root, args.evidence_root)
    except Exception as exc:
        print(f"check_35t_evidence_consistency: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T evidence consistency")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == EXPECTED_STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
