from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


SOURCE_RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
VALIDATION_RUN_ID = "35t-targeted-board-validation-20260522"
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / SOURCE_RUN_ID
PRIMARY_GATE = Path("results/experiments/35t") / SOURCE_RUN_ID / "aggregate/gate_report.json"
VALIDATION_GATE = Path("results/experiments/35t") / VALIDATION_RUN_ID / "aggregate/gate_report.json"
VALIDATION_BUNDLE = Path("results/experiments/35t") / VALIDATION_RUN_ID / "board_validation_bundle/bundle_manifest.json"
VALIDATION_BUNDLE_GATE = Path("results/experiments/35t") / VALIDATION_RUN_ID / "board_validation_bundle/gate_report.json"
SIDE_CHANNEL_CLOSURE_RUN_ID = "35t-sidechannel-closure-r2048-20260522"
SIDE_CHANNEL_CLOSURE_GATE = Path("results/experiments/35t") / SIDE_CHANNEL_CLOSURE_RUN_ID / "aggregate/gate_report.json"
SIDE_CHANNEL_CLOSURE_PLAN = DEFAULT_EVIDENCE_ROOT / "side_channel_closure_plan.json"
SIDE_CHANNEL_CLOSURE_SAMPLES = [
    "batch_open_read_write",
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
]
LOCAL_CODE_ANALYSIS_STATUS = "LOCAL_CODE_ANALYSIS_PROTOTYPE_PASS_WITH_BOUNDED_ATTRIBUTION"
MALWARE_BEHAVIOR_AUDIT_STATUS = "SYNTHETIC_MALWARE_LIKE_BEHAVIOR_AUDIT_PASS_REAL_MALWARE_DEFERRED"
HARDWARE_TRACE_PROTOTYPE_STATUS = "HARDWARE_TRACE_PROTOTYPE_PASS_35T_SMALL_CAPACITY"
ASSESSMENT_REQUIREMENT_MATRIX_STATUS = "ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]
SUPPORTED_CLAIMS = [
    "35T / LiteX / VexRiscv prototype scope",
    "controlled benign and synthetic malware-like workload matrix",
    "512-record 35T small-capacity primary trace gate with 13/13 sample gate PASS",
    "targeted dual-channel validation bundle with strict trace gate separated from side-channel semantic capture",
    "targeted board side-channel fd/path closure for representative file-scan behavior",
    "targeted board side-channel clone/wait process-edge closure for representative process-chain behavior",
    "focused R2048 side-channel closure for the four previously failing semantic samples",
    "512-record 35T small-capacity hardware trace prototype with decoded trace artifacts for all trace-on repetitions",
    "full-matrix local code-analysis artifacts for code maps, trace-code joins, runtime process maps, semantic recovery, and rule audit",
    "8-rule synthetic malware-like behavior audit with real-malware detection claims explicitly deferred",
    "ELF-symbol function-level attribution for the case-study samples",
]
FORBIDDEN_CLAIMS = [
    "CVA6 validation",
    "real malware execution or real malware detection",
    "classifier accuracy, family coverage, IOC coverage, or TTP coverage",
    "mature production detector readiness",
    "complete semantic reconstruction",
    "source-line attribution",
    "single-trace all-gates PASS for the side-channel semantic capture",
]
LIMITATIONS = [
    "The evidence chain is dual-channel: a low-perturbation trace-gate channel supplies the strict full-matrix gate, while a syscall side-channel capture supplies semantic closure evidence.",
    "The side-channel semantic capture is not itself a strict single-trace all-gates PASS and must not be used as the trace-gate channel.",
    "The R2048 side-channel closure is a focused larger-buffer follow-up for the four failed samples, not a single 13-sample side-channel rerun.",
    "Hardware trace evidence is scoped to 35T / LiteX / VexRiscv and must not be generalized to CVA6.",
    "Local code analysis is prototype-level attribution: PC-in-ELF is static code-range evidence and source-line attribution remains unavailable.",
    "Malware analysis is a controlled synthetic behavior-rule audit, not real malware execution, family classification, IOC/TTP coverage, or detector accuracy evidence.",
    "Function attribution is symbol/range based; source-line records are unavailable.",
    "Process-tree evidence still leaves the target parent PID unresolved and must not be described as complete process ownership.",
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


def sample_rows(gate_report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = gate_report.get("samples", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def sample_status_rows(gate_report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = gate_report.get("sample_status", {})
    return {str(key): row for key, row in rows.items() if isinstance(row, dict)} if isinstance(rows, dict) else {}


def event_summary_counts(gate_report: dict[str, Any]) -> dict[str, int]:
    summary = gate_report.get("event_summary", {})
    unknown = 0
    corrupt = 0
    if isinstance(summary, dict):
        for row in summary.values():
            if not isinstance(row, dict):
                continue
            unknown += int(row.get("unknown_event_count", 0) or 0)
            corrupt += int(row.get("corrupt_record_count", 0) or 0)
    return {"unknown_event_count": unknown, "corrupt_record_count": corrupt}


def failed_sample_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failures = []
    for row in rows:
        if row.get("gate_status") == "PASS":
            continue
        marker = row.get("marker_scope_summary", {}) if isinstance(row.get("marker_scope_summary"), dict) else {}
        runtime = (
            row.get("runtime_process_attribution_summary", {})
            if isinstance(row.get("runtime_process_attribution_summary"), dict)
            else {}
        )
        drop = row.get("drop_summary", {}) if isinstance(row.get("drop_summary"), dict) else {}
        failures.append(
            {
                "sample_id": row.get("sample_id"),
                "gate_status": row.get("gate_status"),
                "gate_failures": row.get("gate_failures", []),
                "gate_blockers": row.get("gate_blockers", []),
                "marker_scope_status": marker.get("status"),
                "runtime_process_attribution_status": runtime.get("status"),
                "capped_reps": drop.get("capped_reps", []),
                "drop_rate_median": drop.get("drop_rate_median"),
            }
        )
    return failures


def gate_summary(
    gate_report: dict[str, Any],
    *,
    expected_run_id: str,
    expected_claim_level: str | None,
) -> dict[str, Any]:
    rows = sample_rows(gate_report)
    status_rows = sample_status_rows(gate_report)
    event_counts = event_summary_counts(gate_report)
    sample_gate_pass_count = sum(1 for row in rows if row.get("gate_status") == "PASS")
    sample_status_pass_count = sum(1 for row in status_rows.values() if row.get("status") == "PASS")
    strict_gate_ok = bool(rows) and sample_gate_pass_count == len(rows)
    sample_status_ok = bool(status_rows) and sample_status_pass_count == len(status_rows)
    claim_level_ok = expected_claim_level is None or gate_report.get("claim_level") == expected_claim_level
    return {
        "schema": gate_report.get("schema"),
        "schema_ok": gate_report.get("schema") == "rvmt.35t.next_gate.v2",
        "run_id": gate_report.get("run_id"),
        "run_id_ok": gate_report.get("run_id") == expected_run_id,
        "claim_level": gate_report.get("claim_level"),
        "claim_level_ok": claim_level_ok,
        "trace_records": gate_report.get("trace_records"),
        "trace_records_ok": gate_report.get("trace_records") == 512,
        "trace_profile_policy": gate_report.get("trace_profile_policy"),
        "trace_profile_policy_ok": gate_report.get("trace_profile_policy") == "35t_small_capacity",
        "sample_count": len(rows),
        "sample_gate_pass_count": sample_gate_pass_count,
        "sample_gate_status_ok": strict_gate_ok,
        "sample_status_count": len(status_rows),
        "sample_status_pass_count": sample_status_pass_count,
        "sample_status_ok": sample_status_ok,
        "event_summary": event_counts,
        "event_summary_ok": event_counts["unknown_event_count"] == 0 and event_counts["corrupt_record_count"] == 0,
        "failed_samples": failed_sample_summary(rows),
    }


def gate_ok(summary: dict[str, Any]) -> bool:
    return bool(
        summary.get("schema_ok")
        and summary.get("run_id_ok")
        and summary.get("claim_level_ok")
        and summary.get("trace_records_ok")
        and summary.get("trace_profile_policy_ok")
        and summary.get("sample_count") == 13
        and summary.get("sample_gate_status_ok")
        and summary.get("sample_status_count") == 13
        and summary.get("sample_status_ok")
        and summary.get("event_summary_ok")
    )


def focused_side_channel_closure_summary(repo_root: Path, evidence_root: Path, failures: list[str]) -> dict[str, Any]:
    plan = read_json(evidence_root / "side_channel_closure_plan.json", failures, repo_root, "side-channel closure plan")
    gate = read_json(repo_path(repo_root, SIDE_CHANNEL_CLOSURE_GATE), failures, repo_root, "side-channel closure gate")
    rows = sample_rows(gate)
    status_rows = sample_status_rows(gate)
    rows_by_sample = {str(row.get("sample_id")): row for row in rows}
    expected = set(SIDE_CHANNEL_CLOSURE_SAMPLES)
    actual = set(rows_by_sample)
    per_sample: list[dict[str, Any]] = []
    sample_failures: list[str] = []
    for sample in SIDE_CHANNEL_CLOSURE_SAMPLES:
        row = rows_by_sample.get(sample, {})
        status = status_rows.get(sample, {})
        drop = row.get("drop_summary", {}) if isinstance(row.get("drop_summary"), dict) else {}
        marker = row.get("marker_scope_summary", {}) if isinstance(row.get("marker_scope_summary"), dict) else {}
        runtime = (
            row.get("runtime_process_attribution_summary", {})
            if isinstance(row.get("runtime_process_attribution_summary"), dict)
            else {}
        )
        audit = row.get("audit_rule_summary", {}) if isinstance(row.get("audit_rule_summary"), dict) else {}
        sample_check_failures = []
        if not row:
            sample_check_failures.append("missing_sample_row")
        if row.get("gate_status") != "PASS":
            sample_check_failures.append("gate_status")
        if status.get("status") != "PASS":
            sample_check_failures.append("sample_status")
        if marker.get("status") != "PASS":
            sample_check_failures.append("marker_scope")
        if runtime.get("status") != "PASS":
            sample_check_failures.append("runtime_process_attribution")
        if drop.get("capped_reps"):
            sample_check_failures.append("trace_record_cap_hit")
        if float(drop.get("drop_rate_median", 1.0) if drop.get("drop_rate_median") is not None else 1.0) > 0.05:
            sample_check_failures.append("drop_rate_median_gt_5pct")
        if audit.get("missing"):
            sample_check_failures.append("missing_expected")
        if sample_check_failures:
            sample_failures.append(f"{sample}: {', '.join(sample_check_failures)}")
        per_sample.append(
            {
                "sample_id": sample,
                "status": "PASS" if not sample_check_failures else "FAIL",
                "failures": sample_check_failures,
                "gate_status": row.get("gate_status"),
                "sample_status": status.get("status"),
                "drop_rate_median": drop.get("drop_rate_median"),
                "capped_reps": drop.get("capped_reps", []),
                "marker_scope_status": marker.get("status"),
                "runtime_process_attribution_status": runtime.get("status"),
                "missing_expected": audit.get("missing", []),
            }
        )

    event_counts = event_summary_counts(gate)
    checks = {
        "plan_pass": plan.get("status") == "PASS"
        and isinstance(plan.get("closure_verification"), dict)
        and plan["closure_verification"].get("status") == "PASS",
        "schema": gate.get("schema") == "rvmt.35t.next_gate.v2",
        "run_id": gate.get("run_id") == SIDE_CHANNEL_CLOSURE_RUN_ID,
        "trace_records": gate.get("trace_records") == 2048,
        "trace_profile_policy": gate.get("trace_profile_policy") == "35t_small_capacity",
        "sample_set": actual == expected,
        "sample_gate_status": bool(rows) and all(row.get("gate_status") == "PASS" for row in rows),
        "sample_status": bool(status_rows) and all(row.get("status") == "PASS" for row in status_rows.values()),
        "sample_quality": not sample_failures,
        "event_summary": event_counts["unknown_event_count"] == 0 and event_counts["corrupt_record_count"] == 0,
    }
    for key, ok in checks.items():
        if not ok:
            failures.append(f"focused side-channel closure check failed: {key}")

    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "run_id": gate.get("run_id"),
        "claim_level": gate.get("claim_level"),
        "trace_records": gate.get("trace_records"),
        "sample_count": len(rows),
        "sample_gate_pass_count": sum(1 for row in rows if row.get("gate_status") == "PASS"),
        "sample_status_pass_count": sum(1 for row in status_rows.values() if row.get("status") == "PASS"),
        "focused_samples": SIDE_CHANNEL_CLOSURE_SAMPLES,
        "checks": checks,
        "per_sample": per_sample,
        "event_summary": event_counts,
        "gate_report": rel(repo_path(repo_root, SIDE_CHANNEL_CLOSURE_GATE), repo_root),
        "plan": rel(evidence_root / "side_channel_closure_plan.json", repo_root),
        "failures": sample_failures,
    }


def has_non_claims(value: dict[str, Any]) -> bool:
    text = "\n".join(str(item) for item in value.get("non_claims", []) if item)
    return all(item in text for item in EXPECTED_NON_CLAIMS)


def semantic_summary(repo_root: Path, evidence_root: Path, failures: list[str]) -> dict[str, Any]:
    board_attempt = read_json(evidence_root / "board_validation_attempt_summary.json", failures, repo_root, "board validation attempt")
    board_status = read_json(evidence_root / "board_validation_status.json", failures, repo_root, "board validation status")
    bundle = read_json(repo_path(repo_root, VALIDATION_BUNDLE), failures, repo_root, "targeted board validation bundle")
    fd_path = read_json(evidence_root / "fd_path_flow_summary.json", failures, repo_root, "fd/path flow summary")
    fd_path_case_studies = read_json(evidence_root / "fd_path_case_studies.json", failures, repo_root, "fd/path case studies")
    process_tree = read_json(evidence_root / "process_tree_summary.json", failures, repo_root, "process tree summary")
    process_tree_case_study = read_json(evidence_root / "process_tree_case_study.json", failures, repo_root, "process tree case study")
    function_attr = read_json(evidence_root / "function_attribution_summary.json", failures, repo_root, "function attribution summary")
    source_attr = read_json(evidence_root / "source_attribution_summary.json", failures, repo_root, "source attribution summary")
    closure = read_json(evidence_root / "application_closure_check.json", failures, repo_root, "application closure check")

    fd_flow = (fd_path.get("flows") or [{}])[0] if isinstance(fd_path.get("flows"), list) and fd_path.get("flows") else {}
    fd_selected = fd_path.get("selected_candidate", {}) if isinstance(fd_path.get("selected_candidate"), dict) else {}
    process_edges = process_tree.get("edges", []) if isinstance(process_tree.get("edges"), list) else []
    process_case_checks = process_tree_case_study.get("checks", {}) if isinstance(process_tree_case_study.get("checks"), dict) else {}
    unresolved_parent_edges = [
        edge
        for edge in process_edges
        if isinstance(edge, dict) and str(edge.get("parent_pid", "")).endswith("_unresolved")
    ]
    function_level = function_attr.get("function_level", {}) if isinstance(function_attr.get("function_level"), dict) else {}
    source_line = source_attr.get("source_line_level", {}) if isinstance(source_attr.get("source_line_level"), dict) else {}
    selected_statuses = bundle.get("selected_statuses", {}) if isinstance(bundle.get("selected_statuses"), dict) else {}
    fd_case_rows = fd_path_case_studies.get("samples", {}) if isinstance(fd_path_case_studies.get("samples"), dict) else {}

    checks = {
        "board_attempt_pass": board_attempt.get("status") == "BOARD_VALIDATION_PASS" and board_attempt.get("hardware_validated") is True,
        "board_status_pass": board_status.get("status") == "PASS" and board_status.get("hardware_validated") is True,
        "bundle_pass": (
            bundle.get("schema") == "rvmt.35t.board_validation_bundle.v1"
            and bundle.get("source_run_id") == SOURCE_RUN_ID
            and bundle.get("validation_run_id") == VALIDATION_RUN_ID
            and bundle.get("status") == "PASS"
            and bundle.get("checker_status") == "PASS"
            and bundle.get("hardware_validated") is True
        ),
        "bundle_selected_statuses": (
            selected_statuses.get("fd_path_flow") == "PASS"
            and selected_statuses.get("process_tree") == "PASS"
            and selected_statuses.get("source_attribution") == "PARTIAL"
        ),
        "fd_path_closed": (
            fd_path.get("schema") == "rvmt.fd_path_flow.summary.v1"
            and fd_path.get("status") == "PASS"
            and fd_flow.get("status") == "closed"
            and fd_flow.get("path_source") == "board_syscall_side_channel"
            and fd_selected.get("source_type") == "syscall_side_channel"
        ),
        "fd_path_case_studies": (
            fd_path_case_studies.get("schema") == "rvmt.35t.fd_path_case_studies.v1"
            and fd_path_case_studies.get("status") == "PASS"
            and all(
                sample in fd_case_rows
                and isinstance(fd_case_rows.get(sample), dict)
                and fd_case_rows[sample].get("status") == "PASS"
                and isinstance(fd_case_rows[sample].get("selected_candidate"), dict)
                and fd_case_rows[sample]["selected_candidate"].get("source_type") == "syscall_side_channel"
                for sample in ("file_scan", "batch_open_read_write", "self_copy_sim")
            )
        ),
        "process_tree_edges": (
            process_tree.get("schema") == "rvmt.process_tree.summary.v1"
            and process_tree.get("status") == "PASS"
            and len(process_edges) >= 1
        ),
        "process_tree_case_study": (
            process_tree_case_study.get("schema") == "rvmt.35t.process_tree_case_study.v1"
            and process_tree_case_study.get("status") == "PASS"
            and process_case_checks.get("positive_child_pid_recovered") is True
            and process_case_checks.get("execve_path_string_recovered") is True
            and process_case_checks.get("parent_wait_pid_associated") is True
            and process_case_checks.get("parent_child_graph_output") is True
            and process_case_checks.get("selected_from_board_side_channel") is True
        ),
        "function_attribution_pass": (
            function_attr.get("schema") == "rvmt.35t.function_attribution_summary.v1"
            and function_attr.get("status") == "PASS"
            and function_level.get("status") == "available"
            and function_level.get("samples_available") == function_level.get("sample_count")
        ),
        "source_attribution_bounded": (
            source_attr.get("schema") == "rvmt.35t.source_attribution_summary.v1"
            and source_attr.get("status") == "PARTIAL"
            and source_attr.get("function_level", {}).get("status") == "available"
            and source_line.get("status") == "unavailable"
        ),
        "application_closure_pass": closure.get("status") == "PASS",
    }
    for key, ok in checks.items():
        if not ok:
            failures.append(f"semantic paper evidence check failed: {key}")

    return {
        "checks": checks,
        "board_validation_attempt": {
            "status": board_attempt.get("status"),
            "hardware_validated": board_attempt.get("hardware_validated"),
            "next_gate_claim_level": board_attempt.get("next_gate", {}).get("claim_level")
            if isinstance(board_attempt.get("next_gate"), dict)
            else None,
        },
        "board_validation_status": {
            "status": board_status.get("status"),
            "hardware_validated": board_status.get("hardware_validated"),
        },
        "bundle": {
            "status": bundle.get("status"),
            "checker_status": bundle.get("checker_status"),
            "hardware_validated": bundle.get("hardware_validated"),
            "selected_statuses": selected_statuses,
            "manifest": rel(repo_path(repo_root, VALIDATION_BUNDLE), repo_root),
        },
        "fd_path": {
            "status": fd_path.get("status"),
            "sample": fd_path.get("sample"),
            "path_source": fd_flow.get("path_source"),
            "selected_source_type": fd_selected.get("source_type"),
            "closed_flow_count": len(fd_path.get("flows", [])) if isinstance(fd_path.get("flows"), list) else 0,
        },
        "fd_path_case_studies": {
            "status": fd_path_case_studies.get("status"),
            "samples": sorted(fd_case_rows),
        },
        "process_tree": {
            "status": process_tree.get("status"),
            "sample": process_tree.get("sample"),
            "edge_count": len(process_edges),
            "unresolved_parent_edge_count": len(unresolved_parent_edges),
        },
        "process_tree_case_study": {
            "status": process_tree_case_study.get("status"),
            "checks": process_case_checks,
        },
        "function_attribution": {
            "status": function_attr.get("status"),
            "function_level": function_level,
        },
        "source_attribution": {
            "status": source_attr.get("status"),
            "function_level": source_attr.get("function_level"),
            "source_line_level": source_line,
        },
    }


def workflow_summary(repo_root: Path) -> dict[str, Any]:
    path = repo_root / ".github/workflows/35t-closure.yml"
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    return {
        "path": rel(path, repo_root),
        "exists": path.exists(),
        "application_closure_self_test": "tools/check_35t_application_closure.py --self-test" in text,
        "paper_evidence_self_test": "tools/check_35t_paper_evidence.py --self-test" in text,
        "fd_path_self_test": "tools/recover_fd_path_flow.py --self-test" in text,
        "fd_path_case_study_self_test": "tools/check_35t_fd_path_case_studies.py --self-test" in text,
        "process_tree_self_test": "tools/recover_process_tree.py --self-test" in text,
        "process_tree_case_study_self_test": "tools/check_35t_process_tree_case_study.py --self-test" in text,
        "metric_coverage_self_test": "tools/check_35t_metric_coverage.py --self-test" in text,
        "pointer_snapshot_gate_self_test": "tools/check_35t_pointer_snapshot_gate.py --self-test" in text,
        "pointer_snapshot_design_review_self_test": "tools/check_35t_pointer_snapshot_design_review.py --self-test" in text,
        "pointer_snapshot_design_review_no_write": "tools/check_35t_pointer_snapshot_design_review.py --no-write" in text,
        "threat_model_self_test": "tools/check_35t_threat_model.py --self-test" in text,
        "helper_alignment_self_test": "tools/check_35t_helper_alignment.py --self-test" in text,
        "helper_alignment_no_write": "tools/check_35t_helper_alignment.py --no-write" in text,
        "baseline_execution_spec_self_test": "tools/check_35t_baseline_execution_spec.py --self-test" in text,
        "qemu_plugin_build_preflight_self_test": "tools/check_35t_qemu_plugin_build_preflight.py --self-test" in text,
        "synthetic_extension_host_smoke_self_test": "tools/check_35t_synthetic_extension_host_smoke.py --self-test"
        in text,
        "synthetic_extension_behavior_smoke_self_test": "tools/check_35t_synthetic_extension_behavior_smoke.py --self-test"
        in text,
        "extension_enablement_self_test": "tools/check_35t_extension_35t_enablement.py --self-test" in text,
        "extension_enablement_no_write": "tools/check_35t_extension_35t_enablement.py --no-write" in text,
        "assessment_traceability_self_test": "tools/check_35t_assessment_traceability.py --self-test" in text,
        "assessment_requirement_matrix_self_test": "tools/check_35t_assessment_requirement_matrix.py --self-test"
        in text,
        "assessment_requirement_matrix_no_write": "tools/check_35t_assessment_requirement_matrix.py --no-write" in text,
        "remaining_external_work_self_test": "tools/check_35t_remaining_external_work.py --self-test" in text,
        "remaining_external_work_no_write": "tools/check_35t_remaining_external_work.py --no-write" in text,
        "raw_artifact_sanitization_self_test": "tools/check_35t_raw_artifact_sanitization.py --self-test" in text,
        "raw_artifact_sanitization_no_write": "tools/check_35t_raw_artifact_sanitization.py --no-write" in text,
        "raw_artifact_escrow_self_test": "tools/check_35t_raw_artifact_escrow.py --self-test" in text,
        "raw_artifact_escrow_no_write": "tools/check_35t_raw_artifact_escrow.py --no-write" in text,
        "evidence_consistency_self_test": "tools/check_35t_evidence_consistency.py --self-test" in text,
        "evidence_consistency_no_write": "tools/check_35t_evidence_consistency.py --no-write" in text,
        "paper_positioning_self_test": "tools/check_35t_paper_positioning.py --self-test" in text,
        "assessment_reconciliation_self_test": "tools/check_35t_assessment_reconciliation.py --self-test" in text,
        "assessment_gate_criteria_self_test": "tools/check_35t_assessment_gate_criteria.py --self-test" in text,
        "hardware_trace_prototype_self_test": "tools/check_35t_hardware_trace_prototype.py --self-test" in text,
        "local_code_analysis_self_test": "tools/check_35t_local_code_analysis.py --self-test" in text,
        "malware_behavior_audit_self_test": "tools/check_35t_malware_behavior_audit.py --self-test" in text,
    }


def build_report(repo_root: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    failures: list[str] = []
    warnings: list[str] = []

    primary_gate = read_json(repo_path(repo_root, PRIMARY_GATE), failures, repo_root, "primary full-matrix gate report")
    bundle_manifest = read_json(repo_path(repo_root, VALIDATION_BUNDLE), failures, repo_root, "targeted board validation bundle manifest")
    validation_mode = str(bundle_manifest.get("validation_mode", "single_channel")) if bundle_manifest else "single_channel"
    trace_gate_run_id = str(bundle_manifest.get("trace_gate_run_id") or VALIDATION_RUN_ID)
    semantic_run_id = str(bundle_manifest.get("semantic_run_id") or VALIDATION_RUN_ID)
    if validation_mode == "dual_channel":
        validation_gate_path = repo_path(repo_root, VALIDATION_BUNDLE_GATE)
        validation_gate_label = "targeted dual-channel trace-gate report"
        expected_validation_gate_run_id = trace_gate_run_id
        expected_validation_claim_level: str | None = "full_matrix_ready"
    else:
        validation_gate_path = repo_path(repo_root, VALIDATION_GATE)
        validation_gate_label = "targeted side-channel gate report"
        expected_validation_gate_run_id = VALIDATION_RUN_ID
        expected_validation_claim_level = None
    validation_gate = read_json(validation_gate_path, failures, repo_root, validation_gate_label)
    semantic_side_channel_gate = read_json(repo_path(repo_root, VALIDATION_GATE), [], repo_root, "targeted semantic side-channel gate report")
    primary = gate_summary(primary_gate, expected_run_id=SOURCE_RUN_ID, expected_claim_level="full_matrix_ready")
    validation = gate_summary(
        validation_gate,
        expected_run_id=expected_validation_gate_run_id,
        expected_claim_level=expected_validation_claim_level,
    )
    semantic_gate = gate_summary(semantic_side_channel_gate, expected_run_id=semantic_run_id, expected_claim_level=None)
    if not gate_ok(primary):
        failures.append("primary full-matrix gate is not a strict 13/13 PASS")

    strict_single_run_ok = gate_ok(validation)
    if not strict_single_run_ok:
        warnings.append("targeted validation trace-gate channel is not a strict full-matrix gate PASS")
    if validation_mode == "dual_channel" and semantic_gate.get("failed_samples"):
        warnings.append("side-channel semantic capture has strict gate failures and is not used as the trace-gate channel")

    semantic = semantic_summary(repo_root, evidence_root, failures)
    metric_coverage = read_json(evidence_root / "metric_coverage.json", failures, repo_root, "metric coverage")
    metric_coverage_checks = metric_coverage.get("checks", {}) if isinstance(metric_coverage.get("checks"), dict) else {}
    if not (
        metric_coverage.get("schema") == "rvmt.35t.metric_coverage.v1"
        and metric_coverage.get("status") == "BOUNDED_METRIC_COVERAGE_READY_WITH_DEFERRED_FULL_ACCURACY"
        and metric_coverage_checks.get("all_required_metrics_listed") is True
    ):
        failures.append("metric coverage must enumerate the bounded P4 metric list")
    threat_model = read_json(evidence_root / "threat_model_boundary.json", failures, repo_root, "threat model boundary")
    if not (
        threat_model.get("schema") == "rvmt.35t.threat_model_boundary.v1"
        and threat_model.get("status") == "TRUSTED_KERNEL_USER_MODE_THREAT_MODEL_BOUNDARY_SPECIFIED"
        and "linux_kernel" in set(threat_model.get("trusted_components", []))
        and "user_mode_malware_like_workload" in set(threat_model.get("in_scope", []))
        and "kernel_rootkit" in set(threat_model.get("out_of_scope", []))
    ):
        failures.append("threat model must state trusted-kernel/user-mode boundary and rootkit non-claim")
    side_channel_closure = focused_side_channel_closure_summary(repo_root, evidence_root, failures)
    workflow = workflow_summary(repo_root)
    if not workflow["exists"]:
        failures.append("missing 35T closure workflow")
    if not workflow["application_closure_self_test"]:
        failures.append("35T closure workflow does not run application closure self-test")
    if not workflow["paper_evidence_self_test"]:
        failures.append("35T closure workflow does not run paper evidence self-test")
    if not workflow["fd_path_self_test"]:
        failures.append("35T closure workflow does not run fd/path self-test")
    if not workflow["fd_path_case_study_self_test"]:
        failures.append("35T closure workflow does not run fd/path case-study self-test")
    if not workflow["process_tree_self_test"]:
        failures.append("35T closure workflow does not run process-tree self-test")
    if not workflow["process_tree_case_study_self_test"]:
        failures.append("35T closure workflow does not run process-tree case-study self-test")
    if not workflow["metric_coverage_self_test"]:
        failures.append("35T closure workflow does not run metric coverage self-test")
    if not workflow["pointer_snapshot_gate_self_test"]:
        failures.append("35T closure workflow does not run pointer snapshot gate self-test")
    if not workflow["pointer_snapshot_design_review_self_test"]:
        failures.append("35T closure workflow does not run pointer snapshot design review self-test")
    if not workflow["pointer_snapshot_design_review_no_write"]:
        failures.append("35T closure workflow does not run pointer snapshot design review no-write check")
    if not workflow["threat_model_self_test"]:
        failures.append("35T closure workflow does not run threat model self-test")
    if not workflow["helper_alignment_self_test"]:
        failures.append("35T closure workflow does not run helper alignment self-test")
    if not workflow["helper_alignment_no_write"]:
        failures.append("35T closure workflow does not run helper alignment no-write check")
    if not workflow["baseline_execution_spec_self_test"]:
        failures.append("35T closure workflow does not run baseline execution spec self-test")
    if not workflow["qemu_plugin_build_preflight_self_test"]:
        failures.append("35T closure workflow does not run QEMU-plugin build preflight self-test")
    if not workflow["synthetic_extension_host_smoke_self_test"]:
        failures.append("35T closure workflow does not run synthetic extension host smoke self-test")
    if not workflow["synthetic_extension_behavior_smoke_self_test"]:
        failures.append("35T closure workflow does not run synthetic extension behavior smoke self-test")
    if not workflow["extension_enablement_self_test"]:
        failures.append("35T closure workflow does not run extension enablement self-test")
    if not workflow["extension_enablement_no_write"]:
        failures.append("35T closure workflow does not run extension enablement no-write check")
    if not workflow["assessment_traceability_self_test"]:
        failures.append("35T closure workflow does not run assessment traceability self-test")
    if not workflow["assessment_requirement_matrix_self_test"]:
        failures.append("35T closure workflow does not run assessment requirement matrix self-test")
    if not workflow["assessment_requirement_matrix_no_write"]:
        failures.append("35T closure workflow does not run assessment requirement matrix no-write check")
    if not workflow["remaining_external_work_self_test"]:
        failures.append("35T closure workflow does not run remaining external work self-test")
    if not workflow["remaining_external_work_no_write"]:
        failures.append("35T closure workflow does not run remaining external work no-write check")
    if not workflow["raw_artifact_sanitization_self_test"]:
        failures.append("35T closure workflow does not run raw artifact sanitization self-test")
    if not workflow["raw_artifact_sanitization_no_write"]:
        failures.append("35T closure workflow does not run raw artifact sanitization no-write check")
    if not workflow["raw_artifact_escrow_self_test"]:
        failures.append("35T closure workflow does not run raw artifact escrow self-test")
    if not workflow["raw_artifact_escrow_no_write"]:
        failures.append("35T closure workflow does not run raw artifact escrow no-write check")
    if not workflow["evidence_consistency_self_test"]:
        failures.append("35T closure workflow does not run evidence consistency self-test")
    if not workflow["evidence_consistency_no_write"]:
        failures.append("35T closure workflow does not run evidence consistency no-write check")
    if not workflow["paper_positioning_self_test"]:
        failures.append("35T closure workflow does not run paper positioning self-test")
    if not workflow["assessment_reconciliation_self_test"]:
        failures.append("35T closure workflow does not run assessment reconciliation self-test")
    if not workflow["assessment_gate_criteria_self_test"]:
        failures.append("35T closure workflow does not run assessment gate criteria self-test")
    if not workflow["hardware_trace_prototype_self_test"]:
        failures.append("35T closure workflow does not run hardware trace prototype self-test")
    if not workflow["local_code_analysis_self_test"]:
        failures.append("35T closure workflow does not run local code analysis self-test")
    if not workflow["malware_behavior_audit_self_test"]:
        failures.append("35T closure workflow does not run malware behavior audit self-test")

    manifest = read_json(evidence_root / "evidence_manifest.json", failures, repo_root, "evidence manifest")
    if manifest.get("claim_level") != EXPECTED_CLAIM_LEVEL:
        failures.append("evidence manifest claim level does not match the bounded paper claim")
    if manifest.get("real_malware") is not False or manifest.get("cva6_in_scope") is not False:
        failures.append("evidence manifest must keep real_malware=false and cva6_in_scope=false")
    if not has_non_claims(manifest):
        failures.append("evidence manifest is missing one or more required non-claims")
    assessment_gate_criteria = read_json(
        evidence_root / "assessment_gate_criteria.json",
        failures,
        repo_root,
        "assessment gate criteria",
    )
    if assessment_gate_criteria.get("status") != "ASSESSMENT_GATE_CRITERIA_PASS":
        failures.append("assessment gate criteria must pass the concrete 35T gate checks")
    assessment_requirement_matrix = read_json(
        evidence_root / "assessment_requirement_matrix.json",
        failures,
        repo_root,
        "assessment requirement matrix",
    )
    if not (
        assessment_requirement_matrix.get("schema") == "rvmt.35t.assessment_requirement_matrix.v1"
        and assessment_requirement_matrix.get("status") == ASSESSMENT_REQUIREMENT_MATRIX_STATUS
        and assessment_requirement_matrix.get("requirement_count") == 14
        and assessment_requirement_matrix.get("high_level_checks", {}).get("bounded_external_records_complete") is True
    ):
        failures.append("assessment requirement matrix must pass source-section coverage with bounded external work recorded")
    hardware_trace = read_json(
        evidence_root / "hardware_trace_prototype.json",
        failures,
        repo_root,
        "hardware trace prototype",
    )
    if not (
        hardware_trace.get("schema") == "rvmt.35t.hardware_trace_prototype.v1"
        and hardware_trace.get("status") == HARDWARE_TRACE_PROTOTYPE_STATUS
        and hardware_trace.get("trace_records") == 512
        and hardware_trace.get("sample_gate_pass_count") == 13
        and hardware_trace.get("decoded_trace_file_count") == 65
    ):
        failures.append("hardware trace prototype must pass the 35T small-capacity trace gate checks")
    local_code_analysis = read_json(
        evidence_root / "local_code_analysis.json",
        failures,
        repo_root,
        "local code analysis",
    )
    if not (
        local_code_analysis.get("schema") == "rvmt.35t.local_code_analysis.v1"
        and local_code_analysis.get("status") == LOCAL_CODE_ANALYSIS_STATUS
        and local_code_analysis.get("sample_count") == 13
        and local_code_analysis.get("complete_rep_count") == local_code_analysis.get("expected_rep_count")
    ):
        failures.append("local code analysis must pass full-matrix prototype attribution checks")
    malware_behavior_audit = read_json(
        evidence_root / "malware_behavior_audit.json",
        failures,
        repo_root,
        "malware behavior audit",
    )
    if not (
        malware_behavior_audit.get("schema") == "rvmt.35t.malware_behavior_audit.v1"
        and malware_behavior_audit.get("status") == MALWARE_BEHAVIOR_AUDIT_STATUS
        and malware_behavior_audit.get("sample_count") == 8
        and malware_behavior_audit.get("rule_count") == 8
        and malware_behavior_audit.get("gate_expected_rule_pass_count") == 8
    ):
        failures.append("malware behavior audit must pass the 8-rule synthetic audit checks")
    raw_sanitization = read_json(
        evidence_root / "raw_artifact_sanitization.json",
        failures,
        repo_root,
        "raw artifact sanitization",
    )
    raw_checks = raw_sanitization.get("checks", {}) if isinstance(raw_sanitization.get("checks"), dict) else {}
    if not (
        raw_sanitization.get("schema") == "rvmt.35t.raw_artifact_sanitization.v1"
        and raw_sanitization.get("status") == "RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED"
        and raw_checks.get("sanitized_excerpts_do_not_expose_scanned_patterns") is True
        and raw_checks.get("full_raw_release_deferred") is True
    ):
        failures.append("raw artifact sanitization must publish only hashes/excerpts and keep full raw release deferred")
    raw_escrow = read_json(
        evidence_root / "raw_artifact_escrow.json",
        failures,
        repo_root,
        "raw artifact escrow",
    )
    raw_escrow_checks = raw_escrow.get("checks", {}) if isinstance(raw_escrow.get("checks"), dict) else {}
    if not (
        raw_escrow.get("schema") == "rvmt.35t.raw_artifact_escrow.v1"
        and raw_escrow.get("status") == "LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED"
        and raw_escrow_checks.get("payload_files_present_and_hashed") is True
        and raw_escrow_checks.get("public_release_deferred") is True
    ):
        failures.append("raw artifact escrow must verify local payload hashes while keeping public raw release deferred")

    return {
        "schema": "rvmt.35t.paper_evidence_check.v1",
        "status": "PASS" if not failures else "FAIL",
        "paper_support_status": "SUPPORTED_WITH_BOUNDED_CLAIMS" if not failures else "NOT_SUPPORTED",
        "strict_single_run_status": "PASS" if strict_single_run_ok else "FAIL",
        "validation_mode": validation_mode,
        "source_run_id": SOURCE_RUN_ID,
        "validation_run_id": VALIDATION_RUN_ID,
        "trace_gate_run_id": trace_gate_run_id,
        "semantic_run_id": semantic_run_id,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "primary_full_matrix_gate": primary,
        "targeted_validation_gate": validation,
        "targeted_side_channel_gate": semantic_gate,
        "focused_side_channel_closure": side_channel_closure,
        "semantic_closure": semantic,
        "metric_coverage": {
            "status": metric_coverage.get("status"),
            "required_metrics": metric_coverage.get("required_metrics", []),
        },
        "threat_model": {
            "status": threat_model.get("status"),
            "in_scope": threat_model.get("in_scope", []),
            "out_of_scope": threat_model.get("out_of_scope", []),
        },
        "assessment_gate_criteria": {
            "status": assessment_gate_criteria.get("status"),
            "checks": assessment_gate_criteria.get("checks", {}),
        },
        "assessment_requirement_matrix": {
            "status": assessment_requirement_matrix.get("status"),
            "requirement_count": assessment_requirement_matrix.get("requirement_count"),
            "high_level_checks": assessment_requirement_matrix.get("high_level_checks", {}),
        },
        "hardware_trace_prototype": {
            "status": hardware_trace.get("status"),
            "trace_records": hardware_trace.get("trace_records"),
            "trace_profile_policy": hardware_trace.get("trace_profile_policy"),
            "sample_gate_pass_count": hardware_trace.get("sample_gate_pass_count"),
            "sample_count": hardware_trace.get("sample_count"),
            "decoded_trace_file_count": hardware_trace.get("decoded_trace_file_count"),
            "checks": hardware_trace.get("checks", {}),
            "boundaries": hardware_trace.get("boundaries", []),
        },
        "local_code_analysis": {
            "status": local_code_analysis.get("status"),
            "sample_count": local_code_analysis.get("sample_count"),
            "complete_rep_count": local_code_analysis.get("complete_rep_count"),
            "expected_rep_count": local_code_analysis.get("expected_rep_count"),
            "checks": local_code_analysis.get("checks", {}),
            "boundaries": local_code_analysis.get("boundaries", []),
        },
        "malware_behavior_audit": {
            "status": malware_behavior_audit.get("status"),
            "sample_count": malware_behavior_audit.get("sample_count"),
            "rule_count": malware_behavior_audit.get("rule_count"),
            "gate_expected_rule_pass_count": malware_behavior_audit.get("gate_expected_rule_pass_count"),
            "checks": malware_behavior_audit.get("checks", {}),
            "boundaries": malware_behavior_audit.get("boundaries", []),
        },
        "raw_artifact_sanitization": {
            "status": raw_sanitization.get("status"),
            "class_count": raw_sanitization.get("class_count"),
            "release_policy": raw_sanitization.get("release_policy", {}),
        },
        "raw_artifact_escrow": {
            "status": raw_escrow.get("status"),
            "payload_file_count": raw_escrow.get("payload_file_count"),
            "payload_total_bytes": raw_escrow.get("payload_total_bytes"),
            "package_dir": raw_escrow.get("package_dir"),
        },
        "workflow": workflow,
        "supported_claims": SUPPORTED_CLAIMS,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "limitations": LIMITATIONS,
        "non_claims": EXPECTED_NON_CLAIMS,
        "warnings": warnings,
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    primary = report["primary_full_matrix_gate"]
    validation = report["targeted_validation_gate"]
    side_channel = report["targeted_side_channel_gate"]
    focused_closure = report["focused_side_channel_closure"]
    semantic = report["semantic_closure"]
    hardware = report["hardware_trace_prototype"]
    local = report["local_code_analysis"]
    malware = report["malware_behavior_audit"]
    raw_sanitization = report["raw_artifact_sanitization"]
    raw_escrow = report["raw_artifact_escrow"]
    requirement_matrix = report["assessment_requirement_matrix"]
    lines = [
        f"# 35T Paper Evidence Check: {report['source_run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Paper support status: {report['paper_support_status']}",
        "",
        f"Strict single-run status: {report['strict_single_run_status']}",
        "",
        f"Validation mode: {report['validation_mode']}",
        "",
        f"Claim level: {report['claim_level']}.",
        "",
        "## Primary Full-Matrix Gate",
        "",
        f"- run_id: {primary.get('run_id')}",
        f"- claim_level: {primary.get('claim_level')}",
        f"- samples gate PASS: {primary.get('sample_gate_pass_count')}/{primary.get('sample_count')}",
        f"- sample status PASS: {primary.get('sample_status_pass_count')}/{primary.get('sample_status_count')}",
        f"- trace_records: {primary.get('trace_records')}",
        f"- trace_profile_policy: {primary.get('trace_profile_policy')}",
        f"- UNKNOWN events: {primary.get('event_summary', {}).get('unknown_event_count')}",
        f"- corrupt records: {primary.get('event_summary', {}).get('corrupt_record_count')}",
        "",
        "## Targeted Validation Gate",
        "",
        f"- validation_run_id: {report['validation_run_id']}",
        f"- trace_gate_run_id: {report['trace_gate_run_id']}",
        f"- next gate claim_level: {validation.get('claim_level')}",
        f"- samples gate PASS: {validation.get('sample_gate_pass_count')}/{validation.get('sample_count')}",
        f"- sample status PASS: {validation.get('sample_status_pass_count')}/{validation.get('sample_status_count')}",
        "",
        "## Targeted Side-Channel Semantic Closure",
        "",
        f"- semantic_run_id: {report['semantic_run_id']}",
        f"- side-channel samples gate PASS: {side_channel.get('sample_gate_pass_count')}/{side_channel.get('sample_count')}",
        f"- side-channel sample status PASS: {side_channel.get('sample_status_pass_count')}/{side_channel.get('sample_status_count')}",
        f"- bundle status: {semantic['bundle'].get('status')}",
        f"- checker status: {semantic['bundle'].get('checker_status')}",
        f"- hardware_validated: {str(semantic['bundle'].get('hardware_validated')).lower()}",
        f"- fd/path: {semantic['fd_path'].get('status')} ({semantic['fd_path'].get('selected_source_type')})",
        f"- process tree: {semantic['process_tree'].get('status')} ({semantic['process_tree'].get('edge_count')} edges)",
        f"- function attribution: {semantic['function_attribution'].get('status')}",
        f"- source attribution: {semantic['source_attribution'].get('status')}",
        "",
        "## Focused Side-Channel Closure",
        "",
        f"- closure_run_id: {focused_closure.get('run_id')}",
        f"- trace_records: {focused_closure.get('trace_records')}",
        f"- focused samples gate PASS: {focused_closure.get('sample_gate_pass_count')}/{focused_closure.get('sample_count')}",
        f"- focused sample status PASS: {focused_closure.get('sample_status_pass_count')}/{focused_closure.get('sample_count')}",
        f"- status: {focused_closure.get('status')}",
        f"- gate report: {focused_closure.get('gate_report')}",
        f"- plan: {focused_closure.get('plan')}",
        "",
        "This focused R2048 closure covers the four previously failing side-channel samples. It does not convert the earlier R512 side-channel semantic capture into a single-run 13/13 side-channel result.",
        "",
        "## Assessment Requirement Matrix",
        "",
        f"- status: {requirement_matrix.get('status')}",
        f"- requirement count: {requirement_matrix.get('requirement_count')}",
        "",
        "## Hardware Trace Prototype",
        "",
        f"- status: {hardware.get('status')}",
        f"- trace_records: {hardware.get('trace_records')}",
        f"- trace_profile_policy: {hardware.get('trace_profile_policy')}",
        f"- samples gate PASS: {hardware.get('sample_gate_pass_count')}/{hardware.get('sample_count')}",
        f"- decoded trace files: {hardware.get('decoded_trace_file_count')}",
        "",
        "Boundaries:",
    ]
    lines.extend(f"- {item}" for item in hardware.get("boundaries", []))
    lines += [
        "",
        "## Local Code Analysis",
        "",
        f"- status: {local.get('status')}",
        f"- samples: {local.get('sample_count')}",
        f"- complete trace-on repetitions: {local.get('complete_rep_count')}/{local.get('expected_rep_count')}",
        "",
        "Boundaries:",
    ]
    lines.extend(f"- {item}" for item in local.get("boundaries", []))
    lines += [
        "",
        "## Malware Behavior Audit",
        "",
        f"- status: {malware.get('status')}",
        f"- samples: {malware.get('sample_count')}",
        f"- rules: {malware.get('rule_count')}",
        f"- gate expected rules PASS: {malware.get('gate_expected_rule_pass_count')}/{malware.get('rule_count')}",
        "",
        "Boundaries:",
    ]
    lines.extend(f"- {item}" for item in malware.get("boundaries", []))
    lines += [
        "",
        "## Raw Artifact Sanitization",
        "",
        f"- status: {raw_sanitization.get('status')}",
        f"- class count: {raw_sanitization.get('class_count')}",
        f"- full raw material: {raw_sanitization.get('release_policy', {}).get('full_raw_material')}",
        "",
        "## Raw Artifact Escrow",
        "",
        f"- status: {raw_escrow.get('status')}",
        f"- payload files: {raw_escrow.get('payload_file_count')}",
        f"- payload bytes: {raw_escrow.get('payload_total_bytes')}",
        f"- package dir: {raw_escrow.get('package_dir')}",
        "",
        "## Supported Claims",
        "",
    ]
    lines.extend(f"- {item}" for item in report["supported_claims"])
    lines += ["", "## Forbidden Claims", ""]
    lines.extend(f"- {item}" for item in report["forbidden_claims"])
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {item}" for item in report["limitations"])
    if validation.get("failed_samples"):
        lines += ["", "## Trace-Gate Failures", ""]
        for item in validation["failed_samples"]:
            lines.append(
                "- {sample_id}: failures={failures}; blockers={blockers}; marker={marker}; runtime={runtime}; capped_reps={capped}".format(
                    sample_id=item.get("sample_id"),
                    failures=", ".join(str(v) for v in item.get("gate_failures", [])) or "none",
                    blockers=", ".join(str(v) for v in item.get("gate_blockers", [])) or "none",
                    marker=item.get("marker_scope_status"),
                    runtime=item.get("runtime_process_attribution_status"),
                    capped=len(item.get("capped_reps", []) or []),
                )
            )
    if side_channel.get("failed_samples"):
        lines += ["", "## Side-Channel Gate Failures", ""]
        for item in side_channel["failed_samples"]:
            lines.append(
                "- {sample_id}: failures={failures}; blockers={blockers}; marker={marker}; runtime={runtime}; capped_reps={capped}".format(
                    sample_id=item.get("sample_id"),
                    failures=", ".join(str(v) for v in item.get("gate_failures", [])) or "none",
                    blockers=", ".join(str(v) for v in item.get("gate_blockers", [])) or "none",
                    marker=item.get("marker_scope_status"),
                    runtime=item.get("runtime_process_attribution_status"),
                    capped=len(item.get("capped_reps", []) or []),
                )
            )
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    lines += ["", "## Warnings", ""]
    lines.extend(f"- {item}" for item in report["warnings"] or ["none"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_report(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "paper_evidence_check.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "paper_evidence_check.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def make_gate(
    run_id: str,
    *,
    claim_level: str,
    fail_sample: str | None = None,
    samples: list[str] | None = None,
    trace_records: int = 512,
) -> dict[str, Any]:
    default_samples = [
        "hello",
        "ls",
        "cat",
        "cp",
        "sha256sum",
        "file_scan",
        "batch_open_read_write",
        "self_copy_sim",
        "abnormal_syscall_sequence",
        "illegal_trap",
        "process_chain",
        "dynamic_executable_memory",
        "anti_debug_like",
    ]
    samples = default_samples if samples is None else samples
    rows = []
    for sample in samples:
        failed = sample == fail_sample
        rows.append(
            {
                "sample_id": sample,
                "gate_status": "FAIL" if failed else "PASS",
                "gate_failures": ["missing_strong_expected"] if failed else [],
                "gate_blockers": ["trace_record_cap_hit"] if failed else [],
                "marker_scope_summary": {"status": "FAIL" if failed else "PASS"},
                "runtime_process_attribution_summary": {"status": "BLOCKED" if failed else "PASS"},
                "drop_summary": {"capped_reps": ["rep_00"] if failed else [], "drop_rate_median": 0.1 if failed else 0.0},
            }
        )
    return {
        "schema": "rvmt.35t.next_gate.v2",
        "run_id": run_id,
        "claim_level": claim_level,
        "trace_records": trace_records,
        "trace_profile_policy": "35t_small_capacity",
        "samples": rows,
        "sample_status": {sample: {"status": "PASS"} for sample in samples},
        "event_summary": {sample: {"unknown_event_count": 0, "corrupt_record_count": 0} for sample in samples},
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_self_test_fixture(root: Path, *, primary_fail: bool = False) -> None:
    evidence = root / DEFAULT_EVIDENCE_ROOT
    write_json(root / PRIMARY_GATE, make_gate(SOURCE_RUN_ID, claim_level="full_matrix_ready", fail_sample="hello" if primary_fail else None))
    write_json(root / VALIDATION_GATE, make_gate(VALIDATION_RUN_ID, claim_level="prototype_only", fail_sample="process_chain"))
    write_json(
        root / SIDE_CHANNEL_CLOSURE_GATE,
        make_gate(
            SIDE_CHANNEL_CLOSURE_RUN_ID,
            claim_level="process_attributed_microbench_ready",
            samples=SIDE_CHANNEL_CLOSURE_SAMPLES,
            trace_records=2048,
        ),
    )
    write_json(
        evidence / SIDE_CHANNEL_CLOSURE_PLAN.name,
        {
            "schema": "rvmt.35t.side_channel_closure_plan.v1",
            "status": "PASS",
            "closure_run_id": SIDE_CHANNEL_CLOSURE_RUN_ID,
            "closure_verification": {"status": "PASS"},
        },
    )
    write_json(
        root / VALIDATION_BUNDLE,
        {
            "schema": "rvmt.35t.board_validation_bundle.v1",
            "source_run_id": SOURCE_RUN_ID,
            "validation_run_id": VALIDATION_RUN_ID,
            "status": "PASS",
            "checker_status": "PASS",
            "hardware_validated": True,
            "selected_statuses": {"fd_path_flow": "PASS", "process_tree": "PASS", "source_attribution": "PARTIAL"},
        },
    )
    write_json(
        evidence / "evidence_manifest.json",
        {
            "schema": "rvmt.35t.evidence_snapshot.v1",
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "real_malware": False,
            "cva6_in_scope": False,
            "non_claims": EXPECTED_NON_CLAIMS,
        },
    )
    write_json(evidence / "application_closure_check.json", {"status": "PASS"})
    write_json(
        evidence / "board_validation_attempt_summary.json",
        {"status": "BOARD_VALIDATION_PASS", "hardware_validated": True, "next_gate": {"claim_level": "prototype_only"}},
    )
    write_json(evidence / "board_validation_status.json", {"status": "PASS", "hardware_validated": True})
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
                "file_scan": {"status": "PASS", "selected_candidate": {"source_type": "syscall_side_channel"}},
                "batch_open_read_write": {"status": "PASS", "selected_candidate": {"source_type": "syscall_side_channel"}},
                "self_copy_sim": {"status": "PASS", "selected_candidate": {"source_type": "syscall_side_channel"}},
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
        evidence / "metric_coverage.json",
        {
            "schema": "rvmt.35t.metric_coverage.v1",
            "status": "BOUNDED_METRIC_COVERAGE_READY_WITH_DEFERRED_FULL_ACCURACY",
            "required_metrics": [f"metric_{index}" for index in range(12)],
            "checks": {"all_required_metrics_listed": True},
        },
    )
    write_json(
        evidence / "threat_model_boundary.json",
        {
            "schema": "rvmt.35t.threat_model_boundary.v1",
            "status": "TRUSTED_KERNEL_USER_MODE_THREAT_MODEL_BOUNDARY_SPECIFIED",
            "trusted_components": ["linux_kernel"],
            "in_scope": ["user_mode_malware_like_workload"],
            "out_of_scope": ["kernel_rootkit"],
        },
    )
    write_json(
        evidence / "function_attribution_summary.json",
        {
            "schema": "rvmt.35t.function_attribution_summary.v1",
            "status": "PASS",
            "function_level": {"status": "available", "sample_count": 6, "samples_available": 6},
        },
    )
    write_json(
        evidence / "source_attribution_summary.json",
        {
            "schema": "rvmt.35t.source_attribution_summary.v1",
            "status": "PARTIAL",
            "function_level": {"status": "available"},
            "source_line_level": {"status": "unavailable"},
        },
    )
    workflow = root / ".github/workflows/35t-closure.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "\n".join(
            [
                "steps:",
                "  - run: uv run --no-sync python tools/check_35t_application_closure.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_paper_evidence.py --self-test",
                "  - run: uv run --no-sync python tools/recover_fd_path_flow.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_fd_path_case_studies.py --self-test",
                "  - run: uv run --no-sync python tools/recover_process_tree.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_process_tree_case_study.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_metric_coverage.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_pointer_snapshot_gate.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_pointer_snapshot_design_review.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_pointer_snapshot_design_review.py --no-write",
                "  - run: uv run --no-sync python tools/check_35t_threat_model.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_helper_alignment.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_helper_alignment.py --no-write",
                "  - run: uv run --no-sync python tools/check_35t_baseline_execution_spec.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_qemu_plugin_build_preflight.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_synthetic_extension_host_smoke.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_synthetic_extension_behavior_smoke.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_extension_35t_enablement.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_extension_35t_enablement.py --no-write",
                "  - run: uv run --no-sync python tools/check_35t_assessment_traceability.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --no-write",
                "  - run: uv run --no-sync python tools/check_35t_remaining_external_work.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_remaining_external_work.py --no-write",
                "  - run: uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --no-write",
                "  - run: uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --no-write",
                "  - run: uv run --no-sync python tools/check_35t_evidence_consistency.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_evidence_consistency.py --no-write",
                "  - run: uv run --no-sync python tools/check_35t_paper_positioning.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_assessment_reconciliation.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_assessment_gate_criteria.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_hardware_trace_prototype.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_local_code_analysis.py --self-test",
                "  - run: uv run --no-sync python tools/check_35t_malware_behavior_audit.py --self-test",
            ]
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    write_json(evidence / "assessment_gate_criteria.json", {"status": "ASSESSMENT_GATE_CRITERIA_PASS"})
    write_json(
        evidence / "assessment_requirement_matrix.json",
        {
            "schema": "rvmt.35t.assessment_requirement_matrix.v1",
            "status": ASSESSMENT_REQUIREMENT_MATRIX_STATUS,
            "requirement_count": 14,
            "high_level_checks": {"bounded_external_records_complete": True},
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
        evidence / "raw_artifact_sanitization.json",
        {
            "schema": "rvmt.35t.raw_artifact_sanitization.v1",
            "status": "RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED",
            "class_count": 2,
            "checks": {
                "sanitized_excerpts_do_not_expose_scanned_patterns": True,
                "full_raw_release_deferred": True,
            },
            "release_policy": {"full_raw_material": "deferred"},
        },
    )
    write_json(
        evidence / "raw_artifact_escrow.json",
        {
            "schema": "rvmt.35t.raw_artifact_escrow.v1",
            "status": "LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED",
            "payload_file_count": 14,
            "payload_total_bytes": 1024,
            "package_dir": "results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_escrow_package",
            "checks": {"payload_files_present_and_hashed": True, "public_release_deferred": True},
        },
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_self_test_fixture(root)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "PASS" or report["strict_single_run_status"] != "FAIL":
            print("[FAIL] expected bounded PASS with strict single-run FAIL", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_report(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "paper_evidence_check.md").exists():
            print("[FAIL] missing paper evidence markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_self_test_fixture(root, primary_fail=True)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL":
            print("[FAIL] expected primary gate failure to fail paper evidence", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T paper evidence self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check whether the 35T evidence chain can support bounded paper claims.")
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
        print(f"check_35t_paper_evidence: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T paper evidence check ({report['paper_support_status']})")
    if report["warnings"]:
        for warning in report["warnings"]:
            print(f"warning: {warning}", file=sys.stderr)
    if report["failures"]:
        for failure in report["failures"]:
            print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
