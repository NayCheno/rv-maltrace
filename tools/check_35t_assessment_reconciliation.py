from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_ASSESSMENT = Path("D:/Download/rv_maltrace_35t_assessment.md")
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
SCHEMA = "rvmt.35t.assessment_reconciliation.v1"
STATUS = "CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT"
HARDWARE_TRACE_PROTOTYPE_STATUS = "HARDWARE_TRACE_PROTOTYPE_PASS_35T_SMALL_CAPACITY"
LOCAL_CODE_ANALYSIS_STATUS = "LOCAL_CODE_ANALYSIS_PROTOTYPE_PASS_WITH_BOUNDED_ATTRIBUTION"
MALWARE_BEHAVIOR_AUDIT_STATUS = "SYNTHETIC_MALWARE_LIKE_BEHAVIOR_AUDIT_PASS_REAL_MALWARE_DEFERRED"


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


def goal_by_id(closure: dict[str, Any]) -> dict[str, dict[str, Any]]:
    goals = closure.get("goals", [])
    return {
        str(goal.get("id")): goal
        for goal in goals
        if isinstance(goal, dict) and goal.get("id")
    } if isinstance(goals, list) else {}


def remaining_ids(remaining: dict[str, Any]) -> set[str]:
    records = remaining.get("records", [])
    return {
        str(record.get("id"))
        for record in records
        if isinstance(record, dict) and record.get("id")
    } if isinstance(records, list) else set()


def satisfied_ids(remaining: dict[str, Any]) -> set[str]:
    records = remaining.get("satisfied_conditions", [])
    return {
        str(record.get("id"))
        for record in records
        if isinstance(record, dict) and record.get("id")
    } if isinstance(records, list) else set()


def baseline_statuses(summary: dict[str, Any]) -> dict[str, str]:
    baselines = summary.get("baselines", {})
    if not isinstance(baselines, dict):
        return {}
    statuses: dict[str, str] = {}
    for name, row in baselines.items():
        if isinstance(row, dict):
            statuses[str(name)] = str(row.get("status"))
    return statuses


def row(
    *,
    goal_id: str,
    assessment_snapshot: str,
    current_status: str,
    reconciliation_status: str,
    evidence: list[str],
    boundary: str,
) -> dict[str, Any]:
    return {
        "goal_id": goal_id,
        "assessment_snapshot": assessment_snapshot,
        "current_status": current_status,
        "reconciliation_status": reconciliation_status,
        "evidence": evidence,
        "boundary": boundary,
    }


def build_rows(
    closure: dict[str, Any],
    hardware_trace: dict[str, Any],
    local_code_analysis: dict[str, Any],
    malware_behavior_audit: dict[str, Any],
    fd_cases: dict[str, Any],
    process_case: dict[str, Any],
    pointer_design: dict[str, Any],
    helper_alignment: dict[str, Any],
    baseline_summary: dict[str, Any],
    qemu_plugin_build: dict[str, Any],
    extension_check: dict[str, Any],
    extension_host_smoke: dict[str, Any],
    extension_target_smoke: dict[str, Any],
    extension_behavior_smoke: dict[str, Any],
    extension_enablement: dict[str, Any],
    raw_sanitization: dict[str, Any],
    raw_escrow: dict[str, Any],
    package_manifest: dict[str, Any],
    paper_positioning: dict[str, Any],
) -> list[dict[str, Any]]:
    goals = goal_by_id(closure)
    statuses = baseline_statuses(baseline_summary)
    return [
        row(
            goal_id="P0_claim_boundary",
            assessment_snapshot="freeze 35T claim and CCF-A/CVA6/real-malware non-claims",
            current_status=str(goals.get("P0_claim_boundary", {}).get("status")),
            reconciliation_status="BOUNDARY_LOCAL_CODE_AND_MALWARE_AUDIT_CONFIRMED"
            if hardware_trace.get("status") == HARDWARE_TRACE_PROTOTYPE_STATUS
            and local_code_analysis.get("status") == LOCAL_CODE_ANALYSIS_STATUS
            and malware_behavior_audit.get("status") == MALWARE_BEHAVIOR_AUDIT_STATUS
            else "NOT_RECONCILED",
            evidence=[
                "paper_positioning.json",
                "paper_evidence_check.json",
                "hardware_trace_prototype.json",
                "local_code_analysis.json",
                "malware_behavior_audit.json",
                "assessment_closure.json",
            ],
            boundary="35T remains a bounded synthetic malware-like behavior audit prototype.",
        ),
        row(
            goal_id="P1_fd_path_flow",
            assessment_snapshot="assessment snapshot says fd/path Flow Summary is PARTIAL and no flows are fully linked",
            current_status=str(goals.get("P1_fd_path_flow", {}).get("status")),
            reconciliation_status="UPDATED_BY_CURRENT_BOARD_SIDE_CHANNEL_CASE_STUDIES"
            if fd_cases.get("status") == "PASS"
            else "NOT_RECONCILED",
            evidence=["fd_path_case_studies.json", "fd_path_flow_summary.json", "assessment_closure.json"],
            boundary="P1 is closed only for the prioritized representative case studies; path strings are side-channel backed, not enabled hardware pointer snapshots.",
        ),
        row(
            goal_id="P2_process_tree",
            assessment_snapshot="assessment snapshot says Process Tree Summary is PARTIAL and no strict edges are closed",
            current_status=str(goals.get("P2_process_tree", {}).get("status")),
            reconciliation_status="UPDATED_BY_CURRENT_BOARD_SIDE_CHANNEL_CASE_STUDY"
            if process_case.get("status") == "PASS"
            else "NOT_RECONCILED",
            evidence=["process_tree_case_study.json", "process_tree_summary.json", "assessment_closure.json"],
            boundary="P2 is a representative process-chain explanation; target parent PID remains intentionally unresolved.",
        ),
        row(
            goal_id="P3_pointer_argument_semantics",
            assessment_snapshot="assessment says pointer argument semantic reconstruction is the key remaining CCF-A step",
            current_status=str(goals.get("P3_pointer_argument_semantics", {}).get("status")),
            reconciliation_status="POINTER_DESIGN_AND_HELPER_ALIGNMENT_RECORDED_HARDWARE_SNAPSHOT_STILL_DEFERRED"
            if helper_alignment.get("status") == "TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL"
            and pointer_design.get("status") == "POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED"
            else "CURRENT_BOUNDARY_RECORDED_NOT_UPGRADED",
            evidence=[
                "pointer_semantics_preflight.json",
                "pointer_snapshot_enablement_gate.json",
                "pointer_snapshot_design_review.json",
                "helper_alignment.json",
                "remaining_external_work.json",
            ],
            boundary="Pointer snapshot design review and representative trusted-helper alignment are recorded under the trusted-kernel boundary; hardware user-pointer snapshot remains deferred.",
        ),
        row(
            goal_id="P4_baseline_evaluation",
            assessment_snapshot="assessment says optional eBPF-only, QEMU-plugin, and software instrumentation baselines are blocked",
            current_status=str(goals.get("P4_baseline_evaluation", {}).get("status")),
            reconciliation_status="SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_UPDATED"
            if statuses.get("software_instrumentation") == "PASS"
            and statuses.get("ebpf_only") == "PASS"
            and statuses.get("qemu_plugin") == "PASS"
            and qemu_plugin_build.get("status") == "QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED"
            else "NOT_RECONCILED",
            evidence=[
                "baseline_evaluation_summary.json",
                "baseline_execution_spec_check.json",
                "advanced_baseline_preflight.json",
                "qemu_plugin_build_preflight.json",
                "qemu_plugin_baseline_summary.json",
            ],
            boundary="Software instrumentation, host eBPF, and QEMU-plugin syscall-count evidence are recorded under bounded simulator/software claims.",
        ),
        row(
            goal_id="P5_synthetic_suite_extension",
            assessment_snapshot="assessment recommends synthetic suite expansion before any real malware route",
            current_status=str(goals.get("P5_synthetic_suite_extension", {}).get("status")),
            reconciliation_status="EXTENSION_ENABLEMENT_PREFLIGHT_RECORDED_35T_GATING_DEFERRED"
            if extension_check.get("status") == "IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING"
            and extension_behavior_smoke.get("status") == "HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED"
            and extension_enablement.get("status") == "EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED"
            else "NOT_RECONCILED",
            evidence=[
                "synthetic_suite_extension_check.json",
                "synthetic_extension_host_smoke.json",
                "synthetic_extension_target_smoke.json",
                "synthetic_extension_behavior_smoke.json",
                "extension_35t_enablement_preflight.json",
                "experiments/linux_behavior/malware_like/extension_plan.json",
            ],
            boundary=(
                "Implemented source candidates have host/QEMU behavior smoke plus a default-disabled runner/rootfs/CLI enablement path, but are not expanded 35T coverage; "
                f"host smoke status is {extension_host_smoke.get('status')}; "
                f"target smoke status is {extension_target_smoke.get('status')}; "
                f"behavior smoke status is {extension_behavior_smoke.get('status')}; "
                f"enablement status is {extension_enablement.get('status')}."
            ),
        ),
        row(
            goal_id="P6_artifact_package",
            assessment_snapshot="assessment says the committed evidence snapshot is lightweight and full paper artifacts need more packaging",
            current_status=str(goals.get("P6_artifact_package", {}).get("status")),
            reconciliation_status="LOCAL_RAW_ESCROW_READY_PUBLIC_RELEASE_DEFERRED"
            if package_manifest.get("status") == "LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED"
            and raw_sanitization.get("status") == "RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED"
            and raw_escrow.get("status") == "LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED"
            else "NOT_RECONCILED",
            evidence=[
                "raw_artifact_sanitization.json",
                "raw_artifact_escrow.json",
                "artifact_package_readiness.json",
                "paper_artifact_package_manifest.json",
                "paper_artifact_release_policy.json",
            ],
            boundary="The lightweight release candidate, sanitized excerpts, and local raw escrow package are ready; public or external raw release still requires approval or a controlled-release destination.",
        ),
    ]


def build_report(repo_root: Path, assessment_arg: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    assessment_path = repo_path(repo_root, assessment_arg).resolve()
    failures: list[str] = []
    assessment = read_text(assessment_path, failures, repo_root, "assessment document")
    closure = read_json(evidence_root / "assessment_closure.json", failures, repo_root, "assessment closure")
    traceability = read_json(evidence_root / "assessment_traceability.json", failures, repo_root, "assessment traceability")
    remaining = read_json(evidence_root / "remaining_external_work.json", failures, repo_root, "remaining external work")
    paper_positioning = read_json(evidence_root / "paper_positioning.json", failures, repo_root, "paper positioning")
    hardware_trace = read_json(evidence_root / "hardware_trace_prototype.json", failures, repo_root, "hardware trace prototype")
    local_code_analysis = read_json(evidence_root / "local_code_analysis.json", failures, repo_root, "local code analysis")
    malware_behavior_audit = read_json(evidence_root / "malware_behavior_audit.json", failures, repo_root, "malware behavior audit")
    fd_cases = read_json(evidence_root / "fd_path_case_studies.json", failures, repo_root, "fd/path case studies")
    process_case = read_json(evidence_root / "process_tree_case_study.json", failures, repo_root, "process-tree case study")
    pointer_design = read_json(evidence_root / "pointer_snapshot_design_review.json", failures, repo_root, "pointer snapshot design review")
    helper_alignment = read_json(evidence_root / "helper_alignment.json", failures, repo_root, "helper alignment")
    baseline_summary = read_json(evidence_root / "baseline_evaluation_summary.json", failures, repo_root, "baseline summary")
    qemu_plugin_build = read_json(evidence_root / "qemu_plugin_build_preflight.json", failures, repo_root, "QEMU-plugin build preflight")
    extension_check = read_json(evidence_root / "synthetic_suite_extension_check.json", failures, repo_root, "synthetic extension check")
    extension_host_smoke = read_json(evidence_root / "synthetic_extension_host_smoke.json", failures, repo_root, "synthetic extension host smoke")
    extension_target_smoke = read_json(evidence_root / "synthetic_extension_target_smoke.json", failures, repo_root, "synthetic extension target smoke")
    extension_behavior_smoke = read_json(evidence_root / "synthetic_extension_behavior_smoke.json", failures, repo_root, "synthetic extension behavior smoke")
    extension_enablement = read_json(evidence_root / "extension_35t_enablement_preflight.json", failures, repo_root, "extension 35T enablement preflight")
    raw_sanitization = read_json(evidence_root / "raw_artifact_sanitization.json", failures, repo_root, "raw artifact sanitization")
    raw_escrow = read_json(evidence_root / "raw_artifact_escrow.json", failures, repo_root, "raw artifact escrow")
    package_manifest = read_json(evidence_root / "paper_artifact_package_manifest.json", failures, repo_root, "paper artifact package manifest")

    rows = build_rows(
        closure,
        hardware_trace,
        local_code_analysis,
        malware_behavior_audit,
        fd_cases,
        process_case,
        pointer_design,
        helper_alignment,
        baseline_summary,
        qemu_plugin_build,
        extension_check,
        extension_host_smoke,
        extension_target_smoke,
        extension_behavior_smoke,
        extension_enablement,
        raw_sanitization,
        raw_escrow,
        package_manifest,
        paper_positioning,
    )
    open_external = remaining_ids(remaining)
    required_open_external = {
        "p3_hardware_user_pointer_snapshot",
        "p5_extension_35t_gating",
        "p6_full_raw_artifact_release",
    }
    required_satisfied = {"p3_trusted_helper_or_ebpf_alignment", "p5_extension_35t_enablement_preflight"}
    checks = {
        "assessment_has_fd_path_partial_snapshot": "fd/path Flow Summary" in assessment and "Status: PARTIAL" in assessment and "Flows: none fully linked" in assessment,
        "assessment_has_process_tree_partial_snapshot": "Process Tree Summary" in assessment and "Edges: none strictly closed" in assessment,
        "assessment_has_baseline_blocked_snapshot": "ebpf_only: BLOCKED" in assessment and "qemu_plugin: BLOCKED" in assessment and "software_instrumentation: BLOCKED" in assessment,
        "assessment_has_lightweight_artifact_snapshot": "当前 snapshot 是轻量摘要" in assessment and "论文 artifact 需要更完整" in assessment,
        "closure_bounded_pass": closure.get("status") == "PASS_WITH_BOUNDED_REMAINING_WORK",
        "traceability_bounded_pass": traceability.get("status") == "PASS_WITH_BOUNDED_REMAINING_WORK",
        "paper_positioning_ready": paper_positioning.get("status") == "BOUNDED_FEASIBILITY_POSITIONING_READY",
        "remaining_external_work_recorded": remaining.get("status") == "PASS_CURRENT_EXTERNAL_CONDITIONS_RECORDED",
        "p1_snapshot_updated": any(row["goal_id"] == "P1_fd_path_flow" and row["reconciliation_status"] == "UPDATED_BY_CURRENT_BOARD_SIDE_CHANNEL_CASE_STUDIES" for row in rows),
        "p2_snapshot_updated": any(row["goal_id"] == "P2_process_tree" and row["reconciliation_status"] == "UPDATED_BY_CURRENT_BOARD_SIDE_CHANNEL_CASE_STUDY" for row in rows),
        "p3_snapshot_design_and_helper_updated": any(row["goal_id"] == "P3_pointer_argument_semantics" and row["reconciliation_status"] == "POINTER_DESIGN_AND_HELPER_ALIGNMENT_RECORDED_HARDWARE_SNAPSHOT_STILL_DEFERRED" for row in rows),
        "p4_snapshot_updated": any(row["goal_id"] == "P4_baseline_evaluation" and row["reconciliation_status"] == "SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_UPDATED" for row in rows),
        "p5_sources_recorded_without_35t_claim": any(row["goal_id"] == "P5_synthetic_suite_extension" and row["reconciliation_status"] == "EXTENSION_ENABLEMENT_PREFLIGHT_RECORDED_35T_GATING_DEFERRED" for row in rows),
        "p6_local_raw_escrow_ready_public_release_deferred": any(row["goal_id"] == "P6_artifact_package" and row["reconciliation_status"] == "LOCAL_RAW_ESCROW_READY_PUBLIC_RELEASE_DEFERRED" for row in rows),
        "external_conditions_not_silently_closed": required_open_external <= open_external,
        "satisfied_conditions_not_silent": required_satisfied <= satisfied_ids(remaining),
        "all_rows_have_evidence": all(row["evidence"] for row in rows),
        "no_unreconciled_rows": all(row["reconciliation_status"] != "NOT_RECONCILED" for row in rows),
    }
    failures.extend(key for key, ok in checks.items() if not ok)
    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "status": STATUS if not failures else "FAIL",
        "assessment_source": str(assessment_path),
        "evidence_root": rel(evidence_root, repo_root),
        "checks": checks,
        "reconciliation_rows": rows,
        "interpretation": [
            "the assessment document is treated as a source snapshot, while current repository evidence is authoritative",
            "P1/P2 have been upgraded only to representative board-side-channel case-study closure, not full semantic reconstruction",
            "P3-P6 retain explicit deferred or current-environment boundaries where required external evidence is unavailable",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Assessment Reconciliation: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Assessment source: `{report['assessment_source']}`",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Reconciliation Rows",
        "",
        "| Goal | Current Status | Reconciliation | Boundary |",
        "| --- | --- | --- | --- |",
    ]
    for item in report["reconciliation_rows"]:
        lines.append(
            f"| `{item['goal_id']}` | `{item['current_status']}` | `{item['reconciliation_status']}` | {item['boundary']} |"
        )
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "assessment_reconciliation.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "assessment_reconciliation.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_fixture(root: Path, *, bad_fd_path: bool = False) -> Path:
    evidence = root / DEFAULT_EVIDENCE_ROOT
    assessment = root / "assessment.md"
    assessment.write_text(
        "\n".join(
            [
                "fd/path Flow Summary",
                "Status: PARTIAL",
                "Flows: none fully linked",
                "Process Tree Summary",
                "Edges: none strictly closed",
                "ebpf_only: BLOCKED",
                "qemu_plugin: BLOCKED",
                "software_instrumentation: BLOCKED",
                "当前 snapshot 是轻量摘要。论文 artifact 需要更完整。",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    write_json(
        evidence / "assessment_closure.json",
        {
            "schema": "rvmt.35t.assessment_closure.v1",
            "status": "PASS_WITH_BOUNDED_REMAINING_WORK",
            "goals": [
                {"id": "P0_claim_boundary", "status": "PASS"},
                {"id": "P1_fd_path_flow", "status": "PASS"},
                {"id": "P2_process_tree", "status": "PASS"},
                {"id": "P3_pointer_argument_semantics", "status": "PARTIAL_BOUNDED_SYNTHETIC_ARG_MEM_GUARDRAILS"},
                {"id": "P4_baseline_evaluation", "status": "HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS"},
                {"id": "P5_synthetic_suite_extension", "status": "IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING"},
                {"id": "P6_artifact_package", "status": "LIGHTWEIGHT_ARTIFACT_PASS_FULL_REPRO_DEFERRED"},
            ],
        },
    )
    write_json(evidence / "assessment_traceability.json", {"status": "PASS_WITH_BOUNDED_REMAINING_WORK"})
    write_json(evidence / "paper_positioning.json", {"status": "BOUNDED_FEASIBILITY_POSITIONING_READY"})
    write_json(
        evidence / "hardware_trace_prototype.json",
        {
            "schema": "rvmt.35t.hardware_trace_prototype.v1",
            "status": HARDWARE_TRACE_PROTOTYPE_STATUS,
        },
    )
    write_json(
        evidence / "local_code_analysis.json",
        {
            "schema": "rvmt.35t.local_code_analysis.v1",
            "status": LOCAL_CODE_ANALYSIS_STATUS,
        },
    )
    write_json(
        evidence / "malware_behavior_audit.json",
        {
            "schema": "rvmt.35t.malware_behavior_audit.v1",
            "status": MALWARE_BEHAVIOR_AUDIT_STATUS,
        },
    )
    write_json(evidence / "fd_path_case_studies.json", {"status": "FAIL" if bad_fd_path else "PASS"})
    write_json(evidence / "process_tree_case_study.json", {"status": "PASS"})
    write_json(evidence / "pointer_snapshot_design_review.json", {"status": "POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED"})
    write_json(evidence / "helper_alignment.json", {"status": "TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL"})
    write_json(
        evidence / "baseline_evaluation_summary.json",
        {
            "baselines": {
                "software_instrumentation": {"status": "PASS"},
                "ebpf_only": {"status": "PASS"},
                "qemu_plugin": {"status": "PASS"},
            }
        },
    )
    write_json(evidence / "qemu_plugin_build_preflight.json", {"status": "QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED"})
    write_json(evidence / "qemu_plugin_baseline_summary.json", {"status": "QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES", "pass_count": 13})
    write_json(evidence / "synthetic_suite_extension_check.json", {"status": "IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING"})
    write_json(evidence / "synthetic_extension_host_smoke.json", {"status": "HOST_COMPILE_SMOKE_BLOCKED_CURRENT_ENVIRONMENT"})
    write_json(evidence / "synthetic_extension_target_smoke.json", {"status": "TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED"})
    write_json(evidence / "synthetic_extension_behavior_smoke.json", {"status": "HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED"})
    write_json(evidence / "extension_35t_enablement_preflight.json", {"status": "EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED"})
    write_json(evidence / "raw_artifact_sanitization.json", {"status": "RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED"})
    write_json(evidence / "raw_artifact_escrow.json", {"status": "LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED"})
    write_json(evidence / "paper_artifact_package_manifest.json", {"status": "LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED"})
    write_json(
        evidence / "remaining_external_work.json",
        {
            "status": "PASS_CURRENT_EXTERNAL_CONDITIONS_RECORDED",
            "records": [
                {"id": "p3_hardware_user_pointer_snapshot"},
                {"id": "p5_extension_35t_gating"},
                {"id": "p6_full_raw_artifact_release"},
            ],
            "satisfied_conditions": [
                {"id": "p3_trusted_helper_or_ebpf_alignment"},
                {"id": "p4_qemu_plugin_baseline"},
                {"id": "p5_extension_35t_enablement_preflight"},
            ],
        },
    )
    return assessment


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = write_fixture(root)
        report = build_report(root, assessment, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != STATUS:
            print("[FAIL] expected assessment reconciliation fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "assessment_reconciliation.md").exists():
            print("[FAIL] missing reconciliation markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = write_fixture(root, bad_fd_path=True)
        report = build_report(root, assessment, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL" or "p1_snapshot_updated" not in report["failures"]:
            print("[FAIL] expected stale fd/path reconciliation fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T assessment reconciliation self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reconcile the source 35T assessment snapshot with current evidence.")
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
        print(f"check_35t_assessment_reconciliation: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T assessment reconciliation")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
