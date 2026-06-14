from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT_JSON = DEFAULT_CURRENT_ROOT / "review_closure_audit.json"
DEFAULT_OUT_MD = Path("docs/07-evaluation-evidence/reports/ccfa_review_closure_audit.md")
NOT_APPLICABLE = "NOT_APPLICABLE"
MISSING = "MISSING"

EXTERNAL_IDS = {
    "board_native_dwarf_source_lines",
    "full_hardware_pointer_strings",
    "production_streaming_dma_trace_sink",
    "genesys2_board_benign_control",
}
ACCEPTED_EXTERNAL_STATUS = "EXTERNAL_SUMMARY_ACCEPTED"
OPEN_EXTERNAL_STATUS = "OPEN_EXTERNAL_ARTIFACTS_REQUIRED"

EVIDENCE_FILES: dict[str, str] = {
    "baseline_pass_criteria": "docs/03-platform-architecture/genesys2/baseline_pass_criteria.md",
    "board_bringup": "docs/03-platform-architecture/genesys2/board_bringup.md",
    "ccfa_readiness_matrix": "docs/07-evaluation-evidence/reports/ccfa_readiness_matrix.md",
    "ccfa_next_closure_plan": "docs/07-evaluation-evidence/reports/ccfa_next_closure_plan.md",
    "ccfa_remaining_blockers": "docs/07-evaluation-evidence/reports/ccfa_remaining_blockers_20260611.md",
    "evaluation_plan": "docs/07-evaluation-evidence/evaluation_plan.md",
    "p0_bram_trace": "results/evaluation/genesys2-cva6/current/p0_bram_trace_summary.json",
    "safe_surrogate_bram_trace": "results/evaluation/genesys2-cva6/current/safe_surrogate_bram_trace_summary.json",
    "trace_sink": "results/evaluation/genesys2-cva6/current/trace_sink_summary.json",
    "drop_accounting": "results/evaluation/genesys2-cva6/current/drop_accounting_summary.json",
    "statistical_robustness": "results/evaluation/genesys2-cva6/current/statistical_robustness_summary.json",
    "streaming_dma_target": "results/evaluation/genesys2-cva6/current/streaming_dma_target_summary.json",
    "streaming_dma_readiness": "results/evaluation/genesys2-cva6/current/streaming_dma_readiness_summary.json",
    "pointer_snapshot_guardrails": "results/evaluation/genesys2-cva6/current/pointer_snapshot_guardrails.json",
    "hardware_pointer_prefixes": "results/evaluation/genesys2-cva6/current/hardware_pointer_prefix_summary.json",
    "pointer_string_readiness": "results/evaluation/genesys2-cva6/current/pointer_string_readiness_summary.json",
    "semantic_reconstruction": "results/evaluation/genesys2-cva6/current/semantic_reconstruction_summary.json",
    "fd_path_graph": "results/evaluation/genesys2-cva6/current/fd_path_graph_summary.json",
    "source_line_attribution": "results/evaluation/genesys2-cva6/current/source_line_attribution_summary.json",
    "source_line_toolchain_probe": "results/evaluation/genesys2-cva6/current/source_line_toolchain_probe.json",
    "debug_elf_readiness": "results/evaluation/genesys2-cva6/current/debug_elf_readiness_summary.json",
    "process_elf_ownership": "results/evaluation/genesys2-cva6/current/process_elf_ownership_summary.json",
    "dynamic_mapping_attribution": "results/evaluation/genesys2-cva6/current/dynamic_mapping_attribution_summary.json",
    "ccfa_evaluation_matrix": "results/evaluation/genesys2-cva6/current/ccfa_evaluation_matrix.json",
    "baseline_alignment": "results/evaluation/genesys2-cva6/current/baseline_alignment_summary.json",
    "behavior_audit_metrics": "results/evaluation/genesys2-cva6/current/behavior_audit_metrics.json",
    "case_study_manifest": "results/evaluation/genesys2-cva6/current/case_study_manifest.json",
    "benign_control": "results/evaluation/genesys2-cva6/current/benign_control_summary.json",
    "board_benign_readiness": "results/evaluation/genesys2-cva6/current/board_benign_readiness_summary.json",
    "reproduce_genesys2_current": "tools/reproduce_genesys2_current.py",
    "reproducibility_manifest_checker": "tools/check_genesys2_reproducibility_manifest.py",
    "artifact_package_checker": "tools/check_genesys2_artifact_package.py",
    "external_closure_readiness": "results/evaluation/genesys2-cva6/current/external_closure_readiness.json",
    "external_closure_intake": "results/evaluation/genesys2-cva6/current/external_closure_intake.json",
    "external_closure_plan": "results/evaluation/genesys2-cva6/current/external_closure_plan.json",
    "external_closure_preflight": "results/evaluation/genesys2-cva6/current/external_closure_preflight.json",
    "external_operator_packet": "results/evaluation/genesys2-cva6/current/external_operator_packet.json",
    "external_template_board_native_source_lines": "results/evaluation/genesys2-cva6/current/external_closure_templates/board_native_source_lines_summary.template.json",
    "external_template_hardware_pointer_strings": "results/evaluation/genesys2-cva6/current/external_closure_templates/hardware_pointer_strings_summary.template.json",
    "external_template_streaming_dma_throughput": "results/evaluation/genesys2-cva6/current/external_closure_templates/streaming_dma_throughput_summary.template.json",
    "external_template_board_benign_control": "results/evaluation/genesys2-cva6/current/external_closure_templates/board_benign_control_summary.template.json",
    "real_malware_containment": "results/evaluation/genesys2-cva6/current/real_malware_containment.json",
}

REVIEW_ITEMS: list[dict[str, Any]] = [
    {
        "id": "phase_a_claim_boundary_convergence",
        "review_section": "Phase A",
        "requirement": "Synchronize paper-facing claim boundaries, allowed claims, non-claims, artifact roots, and checker commands.",
        "status": "PASS_CURRENT",
        "evidence_ids": ["ccfa_readiness_matrix", "ccfa_next_closure_plan", "ccfa_remaining_blockers", "evaluation_plan"],
        "checker_commands": [
            "uv run python tools/check_ccfa_claim_boundaries.py --root .",
            "uv run python tools/check_evaluation_plan.py --root .",
        ],
    },
    {
        "id": "phase_a_baseline_board_acceptance",
        "review_section": "Phase A",
        "requirement": "Close stale board baseline TODO state when physical Genesys2 baseline evidence exists.",
        "status": "PASS_CURRENT",
        "evidence_ids": ["baseline_pass_criteria", "board_bringup"],
        "checker_commands": ["uv run python tools/check_baseline_pass_criteria.py --root ."],
    },
    {
        "id": "phase_b_p0_and_safe_surrogate_hardware_trace",
        "review_section": "Phase B",
        "requirement": "Prove controlled Genesys2/CVA6 hardware trace for P0 and safe-surrogate workloads with accepted repetitions and drop accounting.",
        "status": "PASS_CURRENT_CONTROLLED",
        "evidence_ids": ["p0_bram_trace", "safe_surrogate_bram_trace", "trace_sink", "drop_accounting", "statistical_robustness"],
        "checker_commands": [
            "uv run python tools/check_genesys2_p0_bram_trace.py --root .",
            "uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .",
            "uv run python tools/check_trace_drop_accounting.py --root .",
            "uv run python tools/check_genesys2_statistical_robustness.py --root .",
        ],
    },
    {
        "id": "phase_b_bounded_pointer_semantics",
        "review_section": "Phase B",
        "requirement": "Provide hardware ARG_MEM pointer semantic evidence for openat, write, and execve without overclaiming full strings.",
        "status": "PASS_CURRENT_BOUNDED_PREFIX",
        "evidence_ids": ["pointer_snapshot_guardrails", "hardware_pointer_prefixes"],
        "checker_commands": [
            "uv run python tools/check_pointer_snapshot_guardrails.py --root .",
            "uv run python tools/check_hardware_pointer_prefixes.py --root .",
        ],
    },
    {
        "id": "phase_b_full_hardware_pointer_strings",
        "review_section": "Phase B",
        "requirement": "Close full hardware-derived pointer-string reconstruction only with new gap-free hardware evidence.",
        "status": "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
        "external_id": "full_hardware_pointer_strings",
        "evidence_ids": ["pointer_string_readiness", "external_closure_readiness", "external_closure_intake", "external_closure_plan", "external_closure_preflight", "external_operator_packet", "external_template_hardware_pointer_strings"],
        "checker_commands": [
            "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
            "uv run python tools/check_genesys2_external_closure_intake.py --root .",
            "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
            "uv run python tools/check_genesys2_external_operator_packet.py --root .",
            "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
        ],
    },
    {
        "id": "phase_c_function_process_elf_attribution",
        "review_section": "Phase C",
        "requirement": "Provide runtime process, ELF/function, dynamic mapping, and source-attribution boundary evidence.",
        "status": "PASS_CURRENT_FUNCTION_LEVEL",
        "evidence_ids": [
            "source_line_attribution",
            "source_line_toolchain_probe",
            "debug_elf_readiness",
            "process_elf_ownership",
            "dynamic_mapping_attribution",
        ],
        "checker_commands": [
            "uv run python tools/check_source_line_attribution.py --root .",
            "uv run python tools/check_source_line_toolchain_probe.py --root .",
            "uv run python tools/check_genesys2_debug_elf_readiness.py --root .",
            "uv run python tools/check_process_elf_ownership.py --root .",
            "uv run python tools/check_dynamic_mapping_attribution.py --root .",
        ],
    },
    {
        "id": "phase_c_board_native_dwarf_source_lines",
        "review_section": "Phase C",
        "requirement": "Close board-native DWARF source-line attribution only with exact debug ELF board reruns.",
        "status": "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
        "external_id": "board_native_dwarf_source_lines",
        "evidence_ids": ["debug_elf_readiness", "external_closure_readiness", "external_closure_intake", "external_closure_plan", "external_closure_preflight", "external_operator_packet", "external_template_board_native_source_lines"],
        "checker_commands": [
            "uv run python tools/check_genesys2_debug_elf_readiness.py --root .",
            "uv run python tools/check_genesys2_external_closure_intake.py --root .",
            "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
            "uv run python tools/check_genesys2_external_operator_packet.py --root .",
            "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
        ],
    },
    {
        "id": "phase_d_safe_surrogate_behavior_case_studies",
        "review_section": "Phase D",
        "requirement": "Package malware-like safe-surrogate behavior graphs, semantic events, baseline comparison, audit decisions, and per-sample case studies.",
        "status": "PASS_CURRENT_SAFE_SURROGATE",
        "evidence_ids": ["semantic_reconstruction", "fd_path_graph", "behavior_audit_metrics", "case_study_manifest"],
        "checker_commands": [
            "uv run python tools/check_syscall_semantic_reconstruction.py --root .",
            "uv run python tools/check_fd_path_graph.py --root .",
            "uv run python tools/check_behavior_audit_metrics.py --root .",
            "uv run python tools/check_ccfa_case_study_manifest.py --root .",
        ],
    },
    {
        "id": "phase_d_local_benign_control",
        "review_section": "Phase D",
        "requirement": "Provide benign-control false-positive evidence without treating local Linux controls as board traces.",
        "status": "PASS_CURRENT_LOCAL_LINUX_CONTROL",
        "evidence_ids": ["benign_control"],
        "checker_commands": ["uv run python tools/check_benign_control_summary.py --root ."],
    },
    {
        "id": "phase_d_genesys2_board_benign_control",
        "review_section": "Phase D",
        "requirement": "Close Genesys2 board benign-control false-positive evidence only with new board benign workload traces.",
        "status": "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
        "external_id": "genesys2_board_benign_control",
        "evidence_ids": ["board_benign_readiness", "external_closure_readiness", "external_closure_intake", "external_closure_plan", "external_closure_preflight", "external_operator_packet", "external_template_board_benign_control"],
        "checker_commands": [
            "uv run python tools/check_genesys2_board_benign_readiness.py --root .",
            "uv run python tools/check_genesys2_external_closure_intake.py --root .",
            "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
            "uv run python tools/check_genesys2_external_operator_packet.py --root .",
            "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
        ],
    },
    {
        "id": "phase_e_evaluation_matrix_and_baselines",
        "review_section": "Phase E",
        "requirement": "Provide workload manifest, evaluation matrix, baseline alignment, and metric provenance for controlled evidence.",
        "status": "PASS_CURRENT_CONTROLLED",
        "evidence_ids": ["ccfa_evaluation_matrix", "baseline_alignment", "behavior_audit_metrics", "statistical_robustness"],
        "checker_commands": [
            "uv run python tools/check_ccfa_evaluation_matrix.py --root .",
            "uv run python tools/check_baseline_alignment.py --root .",
            "uv run python tools/check_behavior_audit_metrics.py --root .",
            "uv run python tools/check_genesys2_statistical_robustness.py --root .",
        ],
    },
    {
        "id": "phase_e_statistical_robustness_audit",
        "review_section": "Phase E",
        "requirement": "Audit controlled repetition counts, workload classes, benign controls, and retained failed attempts without claiming randomized or real-malware generalization.",
        "status": "PASS_CURRENT_BOUNDED_STATISTICS",
        "evidence_ids": ["statistical_robustness", "p0_bram_trace", "safe_surrogate_bram_trace", "benign_control"],
        "checker_commands": [
            "uv run python tools/check_genesys2_statistical_robustness.py --root .",
            "uv run python tools/check_genesys2_p0_bram_trace.py --root .",
            "uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .",
            "uv run python tools/check_benign_control_summary.py --root .",
        ],
    },
    {
        "id": "phase_e_artifact_package_and_reproduction",
        "review_section": "Phase E",
        "requirement": "Provide current reproducibility manifest, lightweight artifact package, and fresh-clone reproduction commands.",
        "status": "PASS_CURRENT_LIGHTWEIGHT_PACKAGE",
        "evidence_ids": ["reproduce_genesys2_current", "reproducibility_manifest_checker", "artifact_package_checker"],
        "checker_commands": [
            "uv run python tools/check_genesys2_reproducibility_manifest.py --root .",
            "uv run python tools/check_genesys2_artifact_package.py --root .",
            "uv run python tools/reproduce_genesys2_current.py --full",
        ],
    },
    {
        "id": "phase_e_streaming_dma_target_baseline",
        "review_section": "Phase E",
        "requirement": "Quantify the p95 compact event-byte production target that future production streaming/DMA transport evidence must exceed.",
        "status": "PASS_CURRENT_TARGET_BASELINE",
        "evidence_ids": ["streaming_dma_target", "p0_bram_trace", "safe_surrogate_bram_trace"],
        "checker_commands": [
            "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
            "uv run python tools/check_genesys2_p0_bram_trace.py --root .",
            "uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .",
        ],
    },
    {
        "id": "phase_e_production_streaming_dma_trace_sink",
        "review_section": "Phase E",
        "requirement": "Close production streaming/DMA throughput only with non-BRAM transport, throughput, timing, and noninterference evidence.",
        "status": "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
        "external_id": "production_streaming_dma_trace_sink",
        "evidence_ids": ["streaming_dma_target", "streaming_dma_readiness", "external_closure_readiness", "external_closure_intake", "external_closure_plan", "external_closure_preflight", "external_operator_packet", "external_template_streaming_dma_throughput"],
        "checker_commands": [
            "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
            "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
            "uv run python tools/check_genesys2_external_closure_intake.py --root .",
            "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
            "uv run python tools/check_genesys2_external_operator_packet.py --root .",
            "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
        ],
    },
    {
        "id": "phase_g_real_malware_validation",
        "review_section": "Phase G",
        "requirement": "Keep real malware validation outside the current objective while preserving containment policy for optional future work.",
        "status": "EXCLUDED_BY_OBJECTIVE",
        "evidence_ids": ["real_malware_containment"],
        "checker_commands": [
            "uv run python tools/check_real_malware_containment.py --root .",
            "uv run python tools/check_real_malware_validation_gate.py",
        ],
    },
]


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json_if_present(path: Path) -> dict[str, Any] | None:
    if not path.is_file() or path.suffix.lower() != ".json":
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else None


def evidence_metadata(data: dict[str, Any] | None, key: str) -> str:
    if data is None:
        return NOT_APPLICABLE
    value = data.get(key)
    return value if isinstance(value, str) and value else MISSING


def evidence_row(evidence_id: str) -> dict[str, Any]:
    path_value = EVIDENCE_FILES[evidence_id]
    path = repo_path(path_value)
    data = load_json_if_present(path)
    return {
        "id": evidence_id,
        "path": path_value,
        "exists": path.is_file(),
        "sha256": sha256_file(path),
        "schema": evidence_metadata(data, "schema"),
        "status": evidence_metadata(data, "status"),
    }


def external_state(current_root: Path) -> dict[str, dict[str, Any]]:
    intake_path = ROOT / current_root / "external_closure_intake.json"
    intake = load_json_if_present(intake_path) or {}
    records = intake.get("records") if isinstance(intake.get("records"), list) else []
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        if isinstance(record, dict) and isinstance(record.get("id"), str):
            result[record["id"]] = {
                "completion_status": record.get("completion_status"),
                "current_blocker": record.get("current_blocker"),
                "external_summary_path": record.get("external_summary_path"),
                "external_summary_exists": record.get("external_summary_exists"),
                "completion_evidence_valid": record.get("completion_evidence_valid"),
            }
    return result


def external_item_status(default_status: str, external_id: str | None, external: dict[str, dict[str, Any]]) -> str:
    if default_status != OPEN_EXTERNAL_STATUS or not external_id:
        return default_status
    state = external.get(external_id, {})
    if state.get("completion_status") == "EXTERNAL_SUMMARY_ACCEPTED":
        return ACCEPTED_EXTERNAL_STATUS
    return OPEN_EXTERNAL_STATUS


def item_row(item: dict[str, Any], external: dict[str, dict[str, Any]]) -> dict[str, Any]:
    evidence = [evidence_row(evidence_id) for evidence_id in item["evidence_ids"]]
    external_id = item.get("external_id")
    row = {
        "id": item["id"],
        "review_section": item["review_section"],
        "requirement": item["requirement"],
        "status": external_item_status(item["status"], external_id, external),
        "evidence": evidence,
        "checker_commands": item["checker_commands"],
    }
    if external_id:
        row["external_id"] = external_id
        row["external_state"] = external.get(external_id, {})
    return row


def summarize(items: list[dict[str, Any]], external: dict[str, dict[str, Any]]) -> dict[str, Any]:
    local = [item for item in items if str(item["status"]).startswith("PASS")]
    accepted_external = [item for item in items if item["status"] == ACCEPTED_EXTERNAL_STATUS]
    open_external = [item for item in items if item["status"] == OPEN_EXTERNAL_STATUS]
    excluded = [item for item in items if item["status"] == "EXCLUDED_BY_OBJECTIVE"]
    all_local_evidence_present = all(
        evidence["exists"] and (evidence["status"] in {NOT_APPLICABLE, "PASS"})
        for item in local
        for evidence in item["evidence"]
    )
    external_open_ids = {
        item.get("external_id")
        for item in open_external
        if item.get("external_state", {}).get("current_blocker") is True
    }
    accepted_external_ids = {
        item.get("external_id")
        for item in accepted_external
        if item.get("external_state", {}).get("completion_evidence_valid") is True
    }
    known_external_ids = {item.get("external_id") for item in open_external + accepted_external}
    closure_status = (
        "PASS_LOCAL_SCOPE_EXTERNAL_OPEN"
        if all_local_evidence_present and known_external_ids == EXTERNAL_IDS and accepted_external_ids | external_open_ids == EXTERNAL_IDS
        else "FAIL"
    )
    return {
        "closure_status": closure_status,
        "local_item_count": len(local),
        "local_items_evidence_present": all_local_evidence_present,
        "accepted_external_item_count": len(accepted_external),
        "accepted_external_ids": sorted(accepted_external_ids),
        "open_external_item_count": len(open_external),
        "open_external_ids": sorted(external_open_ids),
        "excluded_item_count": len(excluded),
        "objective_exclusions": ["real_malware_validation"],
    }


def markdown_report(audit: dict[str, Any]) -> str:
    lines = [
        "# CCF-A Review Closure Audit",
        "",
        f"Status: `{audit['status']}`",
        f"Closure status: `{audit['closure_status']}`",
        "",
        "This audit maps the 2026-06 review requirements onto the current Genesys2/CVA6 evidence package. It excludes real malware validation by objective, and it does not convert external readiness contracts into completion evidence.",
        "",
        "## Summary",
        "",
        f"- Local/current items closed: {audit['summary']['local_item_count']}",
        f"- Non-real external items accepted: {audit['summary'].get('accepted_external_item_count', 0)}",
        f"- Non-real external items still blocked: {audit['summary']['open_external_item_count']}",
        f"- Objective exclusions: {', '.join(audit['summary']['objective_exclusions'])}",
        "",
        "## Requirement Rows",
        "",
        "| Requirement | Review section | Status | Evidence | Checker |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in audit["items"]:
        evidence = ", ".join(f"`{row['id']}`" for row in item["evidence"])
        checkers = "<br>".join(f"`{command}`" for command in item["checker_commands"])
        lines.append(f"| `{item['id']}` | {item['review_section']} | `{item['status']}` | {evidence} | {checkers} |")
    lines.extend(
        [
            "",
            "## Remaining Non-Real External Items",
            "",
            "| External id | Intake status | Expected summary |",
            "| --- | --- | --- |",
        ]
    )
    for item in audit["items"]:
        if item.get("status") != "OPEN_EXTERNAL_ARTIFACTS_REQUIRED":
            continue
        state = item.get("external_state", {})
        lines.append(
            f"| `{item['external_id']}` | `{state.get('completion_status')}` | `{state.get('external_summary_path')}` |"
        )
    lines.extend(
        [
            "",
            "## Non-Claims",
            "",
            "- Real malware validation is excluded from the current objective.",
            "- External items are closed only when their live intake record is EXTERNAL_SUMMARY_ACCEPTED; invalid external summaries remain blockers.",
            "- Local Linux benign controls, source-equivalent sidecars, bounded hardware prefixes, and BRAM/JTAG marker-window traces are not substitutes for the open external evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def package_audit(current_root: Path) -> dict[str, Any]:
    external = external_state(current_root)
    items = [item_row(item, external) for item in REVIEW_ITEMS]
    summary = summarize(items, external)
    return {
        "schema": "rvmt.genesys2.review_closure_audit.v1",
        "status": "PASS" if summary["closure_status"] == "PASS_LOCAL_SCOPE_EXTERNAL_OPEN" else "FAIL",
        "closure_status": summary["closure_status"],
        "scope": "Digilent Genesys2 + CVA6 CCF-A review closure audit",
        "source_review_reference": "D:/Download/rv-maltrace-ccfa-genesys2-cva6-review.md",
        "canonical_evaluation_root": repo_rel(ROOT / current_root),
        "summary": summary,
        "items": items,
        "claim_boundary": {
            "real_malware_validation_claimed": False,
            "real_malware_validation_excluded_by_objective": True,
            "external_readiness_substituted_for_completion": False,
            "local_linux_benign_substituted_for_board_benign": False,
            "bounded_prefix_substituted_for_full_strings": False,
            "toolchain_probe_substituted_for_board_native_dwarf": False,
        },
        "validation_commands": [
            "uv run python tools/package_genesys2_review_closure_audit.py",
            "uv run python tools/check_genesys2_review_closure_audit.py --root .",
            "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
            "uv run python tools/check_genesys2_external_operator_packet.py --root .",
            "uv run python tools/check_genesys2_statistical_robustness.py --root .",
            "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
            "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
            "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        old_root = globals()["ROOT"]
        try:
            globals()["ROOT"] = root
            for path_value in EVIDENCE_FILES.values():
                path = root / path_value
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.suffix == ".json":
                    write_json(path, {"schema": "fixture", "status": "PASS"})
                else:
                    path.write_text("fixture\n", encoding="utf-8")
            intake_path = root / EVIDENCE_FILES["external_closure_intake"]
            write_json(
                intake_path,
                {
                    "schema": "rvmt.genesys2.external_closure_intake.v1",
                    "status": "PASS",
                    "records": [
                        {
                            "id": external_id,
                            "completion_status": "OPEN_NO_EXTERNAL_SUMMARY",
                            "current_blocker": True,
                            "external_summary_path": f"external/{external_id}.json",
                            "external_summary_exists": False,
                            "completion_evidence_valid": False,
                        }
                        for external_id in sorted(EXTERNAL_IDS)
                    ],
                },
            )
            audit = package_audit(DEFAULT_CURRENT_ROOT)
        finally:
            globals()["ROOT"] = old_root
    if audit["status"] != "PASS" or audit["closure_status"] != "PASS_LOCAL_SCOPE_EXTERNAL_OPEN":
        print("[FAIL] review closure audit fixture did not pass", file=sys.stderr)
        return 1
    if set(audit["summary"]["open_external_ids"]) != EXTERNAL_IDS:
        print("[FAIL] review closure audit fixture external ids mismatch", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 review closure audit packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package the Genesys2/CVA6 CCF-A review closure audit.")
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        audit = package_audit(args.current_root)
        write_json(args.out_json, audit)
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(markdown_report(audit), encoding="utf-8", newline="\n")
    except Exception as exc:
        print(f"package_genesys2_review_closure_audit: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{audit['closure_status']}] wrote review closure audit to {args.out_json} and {args.out_md}")
    return 0 if audit["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
