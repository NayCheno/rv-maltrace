from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    write_json,
)


DEFAULT_DOC = Path("docs/07-evaluation-evidence/evaluation_plan.md")
DEFAULT_UV_DOC = Path("docs/10-process/uv_workflow.md")

REQUIRED_TEXT = (
    "This document turns `docs/09-planning/next-plan.md` Section 9 and Stage 3 into a checkable",
    "evaluation plan and current-evidence index.",
    "not evaluation evidence by itself.",
    "they do not make the project CCF-A paper-ready.",
    "PASS_CURRENT_GENESYS2_CONTROLLED",
    "PASS_CURRENT_BOUNDED_SEMANTICS",
    "PASS_CURRENT_RUNTIME_SMOKE_OPEN_CYCLE_OVERHEAD",
    "PASS_CONTROLLED_SAFE_SURROGATE",
    "PASS_CURRENT_BRAM_COST_OPEN_STREAMING_DMA",
    "PASS_SAFE_CASE_STUDIES_NON_REAL",
    "PASS_CURRENT_STRACE_ALIGNMENT",
    "OPTIONAL_DEFERRED_EBPF",
    "PASS_CURRENT_QEMU_STRACE_ONLY",
    "PASS_BOUNDED_ARG_MEM_PREFIX_OPEN_FULL_STRINGS",
    "PASS_LOCAL_LINUX_BENIGN_OPEN_BOARD_BENIGN",
    "PASS_CURRENT_REPRO_PACKAGE",
    "## Current Evidence Index",
    "## Remaining External Closure Items",
    "board_native_dwarf_source_lines",
    "full_hardware_pointer_strings",
    "production_streaming_dma_trace_sink",
    "genesys2_board_benign_control",
    "uv run python tools/check_evaluation_plan.py",
)

FORBIDDEN_PATTERNS = (
    re.compile(r"\bTODO(?:\([A-Z_]+\))?\b"),
    re.compile(r"All rows remain TODO", re.IGNORECASE),
    re.compile(r"\bCCF-A\s+(?:ready|accepted|guaranteed)\b", re.IGNORECASE),
    re.compile(r"\breal[- ]malware\s+validation\s+(?:is|has)?\s*(?:been\s+)?(?:complete|completed|passed|validated)\b", re.IGNORECASE),
    re.compile(r"\bfull\s+hardware\s+pointer\s+strings\s+(?:are|have)?\s*(?:been\s+)?(?:complete|completed|claimed|validated)\b", re.IGNORECASE),
    re.compile(r"\bproduction\s+streaming(?:/DMA|\s+DMA)?\s+(?:trace\s+sink|throughput)\s+(?:is|has)?\s*(?:been\s+)?(?:complete|completed|validated)\b", re.IGNORECASE),
)

EXPECTED_RQ_STATUSES = {
    "RQ1": "PASS_CURRENT_GENESYS2_CONTROLLED",
    "RQ2": "PASS_CURRENT_BOUNDED_SEMANTICS_PLUS_ACCEPTED_POINTER_STRINGS",
    "RQ3": "PASS_CURRENT_RUNTIME_SMOKE_OPEN_CYCLE_OVERHEAD",
    "RQ4": "PASS_CONTROLLED_SAFE_SURROGATE",
    "RQ5": "PASS_CURRENT_BRAM_COST_OPEN_STREAMING_DMA",
    "RQ6": "PASS_SAFE_CASE_STUDIES_NON_REAL",
}
EXPECTED_BASELINE_STATUSES = {
    "strace / ptrace": "PASS_CURRENT_STRACE_ALIGNMENT",
    "eBPF-only": "OPTIONAL_DEFERRED_EBPF",
    "QEMU plugin": "PASS_CURRENT_QEMU_STRACE_ONLY",
    "software instrumentation": "PASS_SOURCE_SIDECAR_BASELINE",
    "RV-MalScope event-only": "PASS_CURRENT_EVENT_ONLY",
    "RV-MalScope + pointer snapshot": "PASS_BOUNDED_ARG_MEM_PREFIX_OPEN_FULL_STRINGS",
    "RV-MalScope + kernel helper/eBPF companion": "PASS_TRUSTED_COMPANION_OPTIONAL_EBPF",
}
EXPECTED_DATASET_STATUSES = {
    "Class A": "PASS_CURRENT_P0_CONTROLLED",
    "Class B": "PASS_LOCAL_LINUX_BENIGN_OPEN_BOARD_BENIGN",
    "Class C": "PASS_SAFE_SURROGATE_NON_REAL",
}
EXPECTED_METRICS = (
    "syscall precision / recall",
    "argument reconstruction accuracy",
    "path string reconstruction accuracy",
    "fd graph accuracy",
    "runtime overhead",
    "cycle-level perturbation",
    "trace drop rate",
    "trace bytes per syscall",
    "LUT / FF / BRAM overhead",
    "Fmax degradation",
    "anti-analysis detection outcome",
)
EXPECTED_GATE_STATUSES = {
    "simulation correctness": "PASS_REPOSITORY_SIM",
    "direct-core CVA6 smoke": "PASS_DIRECT_CORE",
    "board baseline": "PASS_GENESYS2_BASELINE",
    "board trace": "PASS_CURRENT_BRAM_MARKER_WINDOW",
    "Linux syscall trace": "PASS_CONTROLLED_TRACE_ALIGNMENT",
    "semantic reconstruction": "PASS_CURRENT_SEMANTIC_SUMMARIES",
    "evasion suite": "PASS_SAFE_SURROGATE_AUDIT",
    "hardware cost": "PASS_CURRENT_RESOURCE_TIMING",
    "ablation study": "PASS_CURRENT_BASELINE_ALIGNMENT",
    "case studies": "PASS_CURRENT_CASE_STUDIES",
    "artifact package": "PASS_CURRENT_REPRO_PACKAGE",
}
EXPECTED_EVIDENCE_ARTIFACTS = {
    "results/evaluation/genesys2-cva6/current/ccfa_evaluation_matrix.json": (
        "rvmt.ccfa_evaluation_matrix.v1",
        "tools/check_ccfa_evaluation_matrix.py",
    ),
    "results/evaluation/genesys2-cva6/current/baseline_alignment_summary.json": (
        "rvmt.baseline_alignment.v1",
        "tools/check_baseline_alignment.py",
    ),
    "results/evaluation/genesys2-cva6/current/behavior_audit_metrics.json": (
        "rvmt.behavior_audit_metrics.v1",
        "tools/check_behavior_audit_metrics.py",
    ),
    "results/evaluation/genesys2-cva6/current/statistical_robustness_summary.json": (
        "rvmt.genesys2.statistical_robustness.v1",
        "tools/check_genesys2_statistical_robustness.py",
    ),
    "results/evaluation/genesys2-cva6/current/streaming_dma_target_summary.json": (
        "rvmt.genesys2.streaming_dma_target.v1",
        "tools/check_genesys2_streaming_dma_target.py",
    ),
    "results/evaluation/genesys2-cva6/current/streaming_dma_readiness_summary.json": (
        "rvmt.genesys2.streaming_dma_readiness.v1",
        "tools/check_genesys2_streaming_dma_readiness.py",
    ),
    "results/evaluation/genesys2-cva6/current/pointer_string_readiness_summary.json": (
        "rvmt.genesys2.pointer_string_readiness.v1",
        "tools/check_genesys2_pointer_string_readiness.py",
    ),
    "results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json": (
        "rvmt.genesys2.hardware_pointer_strings.v1",
        "tools/check_genesys2_hardware_pointer_strings.py",
    ),
    "results/evaluation/genesys2-cva6/current/debug_elf_readiness_summary.json": (
        "rvmt.genesys2.debug_elf_readiness.v1",
        "tools/check_genesys2_debug_elf_readiness.py",
    ),
    "results/evaluation/genesys2-cva6/current/board_benign_readiness_summary.json": (
        "rvmt.genesys2.board_benign_readiness.v1",
        "tools/check_genesys2_board_benign_readiness.py",
    ),
    "results/evaluation/genesys2-cva6/current/case_study_manifest.json": (
        "rvmt.ccfa.case_study_manifest.v1",
        "tools/check_ccfa_case_study_manifest.py",
    ),
    "results/evaluation/genesys2-cva6/current/production_runtime_benchmark.json": (
        "rvmt.genesys2.production_runtime_benchmark.v1",
        "tools/check_ccfa_current_quality.py",
    ),
    "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json": (
        "rvmt.genesys2.reproducibility_manifest.v1",
        "tools/check_genesys2_reproducibility_manifest.py",
    ),
    "results/evaluation/genesys2-cva6/current/artifact_package_manifest.json": (
        "rvmt.genesys2.artifact_package.v1",
        "tools/check_genesys2_artifact_package.py",
    ),
    "results/evaluation/genesys2-cva6/current/external_closure_readiness.json": (
        "rvmt.genesys2.external_closure_readiness.v1",
        "tools/check_genesys2_external_closure_readiness.py",
    ),
    "results/evaluation/genesys2-cva6/current/external_closure_intake.json": (
        "rvmt.genesys2.external_closure_intake.v1",
        "tools/check_genesys2_external_closure_intake.py",
    ),
    "results/evaluation/genesys2-cva6/current/external_closure_plan.json": (
        "rvmt.genesys2.external_closure_plan.v1",
        "tools/check_genesys2_external_closure_plan.py",
    ),
    "results/evaluation/genesys2-cva6/current/external_closure_preflight.json": (
        "rvmt.genesys2.external_closure_preflight.v1",
        "tools/check_genesys2_external_closure_preflight.py",
    ),
    "results/evaluation/genesys2-cva6/current/external_operator_packet.json": (
        "rvmt.genesys2.external_operator_packet.v1",
        "tools/check_genesys2_external_operator_packet.py",
    ),
}
EXPECTED_EXTERNAL_ITEMS = {
    "board_native_dwarf_source_lines": "results/evaluation/genesys2-cva6/current/external_closure/board_native_source_lines_summary.json",
    "full_hardware_pointer_strings": "results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json",
    "production_streaming_dma_trace_sink": "results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json",
    "genesys2_board_benign_control": "results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json",
}
EXPECTED_EXTERNAL_STATUSES = {
    "board_native_dwarf_source_lines": "EXTERNAL_SUMMARY_ACCEPTED",
    "full_hardware_pointer_strings": "EXTERNAL_SUMMARY_ACCEPTED",
    "production_streaming_dma_trace_sink": "EXTERNAL_SUMMARY_PRESENT_INVALID",
    "genesys2_board_benign_control": "EXTERNAL_SUMMARY_ACCEPTED",
}


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def parse_table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip().replace("`", "") for cell in line.strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        rows.append(cells)
    return rows


def section_text(text: str, heading: str) -> str:
    pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.MULTILINE)
    match = pattern.search(text)
    if match is None:
        return ""
    next_match = re.search(r"^##\s+", text[match.end() :], re.MULTILINE)
    end = match.end() + next_match.start() if next_match else len(text)
    return text[match.end() : end]


def section_table_rows(text: str, heading: str, header_first_cell: str) -> list[list[str]]:
    rows = parse_table_rows(section_text(text, heading))
    return [row for row in rows if row and row[0] != header_first_cell]


def is_negated_context(text: str, start: int) -> bool:
    prefix = text[max(0, start - 128) : start].lower()
    return any(marker in prefix for marker in ("do not", "must not", "should not", "never ", "not make")) or bool(
        re.search(r"\bnot(?:\s+\w+){0,8}\s*$", prefix)
    )


def require_exact_statuses(
    errors: list[str],
    path: Path,
    rows: list[list[str]],
    expected: dict[str, str],
    section_name: str,
    status_index: int,
) -> None:
    ids = [row[0] for row in rows]
    if ids != list(expected):
        errors.append(f"{path}: {section_name} rows must be exactly {list(expected)}")
    row_map = {row[0]: row for row in rows}
    for row_id, expected_status in expected.items():
        row = row_map.get(row_id)
        if row is None:
            continue
        if len(row) <= status_index:
            errors.append(f"{path}: {section_name} row {row_id} is malformed")
            continue
        if row[status_index] != expected_status:
            errors.append(f"{path}: {row_id} status must be {expected_status}")


def check_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    normalized = normalized_text(text)
    errors: list[str] = []

    for required in REQUIRED_TEXT:
        if normalized_text(required) not in normalized:
            errors.append(f"{path}: missing required text: {required}")

    for pattern in FORBIDDEN_PATTERNS:
        for match in pattern.finditer(text):
            if is_negated_context(text, match.start()):
                continue
            errors.append(f"{path}: forbidden stale or overclaim wording: {match.group(0)}")
            break

    rq_rows = section_table_rows(text, "Research Questions", "ID")
    baseline_rows = section_table_rows(text, "Baselines", "Baseline")
    dataset_rows = section_table_rows(text, "Datasets", "Class")
    metric_rows = section_table_rows(text, "Metrics", "Metric")
    gate_rows = section_table_rows(text, "Artifact Gates", "Gate")
    evidence_rows = section_table_rows(text, "Current Evidence Index", "Artifact")
    external_rows = section_table_rows(text, "Remaining External Closure Items", "Item")

    require_exact_statuses(errors, path, rq_rows, EXPECTED_RQ_STATUSES, "research question", 3)
    require_exact_statuses(errors, path, baseline_rows, EXPECTED_BASELINE_STATUSES, "baseline", 3)
    require_exact_statuses(errors, path, dataset_rows, EXPECTED_DATASET_STATUSES, "dataset", 3)
    require_exact_statuses(errors, path, gate_rows, EXPECTED_GATE_STATUSES, "artifact gate", 2)

    metric_ids = [row[0] for row in metric_rows]
    if metric_ids != list(EXPECTED_METRICS):
        errors.append(f"{path}: metric rows must be exactly {list(EXPECTED_METRICS)}")

    evidence = {row[0]: row for row in evidence_rows}
    if list(evidence) != list(EXPECTED_EVIDENCE_ARTIFACTS):
        errors.append(f"{path}: evidence index rows must be exactly {list(EXPECTED_EVIDENCE_ARTIFACTS)}")
    for artifact, (_, checker) in EXPECTED_EVIDENCE_ARTIFACTS.items():
        row = evidence.get(artifact)
        if row is None:
            continue
        if len(row) < 3 or checker not in row[2]:
            errors.append(f"{path}: {artifact} must reference checker {checker}")

    external = {row[0]: row for row in external_rows}
    if list(external) != list(EXPECTED_EXTERNAL_ITEMS):
        errors.append(f"{path}: external closure rows must be exactly {list(EXPECTED_EXTERNAL_ITEMS)}")
    for item_id, closure_path in EXPECTED_EXTERNAL_ITEMS.items():
        row = external.get(item_id)
        if row is None:
            continue
        if len(row) < 3:
            errors.append(f"{path}: external closure row {item_id} is malformed")
            continue
        if row[1] != EXPECTED_EXTERNAL_STATUSES[item_id]:
            errors.append(f"{path}: {item_id} must be {EXPECTED_EXTERNAL_STATUSES[item_id]}")
        if row[2] != closure_path:
            errors.append(f"{path}: {item_id} closure gate path mismatch")

    non_goals = section_text(text, "Non-Goals")
    for token in (
        "real malware validation",
        "board-native DWARF source",
        "full hardware pointer strings",
        "production streaming/DMA throughput",
    ):
        if token not in non_goals:
            errors.append(f"{path}: Non-Goals must include {token}")

    return errors


def check_current_artifacts(root: Path) -> list[str]:
    errors: list[str] = []
    for artifact, (schema, _) in EXPECTED_EVIDENCE_ARTIFACTS.items():
        path = root / artifact
        if not path.is_file():
            errors.append(f"{artifact}: missing current evidence artifact")
            continue
        try:
            data = load_json(path)
        except Exception as exc:
            errors.append(f"{artifact}: invalid JSON: {exc}")
            continue
        if data.get("schema") != schema:
            errors.append(f"{artifact}: schema must be {schema}")
        if artifact.endswith("external_closure_intake.json"):
            boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
            truthful_blocked = (
                data.get("status") == "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED"
                and int(data.get("accepted_external_blocker_count") or 0) < len(EXPECTED_EXTERNAL_ITEMS)
                and boundary.get("unvalidated_external_summary_accepted") is False
                and boundary.get("all_non_real_external_blockers_closed") is False
            )
            if data.get("status") != "PASS" and not truthful_blocked:
                errors.append(f"{artifact}: status must be PASS or a truthful external-intake BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED")
        elif data.get("status") != "PASS":
            errors.append(f"{artifact}: status must be PASS")
        boundary = data.get("claim_boundary")
        if isinstance(boundary, dict) and boundary.get("real_malware_validation_claimed") is not False:
            errors.append(f"{artifact}: real_malware_validation_claimed must be false")
    intake = root / "results/evaluation/genesys2-cva6/current/external_closure_intake.json"
    if intake.is_file():
        data = load_json(intake)
        if data.get("closure_status") != "OPEN_EXTERNAL_ARTIFACTS_REQUIRED":
            errors.append("external_closure_intake.json: closure_status must remain OPEN_EXTERNAL_ARTIFACTS_REQUIRED until all external summaries are accepted")
        records = data.get("records")
        if isinstance(records, list):
            statuses = {str(row.get("id")): row.get("completion_status") for row in records if isinstance(row, dict)}
            for item_id in EXPECTED_EXTERNAL_ITEMS:
                if statuses.get(item_id) != EXPECTED_EXTERNAL_STATUSES[item_id]:
                    errors.append(f"external_closure_intake.json: {item_id} must be {EXPECTED_EXTERNAL_STATUSES[item_id]}")
    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token in ("tools/check_evaluation_plan.py", "docs/07-evaluation-evidence/evaluation_plan.md"):
        if token not in text:
            errors.append(f"{path}: missing {token}")
    return errors


def write_artifact_fixtures(root: Path) -> None:
    for artifact, (schema, _) in EXPECTED_EVIDENCE_ARTIFACTS.items():
        payload: dict[str, Any] = {"schema": schema, "status": "PASS", "claim_boundary": {"real_malware_validation_claimed": False}}
        if artifact.endswith("external_closure_intake.json"):
            payload["status"] = "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED"
            payload["closure_status"] = "OPEN_EXTERNAL_ARTIFACTS_REQUIRED"
            payload["accepted_external_blocker_count"] = 3
            payload["open_external_blocker_count"] = 0
            payload["invalid_external_blocker_count"] = 1
            payload["claim_boundary"] = {
                "real_malware_validation_claimed": False,
                "all_non_real_external_blockers_closed": False,
                "unvalidated_external_summary_accepted": False,
            }
            payload["records"] = [
                {"id": item_id, "completion_status": EXPECTED_EXTERNAL_STATUSES[item_id]}
                for item_id in EXPECTED_EXTERNAL_ITEMS
            ]
        write_json(root / artifact, payload)


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        tools = root / "tools"
        doc = root / DEFAULT_DOC
        uv_doc = root / DEFAULT_UV_DOC
        doc.parent.mkdir(parents=True)
        uv_doc.parent.mkdir(parents=True)
        tools.mkdir()
        write_artifact_fixtures(root)

        source_doc = DEFAULT_DOC.read_text(encoding="utf-8")
        doc.write_text(source_doc, encoding="utf-8")
        uv_doc.write_text(
            "uv run python tools/check_evaluation_plan.py\n"
            "docs/07-evaluation-evidence/evaluation_plan.md\n",
            encoding="utf-8",
        )

        if check_doc(doc) or check_uv_doc(uv_doc) or check_current_artifacts(root):
            print("[FAIL] self-test rejected valid evaluation plan fixture", file=sys.stderr)
            return 1

        doc.write_text(source_doc.replace("PASS_CURRENT_GENESYS2_CONTROLLED", "TODO", 1), encoding="utf-8")
        if not any("forbidden stale" in error or "RQ1 status" in error for error in check_doc(doc)):
            print("[FAIL] self-test missed stale TODO status", file=sys.stderr)
            return 1

        doc.write_text(source_doc.replace("EXTERNAL_SUMMARY_PRESENT_INVALID", "EXTERNAL_SUMMARY_ACCEPTED", 1), encoding="utf-8")
        if not any("EXTERNAL_SUMMARY_PRESENT_INVALID" in error for error in check_doc(doc)):
            print("[FAIL] self-test missed external blocker overclosure", file=sys.stderr)
            return 1

        doc.write_text(source_doc.replace("| RQ1 |", "| RQX |", 1), encoding="utf-8")
        if not any("research question rows" in error for error in check_doc(doc)):
            print("[FAIL] self-test missed missing RQ row", file=sys.stderr)
            return 1

        bad_artifact = root / "results/evaluation/genesys2-cva6/current/external_closure_intake.json"
        bad = load_json(bad_artifact)
        bad["closure_status"] = "ALL_NON_REAL_EXTERNAL_SUMMARIES_ACCEPTED"
        write_json(bad_artifact, bad)
        if not any("closure_status" in error for error in check_current_artifacts(root)):
            print("[FAIL] self-test missed premature external closure", file=sys.stderr)
            return 1

        uv_doc.write_text("uv run rvmt tasks:list\n", encoding="utf-8")
        if not check_uv_doc(uv_doc):
            print("[FAIL] self-test missed missing uv workflow reference", file=sys.stderr)
            return 1

    print("[PASS] evaluation plan self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the RV-MalTrace evaluation plan gate.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = args.root.resolve()
    errors: list[str] = []
    try:
        errors.extend(check_doc(args.doc if args.doc.is_absolute() else root / args.doc))
        errors.extend(check_uv_doc(args.uv_doc if args.uv_doc.is_absolute() else root / args.uv_doc))
        errors.extend(check_current_artifacts(root))
    except Exception as exc:
        print(f"check_evaluation_plan: error: {exc}", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    print(f"[PASS] evaluation plan gate: {args.doc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
