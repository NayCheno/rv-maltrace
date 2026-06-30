from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    repo_path,
    require,
    write_json,
)

from ccfa_gate_common import ALL_CCFA_SAMPLES, P0_SAMPLES, SAFE_SURROGATE_SAMPLES


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/case_study_manifest.json")
SUMMARY_SCHEMA = "rvmt.ccfa.case_study_manifest.v1"
CASE_SCHEMA = "rvmt.ccfa.case_study_summary.v1"


def num(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def require_file(errors: list[str], root: Path, value: Any, context: str) -> None:
    require(errors, bool(value), f"{context}: path missing")
    if not value:
        return
    path = repo_path(root, value)
    require(errors, path.is_file(), f"{context}: file missing: {value}")


def expected_class(sample_id: str) -> str:
    return "p0_safe_synthetic" if sample_id in P0_SAMPLES else "malware_like_synthetic_syscall_only"


def check_case_summary(errors: list[str], root: Path, sample_id: str, summary_path: str) -> None:
    path = repo_path(root, summary_path)
    require(errors, path.is_file(), f"{sample_id}: case summary missing: {summary_path}")
    if not path.is_file():
        return
    try:
        case = load_json(path)
    except Exception as exc:
        errors.append(f"{sample_id}: case summary invalid JSON: {exc}")
        return
    require(errors, case.get("schema") == CASE_SCHEMA, f"{sample_id}: case summary schema mismatch")
    require(errors, case.get("status") == "PASS", f"{sample_id}: case summary status must be PASS")
    require(errors, case.get("sample_id") == sample_id, f"{sample_id}: sample_id mismatch")
    require(errors, case.get("sample_class") == expected_class(sample_id), f"{sample_id}: sample_class mismatch")
    require(errors, case.get("real_malware") is False, f"{sample_id}: real_malware must be false")
    require(errors, case.get("case_study_complete") is True, f"{sample_id}: case_study_complete must be true")

    hardware = as_dict(case.get("hardware_trace"))
    require_file(errors, root, hardware.get("summary"), f"{sample_id}.hardware_trace.summary")
    require_file(errors, root, hardware.get("trace"), f"{sample_id}.hardware_trace.trace")
    require(errors, hardware.get("continuous_trace") is True, f"{sample_id}: continuous_trace must be true")
    require(errors, num(hardware.get("unaccounted_drop")) == 0, f"{sample_id}: unaccounted_drop must be 0")

    semantic = as_dict(case.get("semantic_reconstruction"))
    require_file(errors, root, semantic.get("semantic_summary"), f"{sample_id}.semantic_summary")
    require_file(errors, root, semantic.get("semantic_events"), f"{sample_id}.semantic_events")
    require_file(errors, root, semantic.get("fd_path_summary"), f"{sample_id}.fd_path_summary")
    require_file(errors, root, semantic.get("fd_path_graph"), f"{sample_id}.fd_path_graph")
    require(errors, bool(as_list(semantic.get("expected_syscalls"))), f"{sample_id}: expected_syscalls missing")
    require(errors, semantic.get("fd_graph_complete") is True, f"{sample_id}: fd graph must be complete")

    code = as_dict(case.get("local_code_attribution"))
    require_file(errors, root, code.get("source_line_attribution_summary"), f"{sample_id}.source_line_attribution_summary")
    require_file(errors, root, code.get("process_elf_ownership_summary"), f"{sample_id}.process_elf_ownership_summary")
    require_file(errors, root, code.get("runtime_process_map"), f"{sample_id}.runtime_process_map")
    require_file(errors, root, code.get("source_line_sidecar"), f"{sample_id}.source_line_sidecar")
    require(errors, code.get("function_attribution_available") is True, f"{sample_id}: function attribution missing")
    require(errors, code.get("board_trace_source_line_available") is False, f"{sample_id}: current case must not claim board-native source-line attribution")
    require(errors, num(code.get("target_elf_attributed_events")) > 0, f"{sample_id}: target ELF events missing")

    behavior = as_dict(case.get("behavior_analysis"))
    require_file(errors, root, behavior.get("behavior_graph"), f"{sample_id}.behavior_graph")
    require_file(errors, root, behavior.get("behavior_mapping"), f"{sample_id}.behavior_mapping")
    require_file(errors, root, behavior.get("integrated_validation"), f"{sample_id}.integrated_validation")
    require_file(errors, root, behavior.get("behavior_audit_metrics"), f"{sample_id}.behavior_audit_metrics")
    require_file(errors, root, behavior.get("metric_summary"), f"{sample_id}.metric_summary")
    require(errors, behavior.get("audit_decision") == "PASS_CONTROLLED_SAFE_WORKLOAD_AUDIT", f"{sample_id}: audit decision mismatch")
    metrics = as_dict(behavior.get("metrics"))
    for key, threshold in (
        ("expected_syscall_recall", 0.95),
        ("syscall_precision", 0.95),
        ("argument_reconstruction_accuracy", 0.95),
        ("behavior_rule_recall", 0.90),
    ):
        require(errors, num(metrics.get(key)) >= threshold, f"{sample_id}: {key} below threshold")
    require(errors, num(metrics.get("unaccounted_drop")) == 0, f"{sample_id}: behavior unaccounted_drop must be 0")

    baseline = as_dict(case.get("baseline_comparison"))
    require_file(errors, root, baseline.get("baseline_logs"), f"{sample_id}.baseline_logs")
    require_file(errors, root, baseline.get("baseline_alignment_summary"), f"{sample_id}.baseline_alignment_summary")
    require(errors, {"strace", "qemu_strace"} <= {str(item) for item in as_list(baseline.get("baselines"))}, f"{sample_id}: baseline list incomplete")

    traceability = as_dict(case.get("reviewer_traceability"))
    required = as_list(traceability.get("required_artifacts"))
    require(errors, len(required) >= 12, f"{sample_id}: required_artifacts under-specified")
    for index, artifact in enumerate(required, start=1):
        require_file(errors, root, artifact, f"{sample_id}.required_artifact.{index}")
    require(
        errors,
        traceability.get("checker_command") == "uv run python tools/check_ccfa_case_study_manifest.py --root .",
        f"{sample_id}: checker command mismatch",
    )

    allowed = " ".join(str(item).lower() for item in as_list(case.get("allowed_claims")))
    if sample_id in SAFE_SURROGATE_SAMPLES:
        require(errors, "malware-like surrogate" in allowed, f"{sample_id}: safe surrogate allowed claim missing")
    else:
        require(errors, "safe synthetic p0" in allowed, f"{sample_id}: P0 allowed claim missing")
    non_claims = " ".join(str(item).lower() for item in as_list(case.get("non_claims")))
    require(errors, "not real malware validation" in non_claims, f"{sample_id}: real-malware non-claim missing")
    require(errors, "not malware detection accuracy" in non_claims, f"{sample_id}: detection-accuracy non-claim missing")
    require(errors, "full hardware-derived pointer strings are not claimed" in non_claims, f"{sample_id}: full-string non-claim missing")
    require(errors, "production streaming/dma throughput is not claimed" in non_claims, f"{sample_id}: streaming/DMA non-claim missing")


def check_manifest(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == SUMMARY_SCHEMA, f"schema must be {SUMMARY_SCHEMA}")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(errors, int(data.get("case_study_count") or 0) == len(ALL_CCFA_SAMPLES), "case study count mismatch")
    require(errors, int(data.get("p0_case_study_count") or 0) == len(P0_SAMPLES), "P0 case study count mismatch")
    require(errors, int(data.get("safe_surrogate_case_study_count") or 0) == len(SAFE_SURROGATE_SAMPLES), "safe surrogate case study count mismatch")
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("controlled_safe_surrogate_case_studies") is True, "controlled case-study boundary missing")
    for key in (
        "real_malware_validation_claimed",
        "malware_detection_accuracy_claimed",
        "hardware_full_pointer_strings_claimed",
        "board_native_source_line_attribution_claimed",
        "production_streaming_dma_throughput_claimed",
        "paper_ready_claimed",
    ):
        require(errors, boundary.get(key) is False, f"case-study manifest must not claim {key}")
    for source in as_list(data.get("source_artifacts")):
        if not isinstance(source, dict):
            errors.append("source artifact row must be object")
            continue
        require_file(errors, root, source.get("path"), f"source_artifact.{source.get('id')}")
    studies = {
        str(row.get("sample_id")): row
        for row in as_list(data.get("case_studies"))
        if isinstance(row, dict) and row.get("sample_id")
    }
    missing = [sample for sample in ALL_CCFA_SAMPLES if sample not in studies]
    extra = [sample for sample in studies if sample not in ALL_CCFA_SAMPLES]
    require(errors, not missing, f"missing case studies: {', '.join(missing)}")
    require(errors, not extra, f"unexpected case studies: {', '.join(extra)}")
    for sample_id in ALL_CCFA_SAMPLES:
        row = studies.get(sample_id, {})
        require(errors, row.get("sample_class") == expected_class(sample_id), f"{sample_id}: manifest sample_class mismatch")
        require(errors, row.get("case_study_complete") is True, f"{sample_id}: manifest case_study_complete must be true")
        for key in ("case_study_summary", "trace", "semantic_events", "behavior_graph", "baseline_logs"):
            require_file(errors, root, row.get(key), f"{sample_id}.manifest.{key}")
        require(errors, row.get("audit_decision") == "PASS_CONTROLLED_SAFE_WORKLOAD_AUDIT", f"{sample_id}: manifest audit decision mismatch")
        if row.get("case_study_summary"):
            check_case_summary(errors, root, sample_id, str(row.get("case_study_summary")))
    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/check_ccfa_case_study_manifest.py --root ." in commands, "case-study checker command missing")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not real-malware validation" in non_claims or "not real malware validation" in non_claims, "manifest real-malware non-claim missing")
    require(errors, "do not claim malware detection accuracy" in non_claims, "manifest detection-accuracy non-claim missing")
    return errors


def fixture_manifest(root: Path) -> dict[str, Any]:
    current = root / "results/evaluation/genesys2-cva6/current"
    samples = current / "samples"
    source_paths = []
    for name in (
        "ccfa_evaluation_matrix.json",
        "semantic_reconstruction_summary.json",
        "fd_path_graph_summary.json",
        "source_line_attribution_summary.json",
        "process_elf_ownership_summary.json",
        "baseline_alignment_summary.json",
        "behavior_audit_metrics.json",
        "p0_bram_trace_summary.json",
        "safe_surrogate_bram_trace_summary.json",
        "source_line_sidecar.json",
    ):
        write_json(current / name, {"schema": "fixture", "status": "PASS"})
        source_paths.append({"id": name.removesuffix(".json"), "path": f"results/evaluation/genesys2-cva6/current/{name}"})
    case_rows = []
    for sample_id in ALL_CCFA_SAMPLES:
        sample_dir = samples / sample_id
        sample_dir.mkdir(parents=True, exist_ok=True)
        for name in (
            "trace.jsonl",
            "semantic_events.json",
            "fd_path_graph.json",
            "runtime_process_map.json",
            "behavior_graph.json",
            "behavior_mapping.json",
            "integrated_validation.json",
            "behavior_audit_metrics.json",
            "metric_summary.json",
            "baseline_logs.json",
        ):
            path = sample_dir / name
            path.write_text("{}\n", encoding="utf-8")
        summary_path = f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/case_study_summary.json"
        case = {
            "schema": CASE_SCHEMA,
            "status": "PASS",
            "sample_id": sample_id,
            "sample_class": expected_class(sample_id),
            "real_malware": False,
            "case_study_complete": True,
            "hardware_trace": {
                "summary": "results/evaluation/genesys2-cva6/current/p0_bram_trace_summary.json" if sample_id in P0_SAMPLES else "results/evaluation/genesys2-cva6/current/safe_surrogate_bram_trace_summary.json",
                "trace": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/trace.jsonl",
                "continuous_trace": True,
                "unaccounted_drop": 0,
            },
            "semantic_reconstruction": {
                "semantic_summary": "results/evaluation/genesys2-cva6/current/semantic_reconstruction_summary.json",
                "semantic_events": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/semantic_events.json",
                "fd_path_summary": "results/evaluation/genesys2-cva6/current/fd_path_graph_summary.json",
                "fd_path_graph": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/fd_path_graph.json",
                "expected_syscalls": ["write"],
                "fd_graph_complete": True,
            },
            "local_code_attribution": {
                "source_line_attribution_summary": "results/evaluation/genesys2-cva6/current/source_line_attribution_summary.json",
                "process_elf_ownership_summary": "results/evaluation/genesys2-cva6/current/process_elf_ownership_summary.json",
                "runtime_process_map": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/runtime_process_map.json",
                "source_line_sidecar": "results/evaluation/genesys2-cva6/current/source_line_sidecar.json",
                "function_attribution_available": True,
                "board_trace_source_line_available": False,
                "target_elf_attributed_events": 1,
            },
            "behavior_analysis": {
                "behavior_graph": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/behavior_graph.json",
                "behavior_mapping": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/behavior_mapping.json",
                "integrated_validation": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/integrated_validation.json",
                "behavior_audit_metrics": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/behavior_audit_metrics.json",
                "metric_summary": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/metric_summary.json",
                "audit_decision": "PASS_CONTROLLED_SAFE_WORKLOAD_AUDIT",
                "metrics": {
                    "expected_syscall_recall": 1.0,
                    "syscall_precision": 1.0,
                    "argument_reconstruction_accuracy": 1.0,
                    "behavior_rule_recall": 1.0,
                    "unaccounted_drop": 0,
                },
            },
            "baseline_comparison": {
                "baseline_logs": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/baseline_logs.json",
                "baseline_alignment_summary": "results/evaluation/genesys2-cva6/current/baseline_alignment_summary.json",
                "baselines": ["strace", "qemu_strace"],
            },
            "reviewer_traceability": {
                "required_artifacts": [
                    "results/evaluation/genesys2-cva6/current/p0_bram_trace_summary.json" if sample_id in P0_SAMPLES else "results/evaluation/genesys2-cva6/current/safe_surrogate_bram_trace_summary.json",
                    f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/trace.jsonl",
                    f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/semantic_events.json",
                    f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/fd_path_graph.json",
                    "results/evaluation/genesys2-cva6/current/semantic_reconstruction_summary.json",
                    "results/evaluation/genesys2-cva6/current/fd_path_graph_summary.json",
                    "results/evaluation/genesys2-cva6/current/source_line_attribution_summary.json",
                    "results/evaluation/genesys2-cva6/current/process_elf_ownership_summary.json",
                    f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/runtime_process_map.json",
                    f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/behavior_graph.json",
                    f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/baseline_logs.json",
                    "results/evaluation/genesys2-cva6/current/baseline_alignment_summary.json",
                ],
                "checker_command": "uv run python tools/check_ccfa_case_study_manifest.py --root .",
            },
            "allowed_claims": [
                "The sample is a repository-authored safe malware-like surrogate case study."
                if sample_id in SAFE_SURROGATE_SAMPLES
                else "The sample is a safe synthetic P0 case study used for trace and attribution validation."
            ],
            "non_claims": [
                "This case study is not real malware validation.",
                "This case study is not malware detection accuracy or malware-family coverage evidence.",
                "Full hardware-derived pointer strings are not claimed.",
                "Board-native DWARF source-line attribution is not claimed for current board traces.",
                "Production streaming/DMA throughput is not claimed.",
            ],
        }
        write_json(root / summary_path, case)
        case_rows.append(
            {
                "sample_id": sample_id,
                "sample_class": expected_class(sample_id),
                "case_study_summary": summary_path,
                "trace": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/trace.jsonl",
                "semantic_events": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/semantic_events.json",
                "behavior_graph": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/behavior_graph.json",
                "baseline_logs": f"results/evaluation/genesys2-cva6/current/samples/{sample_id}/baseline_logs.json",
                "audit_decision": "PASS_CONTROLLED_SAFE_WORKLOAD_AUDIT",
                "case_study_complete": True,
            }
        )
    return {
        "schema": SUMMARY_SCHEMA,
        "status": "PASS",
        "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
        "case_study_count": len(ALL_CCFA_SAMPLES),
        "p0_case_study_count": len(P0_SAMPLES),
        "safe_surrogate_case_study_count": len(SAFE_SURROGATE_SAMPLES),
        "claim_boundary": {
            "controlled_safe_surrogate_case_studies": True,
            "real_malware_validation_claimed": False,
            "malware_detection_accuracy_claimed": False,
            "hardware_full_pointer_strings_claimed": False,
            "board_native_source_line_attribution_claimed": False,
            "production_streaming_dma_throughput_claimed": False,
            "paper_ready_claimed": False,
        },
        "source_artifacts": source_paths,
        "case_studies": case_rows,
        "validation_commands": ["uv run python tools/check_ccfa_case_study_manifest.py --root ."],
        "non_claims": [
            "Case studies are controlled safe/surrogate evidence, not real-malware validation.",
            "Case studies do not claim malware detection accuracy or malware-family coverage.",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        good = fixture_manifest(root)
        errors = check_manifest(good, root)
        if errors:
            print("[FAIL] expected fixture to pass:", "; ".join(errors), file=sys.stderr)
            return 1
        bad = json.loads(json.dumps(good))
        first = bad["case_studies"][0]
        case_path = root / first["case_study_summary"]
        case = load_json(case_path)
        case["real_malware"] = True
        write_json(case_path, case)
        errors = check_manifest(bad, root)
        if not any("real_malware must be false" in error for error in errors):
            print("[FAIL] expected real_malware overclaim fixture to fail", file=sys.stderr)
            return 1
        case["real_malware"] = False
        write_json(case_path, case)
        missing_path = root / first["behavior_graph"]
        missing_path.unlink()
        errors = check_manifest(bad, root)
        if not any("behavior_graph" in error and "file missing" in error for error in errors):
            print("[FAIL] expected missing artifact fixture to fail", file=sys.stderr)
            return 1
    print("[PASS] CCF-A case-study manifest checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the current CCF-A case-study manifest.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = args.root.resolve()
    summary_path = repo_path(root, args.summary)
    try:
        data = load_json(summary_path)
    except Exception as exc:
        print(f"[FAIL] {summary_path}: {exc}", file=sys.stderr)
        return 1
    errors = check_manifest(data, root)
    if errors:
        print(f"[FAIL] case-study manifest rejected: {summary_path}", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"[PASS] case-study manifest accepted: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
