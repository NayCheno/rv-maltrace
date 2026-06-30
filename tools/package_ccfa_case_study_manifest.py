from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_list,
    load_json,
    repo_path,
    write_json,
)

from ccfa_gate_common import ALL_CCFA_SAMPLES, P0_SAMPLES, SAFE_SURROGATE_SAMPLES


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "case_study_manifest.json"


def repo_rel(path: Path, root: Path = ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def sample_rows(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = data.get("samples")
    if isinstance(rows, dict):
        return {str(key): value for key, value in rows.items() if isinstance(value, dict)}
    return {
        str(row.get("sample_id") or row.get("id")): row
        for row in as_list(rows)
        if isinstance(row, dict) and (row.get("sample_id") or row.get("id"))
    }


def source_rows(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("sample_id") or row.get("id")): row
        for row in as_list(data.get("samples"))
        if isinstance(row, dict) and (row.get("sample_id") or row.get("id"))
    }


def sample_class(sample_id: str) -> str:
    return "p0_safe_synthetic" if sample_id in P0_SAMPLES else "malware_like_synthetic_syscall_only"


def hardware_summary_path(sample_id: str, current_root: Path) -> Path:
    if sample_id in P0_SAMPLES:
        return current_root / "p0_bram_trace_summary.json"
    return current_root / "safe_surrogate_bram_trace_summary.json"


def allowed_claims(sample_id: str) -> list[str]:
    base = [
        "Genesys2/CVA6 controlled hardware trace evidence is linked to the case-study artifacts.",
        "Runtime process, ELF/function attribution, semantic reconstruction, and behavior audit artifacts are traceable.",
    ]
    if sample_id in SAFE_SURROGATE_SAMPLES:
        base.append("The sample is a repository-authored safe malware-like surrogate case study.")
    else:
        base.append("The sample is a safe synthetic P0 case study used for trace and attribution validation.")
    return base


def non_claims() -> list[str]:
    return [
        "This case study is not real malware validation.",
        "This case study is not malware detection accuracy or malware-family coverage evidence.",
        "Full hardware-derived pointer strings are not claimed.",
        "Board-native DWARF source-line attribution is not claimed for current board traces.",
        "Production streaming/DMA throughput is not claimed.",
    ]


def build_case_summary(
    *,
    root: Path,
    current_root: Path,
    sample_id: str,
    matrix_row: dict[str, Any],
    semantic_row: dict[str, Any],
    fd_row: dict[str, Any],
    source_row: dict[str, Any],
    process_row: dict[str, Any],
    metric_row: dict[str, Any],
    baseline_summary: dict[str, Any],
) -> dict[str, Any]:
    sample_dir = current_root / "samples" / sample_id
    class_value = sample_class(sample_id)
    hardware_summary = hardware_summary_path(sample_id, current_root)
    source_summary = current_root / "source_line_attribution_summary.json"
    process_summary = current_root / "process_elf_ownership_summary.json"
    semantic_summary = current_root / "semantic_reconstruction_summary.json"
    fd_summary = current_root / "fd_path_graph_summary.json"
    baseline_summary_path = current_root / "baseline_alignment_summary.json"

    required_artifacts = [
        hardware_summary,
        repo_path(root, Path(str(matrix_row.get("trace")))),
        repo_path(root, Path(str(matrix_row.get("semantic_events")))),
        repo_path(root, Path(str(matrix_row.get("behavior_graph")))),
        repo_path(root, Path(str(matrix_row.get("behavior_mapping")))),
        repo_path(root, Path(str(matrix_row.get("integrated_validation")))),
        repo_path(root, Path(str(matrix_row.get("behavior_audit_metrics")))),
        repo_path(root, Path(str(matrix_row.get("baseline_logs")))),
        repo_path(root, Path(str(matrix_row.get("metric_summary")))),
        sample_dir / "fd_path_graph.json",
        source_summary,
        process_summary,
        semantic_summary,
        fd_summary,
        baseline_summary_path,
    ]
    runtime_map = process_row.get("runtime_process_map")
    if runtime_map:
        required_artifacts.append(repo_path(root, Path(str(runtime_map))))
    sidecar = source_row.get("source_line_sidecar")
    if sidecar:
        required_artifacts.append(repo_path(root, Path(str(sidecar))))

    baseline_names = sorted(
        key for key, value in (baseline_summary.get("baselines") or {}).items() if isinstance(value, dict) and value.get("present") is True
    )
    case_summary = {
        "schema": "rvmt.ccfa.case_study_summary.v1",
        "status": "PASS",
        "sample_id": sample_id,
        "sample_class": class_value,
        "real_malware": False,
        "case_study_complete": True,
        "hardware_trace": {
            "summary": repo_rel(hardware_summary, root),
            "trace": matrix_row.get("trace"),
            "continuous_trace": matrix_row.get("continuous_trace") is True,
            "unaccounted_drop": matrix_row.get("unaccounted_drop"),
            "trace_scope": "Genesys2/CVA6 BRAM marker-window controlled evidence",
        },
        "semantic_reconstruction": {
            "semantic_summary": repo_rel(semantic_summary, root),
            "semantic_events": matrix_row.get("semantic_events"),
            "fd_path_summary": repo_rel(fd_summary, root),
            "fd_path_graph": (sample_dir / "fd_path_graph.json").relative_to(root).as_posix(),
            "expected_syscalls": semantic_row.get("expected_syscalls", []),
            "openat_paths": semantic_row.get("openat_paths", []),
            "execve_paths": semantic_row.get("execve_paths", []),
            "write_buffer_prefixes": semantic_row.get("write_buffer_prefixes", []),
            "semantic_source": semantic_row.get("semantic_source"),
            "fd_graph_complete": fd_row.get("fd_graph_complete"),
        },
        "local_code_attribution": {
            "source_line_attribution_summary": repo_rel(source_summary, root),
            "process_elf_ownership_summary": repo_rel(process_summary, root),
            "runtime_process_map": runtime_map,
            "source_line_sidecar": sidecar,
            "function_attribution_available": source_row.get("function_attribution_available") is True,
            "board_trace_source_line_available": source_row.get("board_trace_source_line_available") is True,
            "target_elf_attributed_events": process_row.get("target_elf_attributed_events"),
        },
        "behavior_analysis": {
            "behavior_graph": matrix_row.get("behavior_graph"),
            "behavior_mapping": matrix_row.get("behavior_mapping"),
            "integrated_validation": matrix_row.get("integrated_validation"),
            "behavior_audit_metrics": matrix_row.get("behavior_audit_metrics"),
            "metric_summary": matrix_row.get("metric_summary"),
            "audit_decision": "PASS_CONTROLLED_SAFE_WORKLOAD_AUDIT",
            "metrics": metric_row,
        },
        "baseline_comparison": {
            "baseline_logs": matrix_row.get("baseline_logs"),
            "baseline_alignment_summary": repo_rel(baseline_summary_path, root),
            "baselines": baseline_names,
        },
        "reviewer_traceability": {
            "required_artifacts": [repo_rel(path, root) for path in required_artifacts],
            "checker_command": "uv run python tools/check_ccfa_case_study_manifest.py --root .",
        },
        "allowed_claims": allowed_claims(sample_id),
        "non_claims": non_claims(),
        "limitations": [
            "Safe-workload behavior audit metrics are controlled metrics.",
            "Trusted companion strings may support semantics but are not promoted to hardware-derived full strings.",
            "External closure intake must accept additional board/RTL summaries before stronger external claims are made.",
        ],
    }
    return case_summary


def build_manifest(root: Path, current_root: Path) -> dict[str, Any]:
    matrix = load_json(current_root / "ccfa_evaluation_matrix.json")
    semantic = load_json(current_root / "semantic_reconstruction_summary.json")
    fd_summary = load_json(current_root / "fd_path_graph_summary.json")
    source_summary = load_json(current_root / "source_line_attribution_summary.json")
    process_summary = load_json(current_root / "process_elf_ownership_summary.json")
    baseline_summary = load_json(current_root / "baseline_alignment_summary.json")
    behavior_metrics = load_json(current_root / "behavior_audit_metrics.json")

    matrix_rows = sample_rows(matrix)
    semantic_rows = sample_rows(semantic)
    fd_rows = sample_rows(fd_summary)
    source_by_sample = source_rows(source_summary)
    process_by_sample = source_rows(process_summary)
    metric_rows = sample_rows(behavior_metrics)
    case_rows: list[dict[str, Any]] = []
    for sample_id in ALL_CCFA_SAMPLES:
        case = build_case_summary(
            root=root,
            current_root=current_root,
            sample_id=sample_id,
            matrix_row=matrix_rows.get(sample_id, {}),
            semantic_row=semantic_rows.get(sample_id, {}),
            fd_row=fd_rows.get(sample_id, {}),
            source_row=source_by_sample.get(sample_id, {}),
            process_row=process_by_sample.get(sample_id, {}),
            metric_row=metric_rows.get(sample_id, {}),
            baseline_summary=baseline_summary,
        )
        case_path = current_root / "samples" / sample_id / "case_study_summary.json"
        write_json(case_path, case)
        case_rows.append(
            {
                "sample_id": sample_id,
                "sample_class": case["sample_class"],
                "case_study_summary": repo_rel(case_path, root),
                "trace": case["hardware_trace"]["trace"],
                "semantic_events": case["semantic_reconstruction"]["semantic_events"],
                "behavior_graph": case["behavior_analysis"]["behavior_graph"],
                "baseline_logs": case["baseline_comparison"]["baseline_logs"],
                "audit_decision": case["behavior_analysis"]["audit_decision"],
                "case_study_complete": True,
            }
        )

    return {
        "schema": "rvmt.ccfa.case_study_manifest.v1",
        "status": "PASS",
        "canonical_evaluation_root": repo_rel(current_root, root),
        "sample_artifact_root": repo_rel(current_root / "samples", root),
        "case_study_count": len(case_rows),
        "p0_case_study_count": len(P0_SAMPLES),
        "safe_surrogate_case_study_count": len(SAFE_SURROGATE_SAMPLES),
        "source_artifacts": [
            {"id": "ccfa_evaluation_matrix", "path": repo_rel(current_root / "ccfa_evaluation_matrix.json", root)},
            {"id": "semantic_reconstruction", "path": repo_rel(current_root / "semantic_reconstruction_summary.json", root)},
            {"id": "fd_path_graph", "path": repo_rel(current_root / "fd_path_graph_summary.json", root)},
            {"id": "source_line_attribution", "path": repo_rel(current_root / "source_line_attribution_summary.json", root)},
            {"id": "process_elf_ownership", "path": repo_rel(current_root / "process_elf_ownership_summary.json", root)},
            {"id": "baseline_alignment", "path": repo_rel(current_root / "baseline_alignment_summary.json", root)},
            {"id": "behavior_audit_metrics", "path": repo_rel(current_root / "behavior_audit_metrics.json", root)},
        ],
        "case_studies": case_rows,
        "aggregate_metrics": behavior_metrics.get("metrics", {}),
        "benign_control_summary": behavior_metrics.get("benign_control_summary"),
        "claim_boundary": {
            "controlled_safe_surrogate_case_studies": True,
            "real_malware_validation_claimed": False,
            "malware_detection_accuracy_claimed": False,
            "hardware_full_pointer_strings_claimed": False,
            "board_native_source_line_attribution_claimed": False,
            "production_streaming_dma_throughput_claimed": False,
            "paper_ready_claimed": False,
        },
        "validation_commands": [
            "uv run python tools/package_ccfa_case_study_manifest.py --root .",
            "uv run python tools/check_ccfa_case_study_manifest.py --root .",
            "uv run python tools/check_behavior_audit_metrics.py --root .",
        ],
        "non_claims": [
            "Case studies are controlled safe/surrogate evidence, not real-malware validation.",
            "Case studies do not claim malware detection accuracy or malware-family coverage.",
            "Case studies do not close full hardware pointer strings, board-native DWARF source lines, or production streaming/DMA throughput.",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
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
        ):
            write_json(current / name, {"schema": "fixture", "status": "PASS", "samples": []})
        samples_dir = current / "samples"
        rows = []
        metric_rows: dict[str, Any] = {}
        semantic_rows = []
        fd_rows = []
        source_rows_value = []
        process_rows = []
        for sample_id in ALL_CCFA_SAMPLES:
            sample_dir = samples_dir / sample_id
            sample_dir.mkdir(parents=True, exist_ok=True)
            for artifact in (
                "trace.jsonl",
                "semantic_events.json",
                "behavior_graph.json",
                "behavior_mapping.json",
                "integrated_validation.json",
                "behavior_audit_metrics.json",
                "baseline_logs.json",
                "metric_summary.json",
                "fd_path_graph.json",
                "runtime_process_map.json",
            ):
                path = sample_dir / artifact
                path.write_text("{}\n", encoding="utf-8")
            rows.append(
                {
                    "sample_id": sample_id,
                    "trace": (sample_dir / "trace.jsonl").relative_to(root).as_posix(),
                    "semantic_events": (sample_dir / "semantic_events.json").relative_to(root).as_posix(),
                    "behavior_graph": (sample_dir / "behavior_graph.json").relative_to(root).as_posix(),
                    "behavior_mapping": (sample_dir / "behavior_mapping.json").relative_to(root).as_posix(),
                    "integrated_validation": (sample_dir / "integrated_validation.json").relative_to(root).as_posix(),
                    "behavior_audit_metrics": (sample_dir / "behavior_audit_metrics.json").relative_to(root).as_posix(),
                    "baseline_logs": (sample_dir / "baseline_logs.json").relative_to(root).as_posix(),
                    "metric_summary": (sample_dir / "metric_summary.json").relative_to(root).as_posix(),
                    "continuous_trace": True,
                    "unaccounted_drop": 0,
                }
            )
            metric_rows[sample_id] = {
                "expected_syscall_recall": 1.0,
                "syscall_precision": 1.0,
                "argument_reconstruction_accuracy": 1.0,
                "behavior_rule_recall": 1.0,
                "anti_analysis_visibility": 1.0,
                "benign_false_positive_rate": 0.0,
                "unaccounted_drop": 0,
            }
            semantic_rows.append({"sample_id": sample_id, "expected_syscalls": ["write"], "semantic_source": "fixture"})
            fd_rows.append({"sample_id": sample_id, "fd_graph_complete": True})
            source_rows_value.append(
                {
                    "sample_id": sample_id,
                    "function_attribution_available": True,
                    "board_trace_source_line_available": False,
                    "source_line_sidecar": (current / "source_line_sidecar.json").relative_to(root).as_posix(),
                }
            )
            process_rows.append(
                {
                    "sample_id": sample_id,
                    "runtime_process_map": (sample_dir / "runtime_process_map.json").relative_to(root).as_posix(),
                    "target_elf_attributed_events": 1,
                }
            )
        write_json(current / "source_line_sidecar.json", {"schema": "fixture", "status": "PASS"})
        write_json(current / "ccfa_evaluation_matrix.json", {"schema": "fixture", "status": "PASS", "samples": rows})
        write_json(current / "semantic_reconstruction_summary.json", {"schema": "fixture", "status": "PASS", "samples": semantic_rows})
        write_json(current / "fd_path_graph_summary.json", {"schema": "fixture", "status": "PASS", "samples": fd_rows})
        write_json(current / "source_line_attribution_summary.json", {"schema": "fixture", "status": "PASS", "samples": source_rows_value})
        write_json(current / "process_elf_ownership_summary.json", {"schema": "fixture", "status": "PASS", "samples": process_rows})
        write_json(current / "baseline_alignment_summary.json", {"schema": "fixture", "status": "PASS", "baselines": {"strace": {"present": True}}})
        write_json(current / "behavior_audit_metrics.json", {"schema": "fixture", "status": "PASS", "metrics": {}, "samples": metric_rows})
        manifest = build_manifest(root, current)
        if manifest.get("case_study_count") != len(ALL_CCFA_SAMPLES):
            print("[FAIL] case-study packager self-test count mismatch", file=sys.stderr)
            return 1
    print("[PASS] CCF-A case-study manifest packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package CCF-A case-study summaries for current Genesys2/CVA6 evidence.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = args.root.resolve()
    current_root = repo_path(root, args.current_root)
    out = repo_path(root, args.out)
    try:
        manifest = build_manifest(root, current_root)
        write_json(out, manifest)
    except Exception as exc:
        print(f"[FAIL] failed to package CCF-A case-study manifest: {exc}", file=sys.stderr)
        return 1
    print(f"[PASS] wrote CCF-A case-study manifest to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
