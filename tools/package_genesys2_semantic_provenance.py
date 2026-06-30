from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
SUMMARY_NAME = "semantic_reconstruction_summary.json"
PROVENANCE_NAME = "semantic_provenance_summary.json"
PROVENANCE_SCHEMA = "rvmt.semantic_field_provenance.v1"

ALLOWED_PROVENANCE = ("hardware", "exact_elf", "runtime_os_map", "validation_oracle")
ORACLE_HINTS = ("qemu", "strace", "host", "control", "trusted_companion")


def repo_rel(path: Path, root: Path = ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def value_mentions_oracle(value: Any) -> bool:
    if isinstance(value, str):
        lowered = value.lower()
        return any(hint in lowered for hint in ORACLE_HINTS)
    if isinstance(value, list):
        return any(value_mentions_oracle(item) for item in value)
    if isinstance(value, dict):
        return any(value_mentions_oracle(item) for item in value.values())
    return False


def provenance_for_field(field: str, value: Any) -> list[str]:
    field_l = field.lower()
    if field_l == "trace_source":
        return ["hardware"]
    if field_l in {"source_artifact", "pointer_snapshot_guardrails"}:
        return ["hardware"]
    if "runtime_process_map" in field_l or "load_bias" in field_l:
        return ["runtime_os_map"]
    if "elf" in field_l or "source_line" in field_l or "code_map" in field_l:
        return ["exact_elf"]
    if field_l in {"pointer_snapshot_route", "hardware_user_pointer_snapshot"}:
        return ["hardware", "validation_oracle"]
    if value_mentions_oracle(value):
        return ["validation_oracle"]
    if field_l in {
        "anti_analysis_behavior_node",
        "argument_reconstruction_accuracy",
        "execve_filename_accuracy",
        "execve_path_source",
        "execve_paths",
        "expected_syscall_recall",
        "expected_syscalls",
        "ground_truth_alignment",
        "has_execve",
        "has_openat",
        "has_write",
        "mmap_mprotect_behavior_node",
        "openat_path_source",
        "openat_pathname_accuracy",
        "openat_paths",
        "primary_semantic_source",
        "semantic_source",
        "syscall_precision",
        "write_buffer_prefix_recovered",
        "write_buffer_prefix_source",
        "write_buffer_prefixes",
    }:
        return ["validation_oracle"]
    return ["validation_oracle"]


def annotate_object_fields(data: dict[str, Any], skip: set[str] | None = None) -> dict[str, list[str]]:
    skip = skip or set()
    provenance: dict[str, list[str]] = {}
    for field, value in data.items():
        if field in skip or field.startswith("field_provenance"):
            continue
        provenance[field] = provenance_for_field(field, value)
    return provenance


def annotate_semantic_row(row: dict[str, Any]) -> None:
    row["field_provenance_schema"] = PROVENANCE_SCHEMA
    row["field_provenance"] = annotate_object_fields(row, skip={"non_claims"})
    row["oracle_fields"] = sorted(
        field
        for field, provenance in row["field_provenance"].items()
        if "validation_oracle" in provenance and "hardware" not in provenance
    )
    row["claim_boundary"] = {
        "qemu_strace_host_control_are_oracles_only": True,
        "oracle_fields_not_reported_as_hardware": True,
        "full_pointer_strings_claimed_from_hardware": False,
    }


def annotate_sample_artifact(path: Path) -> dict[str, Any]:
    data = load_json(path)
    row = as_dict(data.get("row"))
    if row:
        annotate_semantic_row(row)
    data["field_provenance_schema"] = PROVENANCE_SCHEMA
    data["field_provenance"] = annotate_object_fields(data, skip={"non_claims", "row"})
    data["field_provenance"]["row"] = ["hardware", "validation_oracle"]
    data["claim_boundary"] = {
        "qemu_strace_host_control_are_oracles_only": True,
        "board_trace_source_is_hardware": True,
        "sidecar_not_board_native_dwarf": True,
        "real_malware_validation_claimed": False,
    }
    write_json(path, data)
    return data


def package_provenance(root: Path = ROOT, current_root: Path = DEFAULT_CURRENT_ROOT) -> dict[str, Any]:
    current = root / current_root
    semantic_summary_path = current / SUMMARY_NAME
    summary = load_json(semantic_summary_path)
    for row in as_list(summary.get("samples")):
        if isinstance(row, dict):
            annotate_semantic_row(row)
    summary["field_provenance_schema"] = PROVENANCE_SCHEMA
    summary["field_provenance"] = annotate_object_fields(summary, skip={"samples", "non_claims"})
    summary["field_provenance"]["samples"] = ["hardware", "validation_oracle"]
    summary["claim_boundary"] = {
        **as_dict(summary.get("claim_boundary")),
        "qemu_strace_host_control_are_oracles_only": True,
        "oracle_fields_not_reported_as_hardware": True,
        "sidecar_not_board_native_dwarf": True,
        "real_malware_validation_claimed": False,
    }
    write_json(semantic_summary_path, summary)

    sample_paths = sorted((current / "samples").glob("*/semantic_events.json"))
    annotated_samples = [annotate_sample_artifact(path) for path in sample_paths]
    oracle_field_count = 0
    hardware_trace_count = 0
    for data in annotated_samples:
        row = as_dict(data.get("row"))
        provenance = as_dict(row.get("field_provenance"))
        oracle_field_count += sum(1 for values in provenance.values() if isinstance(values, list) and "validation_oracle" in values)
        if "hardware" in as_list(provenance.get("trace_source")):
            hardware_trace_count += 1
    return {
        "schema": PROVENANCE_SCHEMA,
        "status": "PASS",
        "canonical_evaluation_root": current_root.as_posix(),
        "semantic_summary": repo_rel(semantic_summary_path, root),
        "sample_artifact_count": len(sample_paths),
        "hardware_trace_field_count": hardware_trace_count,
        "oracle_field_count": oracle_field_count,
        "allowed_provenance": list(ALLOWED_PROVENANCE),
        "claim_boundary": {
            "qemu_strace_host_control_are_oracles_only": True,
            "oracle_fields_not_reported_as_hardware": True,
            "sidecar_not_board_native_dwarf": True,
            "real_malware_validation_claimed": False,
        },
        "sample_artifacts": [
            {
                "sample_id": data.get("sample_id"),
                "path": repo_rel(sample_paths[index], root),
                "trace_source_provenance": as_dict(as_dict(data.get("row")).get("field_provenance")).get("trace_source"),
                "oracle_fields": as_dict(data.get("row")).get("oracle_fields"),
            }
            for index, data in enumerate(annotated_samples)
        ],
        "validation_commands": [
            "uv run python tools/package_genesys2_semantic_provenance.py",
            "uv run python tools/check_genesys2_semantic_provenance.py --root .",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Annotate Genesys2/CVA6 semantic reconstruction fields with source provenance.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_CURRENT_ROOT / PROVENANCE_NAME)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    summary = package_provenance(root, args.current_root)
    out = args.out if args.out.is_absolute() else root / args.out
    write_json(out, summary)
    print(f"[PASS] wrote semantic field provenance summary to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
