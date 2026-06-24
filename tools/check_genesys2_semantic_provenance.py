from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from package_genesys2_semantic_provenance import (
    ALLOWED_PROVENANCE,
    DEFAULT_CURRENT_ROOT,
    PROVENANCE_NAME,
    PROVENANCE_SCHEMA,
    SUMMARY_NAME,
    package_provenance,
    write_json,
)


DEFAULT_SUMMARY = DEFAULT_CURRENT_ROOT / PROVENANCE_NAME
ORACLE_HINTS = ("qemu", "strace", "host", "control", "trusted_companion")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def repo_path(root: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def value_mentions_oracle(value: Any) -> bool:
    if isinstance(value, str):
        lowered = value.lower()
        return any(hint in lowered for hint in ORACLE_HINTS)
    if isinstance(value, list):
        return any(value_mentions_oracle(item) for item in value)
    if isinstance(value, dict):
        return any(value_mentions_oracle(item) for item in value.values())
    return False


def check_provenance_map(errors: list[str], context: str, data: dict[str, Any], skip: set[str] | None = None) -> None:
    skip = skip or set()
    require(errors, data.get("field_provenance_schema") == PROVENANCE_SCHEMA, f"{context}: field provenance schema missing")
    provenance = as_dict(data.get("field_provenance"))
    require(errors, bool(provenance), f"{context}: field_provenance missing")
    for field, value in data.items():
        if field in skip or field.startswith("field_provenance") or field in {"oracle_fields", "claim_boundary"}:
            continue
        if field == "non_claims":
            continue
        require(errors, field in provenance, f"{context}: missing provenance for field {field}")
    for field, values in provenance.items():
        require(errors, isinstance(values, list) and bool(values), f"{context}.{field}: provenance must be a nonempty list")
        if not isinstance(values, list):
            continue
        invalid = sorted(set(str(item) for item in values) - set(ALLOWED_PROVENANCE))
        require(errors, not invalid, f"{context}.{field}: invalid provenance {', '.join(invalid)}")
        field_value = data.get(field)
        if value_mentions_oracle(field_value):
            require(errors, "validation_oracle" in values, f"{context}.{field}: oracle-valued field must include validation_oracle")
            require(errors, values != ["hardware"], f"{context}.{field}: oracle-valued field must not be hardware-only")


def check_semantic_row(errors: list[str], context: str, row: dict[str, Any]) -> None:
    check_provenance_map(errors, context, row, skip={"non_claims"})
    provenance = as_dict(row.get("field_provenance"))
    require(errors, "hardware" in as_list(provenance.get("trace_source")), f"{context}: trace_source must be hardware provenance")
    for field in ("semantic_source", "primary_semantic_source", "ground_truth_alignment", "openat_path_source", "execve_path_source", "write_buffer_prefix_source"):
        if field in row:
            require(errors, "validation_oracle" in as_list(provenance.get(field)), f"{context}.{field}: oracle field must be validation_oracle")
            require(errors, provenance.get(field) != ["hardware"], f"{context}.{field}: oracle field must not be hardware-only")
    boundary = as_dict(row.get("claim_boundary"))
    require(errors, boundary.get("qemu_strace_host_control_are_oracles_only") is True, f"{context}: oracle boundary missing")
    require(errors, boundary.get("full_pointer_strings_claimed_from_hardware") is False, f"{context}: full pointer strings must not be claimed from hardware")


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == PROVENANCE_SCHEMA, "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == DEFAULT_CURRENT_ROOT.as_posix(), "canonical root mismatch")
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("qemu_strace_host_control_are_oracles_only") is True, "oracle boundary missing")
    require(errors, boundary.get("oracle_fields_not_reported_as_hardware") is True, "oracle-as-hardware boundary missing")
    semantic_summary_path = repo_path(root, data.get("semantic_summary"))
    require(errors, semantic_summary_path.is_file(), "semantic summary artifact missing")
    if semantic_summary_path.is_file():
        semantic = load_json(semantic_summary_path)
        check_provenance_map(errors, "semantic_summary", semantic, skip={"samples", "non_claims"})
        for row in as_list(semantic.get("samples")):
            if isinstance(row, dict):
                sample_id = str(row.get("sample_id") or "<unknown>")
                check_semantic_row(errors, f"semantic_summary.samples[{sample_id}]", row)
    sample_rows = as_list(data.get("sample_artifacts"))
    require(errors, int(data.get("sample_artifact_count") or 0) == len(sample_rows), "sample artifact count mismatch")
    for row in sample_rows:
        if not isinstance(row, dict):
            errors.append("sample artifact row must be object")
            continue
        path_value = row.get("path")
        require(errors, bool(path_value), "sample artifact path missing")
        path = repo_path(root, path_value) if path_value else root
        require(errors, path.is_file(), f"sample artifact missing: {path_value}")
        if path.is_file():
            sample = load_json(path)
            sample_id = str(sample.get("sample_id") or path.parent.name)
            check_provenance_map(errors, f"sample_artifact[{sample_id}]", sample, skip={"non_claims", "row"})
            check_semantic_row(errors, f"sample_artifact[{sample_id}].row", as_dict(sample.get("row")))
    require(errors, int(data.get("hardware_trace_field_count") or 0) == len(sample_rows), "each sample must have hardware trace provenance")
    require(errors, int(data.get("oracle_field_count") or 0) > 0, "oracle field count must be positive")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        sample_dir = current / "samples/hello"
        sample_dir.mkdir(parents=True)
        write_json(
            current / SUMMARY_NAME,
            {
                "schema": "rvmt.syscall_semantic_reconstruction.v1",
                "status": "PASS",
                "samples": [
                    {
                        "sample_id": "hello",
                        "trace_source": "results/board/trace.jsonl",
                        "semantic_source": "trusted_qemu_guest_strace_companion",
                        "primary_semantic_source": "qemu_guest_strace",
                        "ground_truth_alignment": {"qemu_guest_strace": "qemu.strace.log"},
                    }
                ],
            },
        )
        write_json(
            sample_dir / "semantic_events.json",
            {
                "schema": "rvmt.sample.semantic_events.v1",
                "sample_id": "hello",
                "trace_source": "results/board/trace.jsonl",
                "row": {
                    "sample_id": "hello",
                    "trace_source": "results/board/trace.jsonl",
                    "semantic_source": "trusted_qemu_guest_strace_companion",
                    "primary_semantic_source": "qemu_guest_strace",
                    "ground_truth_alignment": {"qemu_guest_strace": "qemu.strace.log"},
                },
            },
        )
        summary = package_provenance(root)
        write_json(current / PROVENANCE_NAME, summary)
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] semantic provenance good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        semantic = load_json(current / SUMMARY_NAME)
        semantic["samples"][0]["field_provenance"]["semantic_source"] = ["hardware"]
        write_json(current / SUMMARY_NAME, semantic)
        errors = check_summary(summary, root)
        if not any("oracle-valued field" in error for error in errors):
            print("[FAIL] semantic provenance missed oracle-as-hardware", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 semantic provenance checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check field-level provenance for Genesys2/CVA6 semantic reconstruction.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] semantic provenance summary missing: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] semantic provenance checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] semantic provenance check failed")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] semantic provenance accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
