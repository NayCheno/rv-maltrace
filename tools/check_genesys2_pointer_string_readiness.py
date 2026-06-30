from __future__ import annotations

import argparse
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
    sha256_file,
    write_json,
)


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/pointer_string_readiness_summary.json")
EXPECTED_SYSCALLS = {"openat", "write", "execve"}
EXPECTED_SOURCE_IDS = {
    "hardware_pointer_prefix_summary",
    "pointer_snapshot_guardrails",
    "semantic_reconstruction_summary",
    "fd_path_graph_summary",
    "baseline_alignment_summary",
    "trace_format_arg_mem_schema",
    "cva6_signal_map_pointer_hooks",
    "rv_maltrace_cli_trace_parser",
    "package_hardware_pointer_prefixes",
    "check_hardware_pointer_prefixes",
}
EXPECTED_SOURCE_SCHEMAS = {
    "hardware_pointer_prefix_summary": "rvmt.hardware_pointer_prefixes.v1",
    "pointer_snapshot_guardrails": "rvmt.pointer_snapshot_guardrails.v1",
    "semantic_reconstruction_summary": "rvmt.syscall_semantic_reconstruction.v1",
    "fd_path_graph_summary": "rvmt.fd_path_graph.v1",
    "baseline_alignment_summary": "rvmt.baseline_alignment.v1",
}
REQUIRED_ARTIFACT_KINDS = {
    "rtl_design_manifest",
    "pointer_capture_manifest",
    "pointer_group_reconstruction",
    "mem_last_or_terminator_report",
    "redaction_policy",
    "kernel_space_filter_report",
    "companion_substitution_audit",
    "resource_timing_report",
}
REQUIRED_SUMMARY_FIELDS = {
    "evidence_artifacts",
    "full_string_claimed",
    "full_string_group_count",
    "pointer_groups",
    "syscall_coverage",
    "contiguous_from_offset_zero",
    "mem_last_observed",
    "companion_derived_strings_as_hardware",
    "kernel_fragment_count",
    "full_memory_dump_count",
    "redaction_policy",
    "failed_attempts",
}


def as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def row_map(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def check_evidence_row(errors: list[str], root: Path, row: dict[str, Any], context: str) -> None:
    path_value = row.get("path")
    require(errors, bool(path_value), f"{context}: path missing")
    require(errors, row.get("exists") is True, f"{context}: exists must be true")
    require(errors, bool(row.get("sha256")), f"{context}: sha256 missing")
    if not path_value:
        return
    path = repo_path(root, path_value)
    require(errors, path.is_file(), f"{context}: file missing: {path_value}")
    if path.is_file():
        require(errors, row.get("sha256") == sha256_file(path), f"{context}: sha256 mismatch")
        if path.suffix == ".json":
            data = load_json(path)
            require(errors, row.get("schema") == data.get("schema"), f"{context}: schema mismatch")
            require(errors, row.get("status") == data.get("status"), f"{context}: status mismatch")


def check_sources(errors: list[str], data: dict[str, Any], root: Path) -> None:
    sources = row_map(as_list(data.get("source_evidence")))
    missing = sorted(EXPECTED_SOURCE_IDS - set(sources))
    require(errors, not missing, f"missing source evidence ids: {', '.join(missing)}")
    for source_id, row in sources.items():
        check_evidence_row(errors, root, row, f"source_evidence.{source_id}")
        expected_schema = EXPECTED_SOURCE_SCHEMAS.get(source_id)
        if expected_schema:
            require(errors, row.get("schema") == expected_schema, f"source_evidence.{source_id}: schema mismatch")
            require(errors, row.get("status") == "PASS", f"source_evidence.{source_id}: status must be PASS")


def check_current_prefix(errors: list[str], data: dict[str, Any], root: Path) -> None:
    prefix = as_dict(data.get("current_prefix_evidence"))
    require(errors, prefix.get("summary_schema") == "rvmt.hardware_pointer_prefixes.v1", "prefix summary schema mismatch")
    require(errors, prefix.get("summary_status") == "PASS", "prefix summary status must be PASS")
    require(errors, prefix.get("trace_sink_mode") == "bram_ring", "prefix trace sink must be bram_ring")
    require(errors, prefix.get("source_record_format") == "compact_arg_mem_32bit_addr_data_prefix", "prefix source record format mismatch")
    require(errors, as_int(prefix.get("total_repetitions")) >= 30, "prefix total_repetitions must be at least 30")
    require(errors, as_int(prefix.get("sample_count")) >= 3, "prefix sample_count must be at least 3")
    require(errors, as_int(prefix.get("pointer_group_count")) > 0, "prefix pointer_group_count must be positive")
    require(errors, as_int(prefix.get("captured_byte_count")) > 0, "prefix captured_byte_count must be positive")
    require(errors, as_dict(prefix.get("required_syscall_coverage")).items() >= {name: True for name in EXPECTED_SYSCALLS}.items(), "required syscall coverage mismatch")
    require(errors, prefix.get("hardware_pointer_bytes_observed") is True, "hardware pointer bytes must be observed")
    require(errors, prefix.get("hardware_pointer_prefixes_claimed") is True, "bounded prefix claim missing")
    require(errors, prefix.get("hardware_pointer_strings_claimed") is False, "hardware pointer strings must not be claimed")
    require(errors, prefix.get("full_string_claimed") is False, "full string must not be claimed")
    require(errors, prefix.get("companion_derived_strings_as_hardware") is False, "companion strings must not be hardware")
    require(errors, as_int(prefix.get("kernel_fragment_count"), default=-1) == 0, "kernel fragments must be zero")
    run_root = prefix.get("run_root")
    require(errors, bool(run_root), "prefix run_root required")
    if run_root:
        require(errors, repo_path(root, run_root).is_dir(), f"prefix run_root missing: {run_root}")

    guardrails = as_dict(prefix.get("guardrails"))
    require(errors, guardrails.get("hardware_user_pointer_snapshot") is True, "guardrails hardware snapshot missing")
    require(errors, guardrails.get("hardware_pointer_strings_claimed") is False, "guardrails must not claim hardware pointer strings")
    require(errors, guardrails.get("captures_kernel_memory") is False, "guardrails must not capture kernel memory")
    require(errors, guardrails.get("full_memory_dump") is False, "guardrails must not allow full memory dumps")
    require(errors, as_int(guardrails.get("max_bytes_per_pointer")) == 256, "guardrails max_bytes_per_pointer must be 256")
    redaction_policy = str(guardrails.get("redaction_policy") or "").lower()
    require(errors, bool(redaction_policy), "guardrails redaction policy missing")
    require(
        errors,
        "raw pointer payload" in redaction_policy and "published summaries" in redaction_policy,
        "guardrails redaction policy must describe raw payload and published summary handling",
    )

    observed = as_dict(prefix.get("observed_boundaries"))
    require(errors, as_int(observed.get("observed_group_count")) == as_int(prefix.get("pointer_group_count")), "observed group count mismatch")
    require(errors, observed.get("contains_gapped_groups") is True, "current evidence should record gapped groups")
    require(errors, as_int(observed.get("gapped_group_count")) > 0, "gapped group count must be positive")
    require(errors, observed.get("has_bounded_prefix_groups") is True, "bounded prefix groups must be present")
    require(errors, as_int(observed.get("bounded_prefix_group_count")) > 0, "bounded prefix group count must be positive")
    require(errors, as_int(observed.get("max_contiguous_prefix_bytes")) > 0, "max contiguous prefix bytes must be positive")
    require(errors, observed.get("mem_last_observed") is False, "mem_last must not be claimed in current prefix evidence")
    require(errors, as_int(observed.get("groups_promoted_from_gapped_fragments")) == 0, "gapped fragments must not be promoted")
    require(errors, observed.get("contiguous_offset_zero_full_string_evidence_available") is False, "offset-zero full-string evidence must not be claimed")
    syscall_counts = as_dict(observed.get("syscall_group_counts"))
    for syscall_name in EXPECTED_SYSCALLS:
        require(errors, as_int(syscall_counts.get(syscall_name)) > 0, f"missing observed syscall groups: {syscall_name}")


def check_future_contract(errors: list[str], data: dict[str, Any]) -> None:
    contract = as_dict(data.get("future_full_string_contract"))
    require(errors, contract.get("required_summary_schema") == "rvmt.genesys2.hardware_pointer_strings.v1", "future summary schema mismatch")
    require(
        errors,
        contract.get("external_summary_path") == "results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json",
        "future external summary path mismatch",
    )
    require(errors, set(as_list(contract.get("required_syscalls"))) == EXPECTED_SYSCALLS, "future syscall set mismatch")
    requirements = as_dict(contract.get("minimum_requirements"))
    for key in (
        "contiguous_bytes_from_offset_zero_required",
        "terminator_or_documented_bounded_truncation_required",
        "mem_last_or_terminator_evidence_required",
        "gap_free_group_reconstruction_required",
        "per_group_artifact_hash_required",
        "companion_substitution_forbidden",
        "gapped_fragment_promotion_forbidden",
        "kernel_fragment_count_must_be_zero",
        "full_memory_dump_forbidden",
        "raw_payload_redaction_policy_required",
    ):
        require(errors, requirements.get(key) is True, f"minimum requirement missing: {key}")
    require(errors, set(as_list(contract.get("required_evidence_artifact_kinds"))) >= REQUIRED_ARTIFACT_KINDS, "required artifact kinds incomplete")
    require(errors, set(as_list(contract.get("required_summary_fields"))) >= REQUIRED_SUMMARY_FIELDS, "required summary fields incomplete")
    criteria_text = " ".join(str(item).lower() for item in as_list(contract.get("acceptance_criteria")))
    for needle in ("offset 0", "nul terminator", "bounded truncation", "mem_last", "gapped", "companion", "kernel-space", "redaction", "openat/write/execve"):
        require(errors, needle in criteria_text, f"acceptance criteria must mention {needle}")


def check_boundary(errors: list[str], data: dict[str, Any]) -> None:
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("pointer_string_readiness_claimed") is True, "readiness claim boundary missing")
    require(errors, boundary.get("hardware_pointer_prefix_evidence_available") is True, "prefix evidence boundary missing")
    for key in (
        "full_hardware_pointer_strings_claimed",
        "hardware_pointer_strings_claimed",
        "full_string_claimed",
        "bounded_prefix_substituted_for_full_strings",
        "companion_derived_strings_as_hardware",
        "raw_pointer_payload_release_claimed",
        "kernel_memory_capture_claimed",
        "full_memory_dump_claimed",
        "real_malware_validation_claimed",
    ):
        require(errors, boundary.get(key) is False, f"{key} must be false")
    require(errors, boundary.get("rtl_extension_required_for_closure") is True, "RTL extension requirement missing")
    require(errors, boundary.get("external_execution_required_for_closure") is True, "external execution requirement missing")


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.pointer_string_readiness.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(errors, "full hardware pointer-string" in str(data.get("scope") or ""), "scope must identify full hardware pointer-string readiness")
    check_sources(errors, data, root)
    check_current_prefix(errors, data, root)
    check_future_contract(errors, data)
    check_boundary(errors, data)
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "does not claim full hardware pointer-string evidence is complete" in non_claims, "non_claims must reject full-string completion")
    require(errors, "bounded-prefix evidence, not full strings" in non_claims, "non_claims must preserve prefix boundary")
    require(errors, "must not be substituted" in non_claims, "non_claims must reject companion substitution")
    require(errors, "gapped hardware fragments must not be joined" in non_claims, "non_claims must reject gapped fragment joining")
    require(errors, "real-malware validation" in non_claims, "non_claims must reject real-malware validation")
    require(errors, as_list(data.get("failures")) == [], "failures must be empty")
    return errors


def make_source_row(root: Path, source_id: str, path: Path, schema: str | None = None) -> dict[str, Any]:
    if schema:
        write_json(path, {"schema": schema, "status": "PASS"})
        return {
            "id": source_id,
            "path": path.relative_to(root).as_posix(),
            "exists": True,
            "sha256": sha256_file(path),
            "schema": schema,
            "status": "PASS",
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("fixture\n", encoding="utf-8", newline="\n")
    return {
        "id": source_id,
        "path": path.relative_to(root).as_posix(),
        "exists": True,
        "sha256": sha256_file(path),
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        run_root = root / "results/board/pointer-run"
        run_root.mkdir(parents=True)
        source_rows = []
        for source_id in sorted(EXPECTED_SOURCE_IDS):
            schema = EXPECTED_SOURCE_SCHEMAS.get(source_id)
            suffix = ".json" if schema else ".txt"
            path = root / "sources" / f"{source_id}{suffix}"
            source_rows.append(make_source_row(root, source_id, path, schema))
        summary = {
            "schema": "rvmt.genesys2.pointer_string_readiness.v1",
            "status": "PASS",
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "scope": "readiness package for future full hardware pointer-string evidence on Genesys2/CVA6",
            "source_evidence": source_rows,
            "current_prefix_evidence": {
                "summary_schema": "rvmt.hardware_pointer_prefixes.v1",
                "summary_status": "PASS",
                "run_root": run_root.relative_to(root).as_posix(),
                "trace_sink_mode": "bram_ring",
                "source_record_format": "compact_arg_mem_32bit_addr_data_prefix",
                "total_repetitions": 30,
                "sample_count": 3,
                "pointer_group_count": 9,
                "captured_byte_count": 120,
                "required_syscall_coverage": {name: True for name in EXPECTED_SYSCALLS},
                "hardware_pointer_bytes_observed": True,
                "hardware_pointer_prefixes_claimed": True,
                "hardware_pointer_strings_claimed": False,
                "full_string_claimed": False,
                "companion_derived_strings_as_hardware": False,
                "kernel_fragment_count": 0,
                "guardrails": {
                    "hardware_user_pointer_snapshot": True,
                    "hardware_pointer_strings_claimed": False,
                    "captures_kernel_memory": False,
                    "full_memory_dump": False,
                    "max_bytes_per_pointer": 256,
                    "redaction_policy": "raw pointer payload fixture retained locally; published summaries are sanitized",
                },
                "observed_boundaries": {
                    "observed_group_count": 9,
                    "gapped_group_count": 3,
                    "bounded_prefix_group_count": 6,
                    "nul_seen_in_contiguous_prefix_count": 1,
                    "max_contiguous_prefix_bytes": 12,
                    "syscall_group_counts": {"openat": 3, "write": 3, "execve": 3},
                    "contains_gapped_groups": True,
                    "has_bounded_prefix_groups": True,
                    "mem_last_observed": False,
                    "groups_promoted_from_gapped_fragments": 0,
                    "contiguous_offset_zero_full_string_evidence_available": False,
                },
            },
            "future_full_string_contract": {
                "required_summary_schema": "rvmt.genesys2.hardware_pointer_strings.v1",
                "external_summary_path": "results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json",
                "required_syscalls": sorted(EXPECTED_SYSCALLS),
                "minimum_requirements": {
                    "contiguous_bytes_from_offset_zero_required": True,
                    "terminator_or_documented_bounded_truncation_required": True,
                    "mem_last_or_terminator_evidence_required": True,
                    "gap_free_group_reconstruction_required": True,
                    "per_group_artifact_hash_required": True,
                    "companion_substitution_forbidden": True,
                    "gapped_fragment_promotion_forbidden": True,
                    "kernel_fragment_count_must_be_zero": True,
                    "full_memory_dump_forbidden": True,
                    "raw_payload_redaction_policy_required": True,
                },
                "required_evidence_artifact_kinds": sorted(REQUIRED_ARTIFACT_KINDS),
                "required_summary_fields": sorted(REQUIRED_SUMMARY_FIELDS),
                "acceptance_criteria": [
                    "offset 0 through NUL terminator or bounded truncation, mem_last required, gapped fragments rejected, companion rejected, kernel-space rejected, redaction required, openat/write/execve covered",
                ],
            },
            "claim_boundary": {
                "pointer_string_readiness_claimed": True,
                "hardware_pointer_prefix_evidence_available": True,
                "full_hardware_pointer_strings_claimed": False,
                "hardware_pointer_strings_claimed": False,
                "full_string_claimed": False,
                "bounded_prefix_substituted_for_full_strings": False,
                "companion_derived_strings_as_hardware": False,
                "raw_pointer_payload_release_claimed": False,
                "kernel_memory_capture_claimed": False,
                "full_memory_dump_claimed": False,
                "real_malware_validation_claimed": False,
                "rtl_extension_required_for_closure": True,
                "external_execution_required_for_closure": True,
            },
            "non_claims": [
                "This is a readiness package and does not claim full hardware pointer-string evidence is complete.",
                "Current evidence remains bounded-prefix evidence, not full strings.",
                "Companion strings must not be substituted for hardware strings.",
                "Gapped hardware fragments must not be joined into full strings.",
                "Real-malware validation is not claimed.",
            ],
            "failures": [],
        }
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] pointer string readiness good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["full_hardware_pointer_strings_claimed"] = True
        errors = check_summary(summary, root)
        if not errors:
            print("[FAIL] pointer string readiness bad fixture passed", file=sys.stderr)
            return 1
    print("[PASS] pointer string readiness checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2 full hardware pointer-string readiness evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing pointer string readiness summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] pointer string readiness checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] pointer string readiness evidence is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print("[PASS] pointer string readiness evidence accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
