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
    write_json,
)

from ccfa_gate_common import ALL_CCFA_SAMPLES


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/external_closure_readiness.json")

EXPECTED_RECORD_STATUSES = {
    "board_native_dwarf_source_lines": "EXTERNAL_BOARD_RERUN_READY_NOT_EXECUTED",
    "full_hardware_pointer_strings": "RTL_EXTENSION_REQUIRED_NOT_EXECUTED",
    "production_streaming_dma_trace_sink": "STREAMING_DMA_EXPERIMENT_REQUIRED_NOT_EXECUTED",
    "genesys2_board_benign_control": "BOARD_BENIGN_CONTROL_RUN_REQUIRED_NOT_EXECUTED",
}


def row_map(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def text_has_all(text: str, needles: list[str]) -> bool:
    lower = text.lower()
    return all(needle.lower() in lower for needle in needles)


def check_evidence_rows(errors: list[str], root: Path, record_id: str, rows: list[Any]) -> None:
    require(errors, bool(rows), f"{record_id}: existing_evidence must be nonempty")
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            errors.append(f"{record_id}: evidence row {index} must be an object")
            continue
        path_value = row.get("path")
        require(errors, bool(path_value), f"{record_id}: evidence row {index} path missing")
        require(errors, row.get("exists") is True, f"{record_id}: evidence row {index} must exist")
        if path_value:
            require(errors, repo_path(root, path_value).is_file(), f"{record_id}: evidence file missing: {path_value}")
        require(errors, bool(row.get("sha256")), f"{record_id}: evidence row {index} sha256 missing")


def check_record_common(errors: list[str], root: Path, record_id: str, record: dict[str, Any]) -> None:
    require(errors, record.get("current_blocker") is True, f"{record_id}: current_blocker must be true")
    require(errors, record.get("completion_requires_external_state") is True, f"{record_id}: external-state requirement missing")
    require(errors, record.get("external_evidence_claimed") is False, f"{record_id}: must not claim external evidence")
    require(errors, record.get("readiness_status") == EXPECTED_RECORD_STATUSES[record_id], f"{record_id}: readiness_status mismatch")
    require(errors, bool(record.get("current_status")), f"{record_id}: current_status required")
    check_evidence_rows(errors, root, record_id, as_list(record.get("existing_evidence")))
    require(errors, len(as_list(record.get("required_external_artifacts"))) >= 4, f"{record_id}: required external artifacts under-specified")
    require(errors, len(as_list(record.get("acceptance_criteria"))) >= 4, f"{record_id}: acceptance criteria under-specified")
    contract = as_dict(record.get("future_checker_contract"))
    require(errors, bool(contract.get("required_summary_schema")), f"{record_id}: future summary schema required")
    require(errors, contract.get("must_fail_until_external_artifacts_present") is True, f"{record_id}: future checker must fail until external artifacts exist")
    required_fields = as_list(contract.get("required_fields"))
    require(errors, len(required_fields) >= 4, f"{record_id}: future checker required_fields under-specified")
    require(errors, "evidence_artifacts" in required_fields, f"{record_id}: future checker must require evidence_artifacts")
    require(errors, text_has_all(str(record.get("no_substitution_rule") or ""), ["must not", "substituted"]), f"{record_id}: no-substitution rule is too weak")


def check_record_specific(errors: list[str], record_id: str, record: dict[str, Any]) -> None:
    criteria = " ".join(str(item) for item in as_list(record.get("acceptance_criteria")))
    artifacts = " ".join(str(item) for item in as_list(record.get("required_external_artifacts")))
    contract_fields = " ".join(str(item) for item in as_list(as_dict(record.get("future_checker_contract")).get("required_fields")))
    no_sub = str(record.get("no_substitution_rule") or "")
    evidence_ids = set(row_map(as_list(record.get("existing_evidence"))))
    if record_id == "board_native_dwarf_source_lines":
        require(errors, set(as_list(record.get("sample_scope"))) == set(ALL_CCFA_SAMPLES), "source-line record sample scope mismatch")
        require(errors, text_has_all(artifacts, [".debug_line", "board capture", "captured_elf_sha256"]), "source-line artifacts must require DWARF and exact ELF linkage")
        require(errors, text_has_all(criteria, ["board_trace_source_line_available=true", "source_line_attribution_available=true", "0.95"]), "source-line criteria must require board trace line attribution rate")
        require(errors, "sidecar" in no_sub.lower(), "source-line no-substitution rule must reject sidecars")
    elif record_id == "full_hardware_pointer_strings":
        require(errors, "pointer_string_readiness" in evidence_ids, "pointer string record must include readiness summary evidence")
        require(errors, "package_pointer_string_readiness" in evidence_ids, "pointer string record must include readiness packager evidence")
        require(errors, "check_pointer_string_readiness" in evidence_ids, "pointer string record must include readiness checker evidence")
        require(errors, set(as_list(record.get("syscall_scope"))) >= {"openat", "write", "execve"}, "pointer string syscall scope incomplete")
        require(errors, text_has_all(artifacts, ["contiguous", "mem_last", "redaction"]), "pointer artifacts must require contiguous mem_last and release policy")
        require(errors, text_has_all(criteria, ["full_string_claimed", "companion-derived", "kernel-space"]), "pointer criteria must preserve string and safety boundaries")
        require(errors, text_has_all(contract_fields, ["full_string_claimed", "full_string_group_count", "pointer_groups", "contiguous_from_offset_zero", "mem_last_observed", "redaction_policy"]), "pointer future checker fields incomplete")
    elif record_id == "production_streaming_dma_trace_sink":
        require(errors, "streaming_dma_readiness" in evidence_ids, "streaming record must include readiness summary evidence")
        require(errors, text_has_all(artifacts, ["non-BRAM", "throughput", "host receiver", "resource"]), "streaming artifacts must require non-BRAM throughput evidence")
        require(errors, text_has_all(criteria, ["not reported as BRAM", "p99", "1.5", "unaccounted DROP", "timing closure"]), "streaming criteria incomplete")
        require(
            errors,
            text_has_all(
                contract_fields,
                [
                    "transport",
                    "sustained_bytes_per_second",
                    "p95_event_bytes_per_second",
                    "p99_event_bytes_per_second",
                    "required_sustained_bytes_per_second",
                    "minimum_sustained_throughput_multiplier",
                ],
            ),
            "streaming future checker fields incomplete",
        )
    elif record_id == "genesys2_board_benign_control":
        require(errors, "board_benign_readiness" in evidence_ids, "board benign record must include readiness summary evidence")
        require(errors, "Genesys2/CVA6 board traces" in artifacts, "board benign artifacts must require board traces")
        require(errors, text_has_all(criteria, ["at least five", "0.0", "board benign evidence"]), "board benign criteria incomplete")
        require(errors, text_has_all(contract_fields, ["genesys2_board_trace_claimed", "benign_false_positive_rate"]), "board benign future checker fields incomplete")


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.external_closure_readiness.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(errors, "real_malware_validation" in as_list(data.get("objective_exclusions")), "real-malware objective exclusion missing")
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("readiness_contract_only") is True, "readiness contract boundary missing")
    for key in (
        "real_malware_validation_claimed",
        "hardware_full_pointer_strings_claimed",
        "production_streaming_dma_throughput_claimed",
        "board_native_source_line_attribution_claimed",
        "genesys2_board_benign_control_claimed",
    ):
        require(errors, boundary.get(key) is False, f"{key} must be false")
    require(errors, boundary.get("current_board_elf_dwarf_available") is False, "current board ELF DWARF must remain false")
    require(errors, boundary.get("current_board_trace_source_line_available") is False, "current board trace source lines must remain false")
    require(errors, boundary.get("full_string_claimed") is False, "full_string_claimed must remain false")
    require(errors, int(data.get("external_blocker_count") or 0) == len(EXPECTED_RECORD_STATUSES), "external_blocker_count mismatch")
    records = row_map(as_list(data.get("records")))
    missing = sorted(set(EXPECTED_RECORD_STATUSES) - set(records))
    extra = sorted(set(records) - set(EXPECTED_RECORD_STATUSES))
    require(errors, not missing, f"missing records: {', '.join(missing)}")
    require(errors, not extra, f"unexpected records: {', '.join(extra)}")
    for record_id, record in records.items():
        check_record_common(errors, root, record_id, record)
        check_record_specific(errors, record_id, record)
    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_external_closure_readiness.py" in commands, "validation command must include packager")
    require(errors, "tools/check_genesys2_external_closure_readiness.py --root ." in commands, "validation command must include checker")
    interpretation = " ".join(str(item).lower() for item in as_list(data.get("interpretation")))
    require(errors, "does not upgrade current evidence" in interpretation, "interpretation must preserve current evidence boundary")
    require(errors, as_list(data.get("failures")) == [], "failures must be empty")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / "evidence.txt"
        evidence.write_text("fixture\n", encoding="utf-8")
        evidence_row = {"id": "fixture", "path": "evidence.txt", "exists": True, "sha256": "a" * 64}
        records = []
        for record_id, status in EXPECTED_RECORD_STATUSES.items():
            record: dict[str, Any] = {
                "id": record_id,
                "current_status": "fixture",
                "readiness_status": status,
                "current_blocker": True,
                "completion_requires_external_state": True,
                "external_evidence_claimed": False,
                "existing_evidence": [evidence_row],
                "required_external_artifacts": ["one", "two", "three", "four"],
                "acceptance_criteria": ["one", "two", "three", "four"],
                "future_checker_contract": {
                    "required_summary_schema": f"rvmt.fixture.{record_id}.v1",
                    "must_fail_until_external_artifacts_present": True,
                    "required_fields": ["evidence_artifacts", "one", "two", "three", "four"],
                },
                "no_substitution_rule": "fixture must not be substituted for external evidence",
            }
            if record_id == "board_native_dwarf_source_lines":
                record["sample_scope"] = ALL_CCFA_SAMPLES
                record["required_external_artifacts"] = [
                    ".debug_line board capture captured_elf_sha256",
                    "two",
                    "three",
                    "four",
                ]
                record["acceptance_criteria"] = [
                    "board_trace_source_line_available=true source_line_attribution_available=true 0.95",
                    "two",
                    "three",
                    "four",
                ]
                record["no_substitution_rule"] = "sidecar must not be substituted for board DWARF"
            elif record_id == "full_hardware_pointer_strings":
                record["existing_evidence"] = [
                    evidence_row,
                    {"id": "pointer_string_readiness", "path": "evidence.txt", "exists": True, "sha256": "d" * 64},
                    {"id": "package_pointer_string_readiness", "path": "evidence.txt", "exists": True, "sha256": "e" * 64},
                    {"id": "check_pointer_string_readiness", "path": "evidence.txt", "exists": True, "sha256": "f" * 64},
                ]
                record["syscall_scope"] = ["openat", "write", "execve"]
                record["required_external_artifacts"] = ["contiguous mem_last redaction", "two", "three", "four"]
                record["acceptance_criteria"] = ["full_string_claimed companion-derived kernel-space", "two", "three", "four"]
                record["future_checker_contract"]["required_fields"] = [
                    "full_string_claimed",
                    "full_string_group_count",
                    "pointer_groups",
                    "evidence_artifacts",
                    "contiguous_from_offset_zero",
                    "mem_last_observed",
                    "redaction_policy",
                ]
            elif record_id == "production_streaming_dma_trace_sink":
                record["existing_evidence"] = [
                    evidence_row,
                    {"id": "streaming_dma_readiness", "path": "evidence.txt", "exists": True, "sha256": "c" * 64},
                ]
                record["required_external_artifacts"] = ["non-BRAM throughput host receiver resource", "two", "three", "four"]
                record["acceptance_criteria"] = ["not reported as BRAM p99 1.5 unaccounted DROP timing closure", "two", "three", "four"]
                record["future_checker_contract"]["required_fields"] = [
                    "transport",
                    "evidence_artifacts",
                    "sustained_bytes_per_second",
                    "p95_event_bytes_per_second",
                    "p99_event_bytes_per_second",
                    "required_sustained_bytes_per_second",
                    "minimum_sustained_throughput_multiplier",
                    "four",
                ]
            elif record_id == "genesys2_board_benign_control":
                record["existing_evidence"] = [
                    evidence_row,
                    {"id": "board_benign_readiness", "path": "evidence.txt", "exists": True, "sha256": "b" * 64},
                ]
                record["required_external_artifacts"] = ["Genesys2/CVA6 board traces false-positive", "two", "three", "four"]
                record["acceptance_criteria"] = ["at least five 0.0 board benign evidence", "two", "three", "four"]
                record["future_checker_contract"]["required_fields"] = [
                    "genesys2_board_trace_claimed",
                    "evidence_artifacts",
                    "benign_false_positive_rate",
                    "three",
                    "four",
                ]
            records.append(record)
        summary = {
            "schema": "rvmt.genesys2.external_closure_readiness.v1",
            "status": "PASS",
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "objective_exclusions": ["real_malware_validation"],
            "claim_boundary": {
                "readiness_contract_only": True,
                "real_malware_validation_claimed": False,
                "hardware_full_pointer_strings_claimed": False,
                "production_streaming_dma_throughput_claimed": False,
                "board_native_source_line_attribution_claimed": False,
                "genesys2_board_benign_control_claimed": False,
                "current_board_elf_dwarf_available": False,
                "current_board_trace_source_line_available": False,
                "full_string_claimed": False,
            },
            "external_blocker_count": 4,
            "records": records,
            "validation_commands": [
                "uv run python tools/package_genesys2_external_closure_readiness.py",
                "uv run python tools/check_genesys2_external_closure_readiness.py --root .",
            ],
            "interpretation": ["This does not upgrade current evidence."],
            "failures": [],
        }
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] external closure readiness good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["records"][0]["external_evidence_claimed"] = True
        errors = check_summary(summary, root)
        if not errors:
            print("[FAIL] external closure readiness bad fixture passed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 external closure readiness checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check readiness contracts for remaining non-real-malware Genesys2/CVA6 blockers.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing external closure readiness summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] external closure readiness checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] external closure readiness is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] external closure readiness accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
