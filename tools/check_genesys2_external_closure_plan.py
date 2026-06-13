from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from ccfa_gate_common import ALL_CCFA_SAMPLES
from check_genesys2_external_closure_intake import EXPECTED_EXTERNAL_SUMMARIES, REQUIRED_EVIDENCE_ARTIFACT_KINDS


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/external_closure_plan.json")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def repo_path(root: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def row_map(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def text_has_all(text: str, needles: list[str]) -> bool:
    lower = text.lower()
    return all(needle.lower() in lower for needle in needles)


def expected_plan_status(intake_status: str) -> str:
    if intake_status == "EXTERNAL_SUMMARY_ACCEPTED":
        return "EXTERNAL_SUMMARY_ACCEPTED"
    if intake_status == "EXTERNAL_SUMMARY_PRESENT_INVALID":
        return "NEEDS_EXTERNAL_SUMMARY_CORRECTION"
    return "READY_TO_EXECUTE_WITH_EXTERNAL_STATE"


def check_template_common(errors: list[str], record_id: str, record: dict[str, Any]) -> dict[str, Any]:
    spec = EXPECTED_EXTERNAL_SUMMARIES[record_id]
    template = as_dict(record.get("summary_template"))
    require(errors, template.get("schema") == spec["schema"], f"{record_id}: template schema mismatch")
    require(errors, template.get("status") == "TEMPLATE_NOT_EVIDENCE", f"{record_id}: template must not be evidence")
    require(errors, template.get("template_only") is True, f"{record_id}: template_only must be true")
    boundary = as_dict(template.get("claim_boundary"))
    require(errors, boundary.get("real_malware_validation_claimed") is False, f"{record_id}: template must reject real malware validation")
    artifact_rows = row_map(as_list(template.get("evidence_artifacts")))
    required_kinds = REQUIRED_EVIDENCE_ARTIFACT_KINDS[record_id]
    kinds = {str(row.get("kind")) for row in artifact_rows.values() if isinstance(row.get("kind"), str)}
    extra_kinds = sorted(kinds - required_kinds)
    missing_kinds = sorted(required_kinds - kinds)
    require(errors, not missing_kinds, f"{record_id}: template missing evidence artifact kinds: {', '.join(missing_kinds)}")
    require(errors, not extra_kinds, f"{record_id}: template has unexpected evidence artifact kinds: {', '.join(extra_kinds)}")
    for row_id, row in artifact_rows.items():
        path_value = str(row.get("path") or "")
        require(errors, bool(path_value), f"{record_id}.{row_id}: template evidence artifact path required")
        require(
            errors,
            path_value.startswith(f"results/evaluation/genesys2-cva6/current/external_closure/{record_id}/"),
            f"{record_id}.{row_id}: template evidence artifact path must stay under record external_closure directory",
        )
        require(errors, bool(row.get("sha256")), f"{record_id}.{row_id}: template evidence artifact sha256 placeholder required")
    return template


def check_source_line_template(errors: list[str], record_id: str, template: dict[str, Any]) -> None:
    boundary = as_dict(template.get("claim_boundary"))
    require(errors, boundary.get("board_native_source_line_attribution_claimed") is True, f"{record_id}: board-native claim flag required")
    require(errors, boundary.get("sidecar_source_lines_substituted") is False, f"{record_id}: sidecar substitution must be false")
    aggregate = as_dict(template.get("aggregate"))
    require(errors, aggregate.get("sample_count") == len(ALL_CCFA_SAMPLES), f"{record_id}: template sample_count mismatch")
    require(errors, aggregate.get("unknown_key_events") == 0, f"{record_id}: unknown_key_events must be 0")
    require(errors, aggregate.get("unaccounted_drop") == 0, f"{record_id}: unaccounted_drop must be 0")
    samples = row_map(as_list(template.get("samples")))
    missing = sorted(set(ALL_CCFA_SAMPLES) - set(samples))
    require(errors, not missing, f"{record_id}: template missing samples: {', '.join(missing)}")
    for sample_id, row in samples.items():
        require(errors, "captured_elf_sha256" in row, f"{record_id}.{sample_id}: captured_elf_sha256 required")
        require(errors, row.get("debug_sections_present") is True, f"{record_id}.{sample_id}: debug sections required")
        require(errors, row.get("board_trace_source_line_available") is True, f"{record_id}.{sample_id}: board source-line flag required")


def check_pointer_template(errors: list[str], record_id: str, template: dict[str, Any]) -> None:
    boundary = as_dict(template.get("claim_boundary"))
    require(errors, boundary.get("hardware_full_pointer_strings_claimed") is True, f"{record_id}: hardware full-string claim flag required")
    require(errors, boundary.get("companion_strings_substituted_as_hardware") is False, f"{record_id}: companion substitution must be false")
    aggregate = as_dict(template.get("aggregate"))
    for key in ("full_string_claimed", "contiguous_from_offset_zero", "mem_last_observed"):
        require(errors, aggregate.get(key) is True, f"{record_id}: {key} must be true in template")
    require(errors, aggregate.get("kernel_fragment_count") == 0, f"{record_id}: kernel fragments must be 0")
    require(errors, bool(template.get("full_string_group_count")), f"{record_id}: full_string_group_count required")
    require(errors, bool(template.get("redaction_policy")), f"{record_id}: redaction_policy required")
    require(errors, isinstance(template.get("failed_attempts"), list), f"{record_id}: failed_attempts list required")
    pointer_groups = as_list(template.get("pointer_groups"))
    require(errors, bool(pointer_groups), f"{record_id}: pointer_groups required")
    for index, group in enumerate(pointer_groups, start=1):
        row = as_dict(group)
        require(errors, str(row.get("syscall_name") or "") in {"openat", "write", "execve"}, f"{record_id}.pointer_groups[{index}]: syscall_name invalid")
        require(errors, row.get("full_string_claimed") is True, f"{record_id}.pointer_groups[{index}]: full_string_claimed required")
        require(errors, row.get("contiguous_from_offset_zero") is True, f"{record_id}.pointer_groups[{index}]: contiguous_from_offset_zero required")
        require(errors, row.get("mem_last_observed") is True, f"{record_id}.pointer_groups[{index}]: mem_last_observed required")
    coverage = as_dict(template.get("syscall_coverage"))
    for syscall_name in ("openat", "write", "execve"):
        row = as_dict(coverage.get(syscall_name))
        require(errors, bool(row), f"{record_id}: missing {syscall_name} coverage")
        require(errors, row.get("gap_free") is True, f"{record_id}.{syscall_name}: gap_free required")
        require(errors, row.get("mem_last_observed") is True, f"{record_id}.{syscall_name}: mem_last required")


def check_streaming_template(errors: list[str], record_id: str, template: dict[str, Any]) -> None:
    boundary = as_dict(template.get("claim_boundary"))
    require(errors, boundary.get("production_streaming_dma_throughput_claimed") is True, f"{record_id}: throughput claim flag required")
    require(errors, boundary.get("bram_jtag_substituted_for_streaming") is False, f"{record_id}: BRAM/JTAG substitution must be false")
    for key in ("timing_passed", "noninterference_passed", "host_receiver_log_present", "resource_report_present", "failed_attempts_retained"):
        require(errors, template.get(key) is True, f"{record_id}: {key} required")
    require(errors, template.get("unaccounted_drop") == 0, f"{record_id}: unaccounted_drop must be 0")


def check_benign_template(errors: list[str], record_id: str, template: dict[str, Any]) -> None:
    boundary = as_dict(template.get("claim_boundary"))
    require(errors, boundary.get("genesys2_board_benign_control_claimed") is True, f"{record_id}: board benign claim flag required")
    require(errors, boundary.get("local_linux_benign_substituted") is False, f"{record_id}: local Linux substitution must be false")
    aggregate = as_dict(template.get("aggregate"))
    require(errors, aggregate.get("genesys2_board_trace_claimed") is True, f"{record_id}: board trace aggregate flag required")
    require(errors, aggregate.get("unexpected_false_positive_count") == 0, f"{record_id}: unexpected FP count must be 0")
    require(errors, aggregate.get("benign_false_positive_rate") == 0.0, f"{record_id}: benign FP rate must be 0.0")
    samples = row_map(as_list(template.get("samples")))
    require(errors, len(samples) >= 5, f"{record_id}: at least five benign template samples required")
    for sample_id, sample in samples.items():
        for key in ("semantic_events", "behavior_graph", "behavior_audit"):
            path_value = str(sample.get(key) or "")
            require(errors, bool(path_value), f"{record_id}.{sample_id}: {key} path required")
            require(
                errors,
                path_value.startswith(f"results/evaluation/genesys2-cva6/current/external_closure/{record_id}/{sample_id}/"),
                f"{record_id}.{sample_id}: {key} path must stay under record external_closure directory",
            )


def check_record_specific(errors: list[str], record_id: str, record: dict[str, Any]) -> None:
    template = check_template_common(errors, record_id, record)
    if record_id == "board_native_dwarf_source_lines":
        check_source_line_template(errors, record_id, template)
        commands = " ".join(as_list(record.get("collection_commands")))
        require(errors, "join_trace_code_map.py" in commands and "build_code_map.py" in commands, f"{record_id}: source-line join commands required")
    elif record_id == "full_hardware_pointer_strings":
        check_pointer_template(errors, record_id, template)
        commands = " ".join(as_list(record.get("collection_commands")))
        require(errors, "run_genesys2_pointer_snapshot_bram_capture.py" in commands, f"{record_id}: pointer capture command required")
        preflight_commands = " ".join(as_list(record.get("preflight_commands")))
        packaging_commands = " ".join(as_list(record.get("packaging_commands")))
        require(errors, "check_genesys2_pointer_string_readiness.py" in preflight_commands, f"{record_id}: pointer string readiness preflight required")
        require(errors, "package_genesys2_pointer_string_readiness.py" in packaging_commands, f"{record_id}: pointer string readiness packaging required")
        require(errors, "check_genesys2_pointer_string_readiness.py" in packaging_commands, f"{record_id}: pointer string readiness packaging check required")
    elif record_id == "production_streaming_dma_trace_sink":
        check_streaming_template(errors, record_id, template)
        commands = " ".join(as_list(record.get("collection_commands"))).lower()
        require(errors, "non-bram" in commands and "host receiver" in commands, f"{record_id}: non-BRAM host receiver collection required")
    elif record_id == "genesys2_board_benign_control":
        check_benign_template(errors, record_id, template)
        commands = " ".join(as_list(record.get("collection_commands"))).lower()
        require(errors, "genesys2/cva6" in commands and "benign" in commands, f"{record_id}: board benign collection required")


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.external_closure_plan.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(errors, "real_malware_validation" in as_list(data.get("objective_exclusions")), "real-malware exclusion missing")
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("plan_only") is True, "plan_only boundary required")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("external_execution_completed") is False, "plan must not claim external execution completed")
    source_rows = row_map(as_list(data.get("source_artifacts")))
    for source_id, schema in (
        ("external_closure_readiness", "rvmt.genesys2.external_closure_readiness.v1"),
        ("external_closure_intake", "rvmt.genesys2.external_closure_intake.v1"),
    ):
        row = source_rows.get(source_id)
        require(errors, row is not None, f"source artifact missing: {source_id}")
        if row is None:
            continue
        require(errors, row.get("schema") == schema, f"{source_id}: source schema mismatch")
        require(errors, row.get("expected_schema") == schema, f"{source_id}: expected source schema mismatch")
        require(errors, row.get("exists") is True, f"{source_id}: exists flag must be true")
        path = row.get("path")
        require(errors, bool(path), f"{source_id}: source path missing")
        if path:
            source_path = repo_path(root, path)
            require(errors, source_path.is_file(), f"{source_id}: source file missing: {path}")
            if source_path.is_file():
                require(errors, row.get("sha256") == sha256_file(source_path), f"{source_id}: source sha256 mismatch")
    records = row_map(as_list(data.get("records")))
    expected_ids = set(EXPECTED_EXTERNAL_SUMMARIES)
    missing = sorted(expected_ids - set(records))
    extra = sorted(set(records) - expected_ids)
    require(errors, not missing, f"missing records: {', '.join(missing)}")
    require(errors, not extra, f"unexpected records: {', '.join(extra)}")
    for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
        record = records.get(record_id)
        if not record:
            continue
        require(errors, record.get("required_summary_schema") == spec["schema"], f"{record_id}: required schema mismatch")
        require(errors, record.get("external_summary_path") == spec["path"].as_posix(), f"{record_id}: external summary path mismatch")
        intake_status = str(record.get("intake_completion_status") or "")
        require(errors, record.get("plan_status") == expected_plan_status(intake_status), f"{record_id}: plan status mismatch")
        require(errors, len(as_list(record.get("operator_inputs"))) >= 3, f"{record_id}: operator inputs under-specified")
        require(errors, len(as_list(record.get("required_raw_artifacts"))) >= 4, f"{record_id}: raw artifacts under-specified")
        require(errors, len(as_list(record.get("acceptance_criteria"))) >= 4, f"{record_id}: acceptance criteria under-specified")
        require(errors, len(as_list(record.get("preflight_commands"))) >= 2, f"{record_id}: preflight commands under-specified")
        require(errors, len(as_list(record.get("collection_commands"))) >= 2, f"{record_id}: collection commands under-specified")
        require(errors, len(as_list(record.get("packaging_commands"))) >= 2, f"{record_id}: packaging commands under-specified")
        packaging = " ".join(str(item) for item in as_list(record.get("packaging_commands")))
        require(errors, "tools/prepare_genesys2_external_summary.py" in packaging, f"{record_id}: external summary preparation command missing")
        require(errors, f"--record-id {record_id}" in packaging, f"{record_id}: external summary preparation record id missing")
        require(errors, "--write-template" in packaging, f"{record_id}: external summary template export command missing")
        require(errors, "external_closure_templates" in packaging, f"{record_id}: template export must stay outside the intake evidence directory")
        require(errors, "--summary <candidate-" in packaging, f"{record_id}: candidate summary pre-validation command missing")
        validation = " ".join(str(item) for item in as_list(record.get("validation_commands")))
        require(errors, "check_genesys2_external_closure_intake.py --root ." in validation, f"{record_id}: intake validation command missing")
        require(errors, "check_genesys2_external_closure_intake.py --root ." in str(record.get("acceptance_gate") or ""), f"{record_id}: acceptance gate mismatch")
        no_sub = str(record.get("no_substitution_rule") or "")
        require(errors, text_has_all(no_sub, ["must not", "substitut"]), f"{record_id}: no-substitution rule too weak")
        exits = " ".join(str(item) for item in as_list(record.get("exit_criteria")))
        require(errors, "EXTERNAL_SUMMARY_ACCEPTED" in exits and "completion_evidence_valid=true" in exits, f"{record_id}: exit criteria incomplete")
        check_record_specific(errors, record_id, record)
    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_external_closure_plan.py" in commands, "plan packager command missing")
    require(errors, "tools/check_genesys2_external_closure_plan.py --root ." in commands, "plan checker command missing")
    require(errors, "tools/prepare_genesys2_external_summary.py --self-test" in commands, "external summary preparation self-test command missing")
    interpretation = " ".join(str(item).lower() for item in as_list(data.get("interpretation")))
    require(errors, "templates are not evidence" in interpretation, "interpretation must say templates are not evidence")
    require(errors, "does not close" in interpretation, "interpretation must avoid closure overclaim")
    return errors


def self_test() -> int:
    from package_genesys2_external_closure_plan import package_plan

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / "results/evaluation/genesys2-cva6/current"
        current.mkdir(parents=True, exist_ok=True)
        readiness_records = []
        intake_records = []
        for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
            readiness_records.append(
                {
                    "id": record_id,
                    "readiness_status": "fixture",
                    "required_external_artifacts": ["one", "two", "three", "four"],
                    "acceptance_criteria": ["one", "two", "three", "four"],
                    "no_substitution_rule": "fixture must not be substituted for external evidence",
                }
            )
            intake_records.append(
                {
                    "id": record_id,
                    "completion_status": "OPEN_NO_EXTERNAL_SUMMARY",
                    "current_blocker": True,
                    "external_summary_path": spec["path"].as_posix(),
                }
            )
        write_json(current / "external_closure_readiness.json", {"schema": "rvmt.genesys2.external_closure_readiness.v1", "status": "PASS", "records": readiness_records})
        write_json(
            current / "external_closure_intake.json",
            {
                "schema": "rvmt.genesys2.external_closure_intake.v1",
                "status": "PASS",
                "closure_status": "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
                "records": intake_records,
            },
        )
        plan = package_plan(root, Path("results/evaluation/genesys2-cva6/current"))
        errors = check_summary(plan, root)
        if errors:
            print("[FAIL] external closure plan good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        plan["records"][0]["summary_template"]["status"] = "PASS"
        errors = check_summary(plan, root)
        if not errors:
            print("[FAIL] external closure plan bad fixture passed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 external closure plan checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the executable plan for remaining non-real-malware Genesys2/CVA6 external blockers.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing external closure plan summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] external closure plan checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] external closure plan is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] external closure plan accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
