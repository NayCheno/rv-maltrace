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

from check_genesys2_external_closure_intake import EXPECTED_EXTERNAL_SUMMARIES


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/external_closure_preflight.json")
NOT_APPLICABLE = "NOT_APPLICABLE"
NOT_REQUESTED = "NOT_REQUESTED"


def row_map(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def path_map(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("path")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("path"), str) and row.get("path")
    }


def check_command_rows(errors: list[str], root: Path, record_id: str, rows: list[Any], require_local_tool: bool) -> None:
    require(errors, bool(rows), f"{record_id}: command rows missing")
    saw_local_tool = False
    for index, raw_row in enumerate(rows):
        row = as_dict(raw_row)
        prefix = f"{record_id}: command[{index}]: "
        kind = row.get("kind")
        require(errors, kind in {"local_tool", "external_operator_action", "operator_collection_instruction", "summary_packaging_instruction"}, prefix + "unexpected kind")
        require(errors, row.get("local_preflight_ready") is True, prefix + "local_preflight_ready must be true")
        command = str(row.get("command") or "")
        require(errors, bool(command), prefix + "command required")
        require(errors, isinstance(row.get("script"), str) and bool(row.get("script")), prefix + "script marker required")
        require(errors, isinstance(row.get("script_exists"), bool), prefix + "script_exists marker required")
        require(errors, row.get("dry_run_supported") in {True, False, NOT_REQUESTED}, prefix + "dry_run_supported marker required")
        require(errors, row.get("code_map_supported") in {True, False, NOT_REQUESTED}, prefix + "code_map_supported marker required")
        if kind == "local_tool":
            saw_local_tool = True
            script = str(row.get("script") or "")
            require(errors, script.startswith("tools/") and script.endswith(".py"), prefix + "script path required")
            script_path = repo_path(root, script)
            require(errors, script_path.suffix == ".py", prefix + "script suffix mismatch")
            require(errors, row.get("script_exists") is True, prefix + "script must exist")
            require(errors, script_path.is_file(), prefix + f"script file missing under root: {script}")
            if "--dry-run" in command:
                require(errors, row.get("dry_run_supported") is True, prefix + "dry-run support required")
            else:
                require(errors, row.get("dry_run_supported") == NOT_REQUESTED, prefix + "dry-run support must be NOT_REQUESTED")
            if "--code-map" in command:
                require(errors, row.get("code_map_supported") is True, prefix + "code-map support required")
            else:
                require(errors, row.get("code_map_supported") == NOT_REQUESTED, prefix + "code-map support must be NOT_REQUESTED")
        else:
            require(errors, row.get("script") == NOT_APPLICABLE, prefix + "operator row script marker must be NOT_APPLICABLE")
            require(errors, row.get("script_exists") is False, prefix + "operator row script_exists must be false")
            require(errors, row.get("dry_run_supported") == NOT_REQUESTED, prefix + "operator row dry-run marker must be NOT_REQUESTED")
            require(errors, row.get("code_map_supported") == NOT_REQUESTED, prefix + "operator row code-map marker must be NOT_REQUESTED")
            notes = " ".join(str(item).lower() for item in as_list(row.get("notes")))
            require(errors, "external" in notes or "collection" in notes or "packaging" in notes, prefix + "operator note required")
    if require_local_tool:
        require(errors, saw_local_tool, f"{record_id}: at least one local tool preflight command required")


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.external_closure_preflight.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(errors, "real_malware_validation" in as_list(data.get("objective_exclusions")), "real-malware objective exclusion missing")
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("local_preflight_only") is True, "local preflight boundary missing")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("board_native_source_line_attribution_claimed") is False, "board-native source-line evidence must not be claimed")
    require(errors, boundary.get("hardware_full_pointer_strings_claimed") is False, "full hardware pointer strings must not be claimed")
    require(errors, boundary.get("production_streaming_dma_throughput_claimed") is False, "streaming/DMA throughput must not be claimed")
    require(errors, boundary.get("genesys2_board_benign_control_claimed") is False, "Genesys2 board benign-control evidence must not be claimed")

    sources = path_map(as_list(data.get("source_artifacts")))
    for required_path in (
        "results/evaluation/genesys2-cva6/current/external_closure_plan.json",
        "results/evaluation/genesys2-cva6/current/external_closure_intake.json",
    ):
        row = sources.get(required_path)
        require(errors, bool(row), f"source artifact missing: {required_path}")
        if row:
            expected_schema = (
                "rvmt.genesys2.external_closure_plan.v1"
                if required_path.endswith("external_closure_plan.json")
                else "rvmt.genesys2.external_closure_intake.v1"
            )
            require(errors, row.get("exists") is True, f"{required_path}: source must exist")
            require(errors, row.get("expected_schema") == expected_schema, f"{required_path}: expected schema mismatch")
            require(errors, row.get("schema") == expected_schema, f"{required_path}: source schema mismatch")
            allowed_statuses = {"PASS", "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED"} if required_path.endswith("external_closure_intake.json") else {"PASS"}
            require(errors, row.get("status") in allowed_statuses, f"{required_path}: source status mismatch")
            path = repo_path(root, required_path)
            require(errors, path.is_file(), f"{required_path}: source file missing")
            if path.is_file():
                require(errors, row.get("sha256") == sha256_file(path), f"{required_path}: source sha256 mismatch")

    records = row_map(as_list(data.get("records")))
    expected_ids = set(EXPECTED_EXTERNAL_SUMMARIES)
    missing = sorted(expected_ids - set(records))
    extra = sorted(set(records) - expected_ids)
    require(errors, not missing, f"missing records: {', '.join(missing)}")
    require(errors, not extra, f"unexpected records: {', '.join(extra)}")
    open_count = accepted_count = invalid_count = 0
    for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
        record = records.get(record_id)
        if not record:
            continue
        prefix = f"{record_id}: "
        require(errors, record.get("status") == "PASS_LOCAL_PREFLIGHT_EXTERNAL_OPEN", prefix + "status mismatch")
        require(errors, record.get("required_summary_schema") == spec["schema"], prefix + "schema mismatch")
        require(errors, record.get("external_summary_path") == spec["path"].as_posix(), prefix + "external summary path mismatch")
        require(errors, record.get("schema_path_ready") is True, prefix + "schema/path readiness required")
        require(errors, record.get("tool_entrypoints_ready") is True, prefix + "tool entrypoints must be ready")
        require(errors, record.get("no_substitution_rule_present") is True, prefix + "no-substitution rule missing")
        require(errors, int(record.get("operator_input_count") or 0) > 0, prefix + "operator inputs required")
        require(errors, int(record.get("required_raw_artifact_count") or 0) > 0, prefix + "required raw artifact list required")
        require(errors, int(record.get("acceptance_criteria_count") or 0) > 0, prefix + "acceptance criteria required")
        require(errors, record.get("local_preflight_ready") is True, prefix + "local preflight must be ready")
        completion_status = record.get("completion_status")
        if completion_status == "EXTERNAL_SUMMARY_ACCEPTED":
            accepted_count += 1
            require(errors, record.get("current_blocker") is False, prefix + "accepted summary should clear blocker")
            require(errors, record.get("external_execution_still_required") is False, prefix + "accepted summary should not require more external execution")
        elif completion_status == "EXTERNAL_SUMMARY_PRESENT_INVALID":
            invalid_count += 1
            require(errors, record.get("current_blocker") is True, prefix + "invalid summary remains blocked")
            require(errors, record.get("external_execution_still_required") is True, prefix + "invalid summary requires external correction")
        else:
            open_count += 1
            require(errors, completion_status == "OPEN_NO_EXTERNAL_SUMMARY", prefix + "unexpected completion status")
            require(errors, record.get("current_blocker") is True, prefix + "missing summary remains blocked")
            require(errors, record.get("external_execution_still_required") is True, prefix + "missing summary requires external execution")
        check_command_rows(errors, root, record_id, as_list(record.get("preflight_commands")), require_local_tool=True)
        check_command_rows(errors, root, record_id, as_list(record.get("collection_commands")), require_local_tool=False)
        check_command_rows(errors, root, record_id, as_list(record.get("packaging_commands")), require_local_tool=False)
    require(errors, data.get("open_external_blocker_count") == open_count, "open count mismatch")
    require(errors, data.get("accepted_external_blocker_count") == accepted_count, "accepted count mismatch")
    require(errors, data.get("invalid_external_blocker_count") == invalid_count, "invalid count mismatch")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_external_closure_preflight.py" in commands, "preflight packager command missing")
    require(errors, "tools/check_genesys2_external_closure_preflight.py --root ." in commands, "preflight checker command missing")
    require(errors, "tools/check_genesys2_external_closure_plan.py --root ." in commands, "plan checker command missing")
    require(errors, "tools/check_genesys2_external_closure_intake.py --root ." in commands, "intake checker command missing")
    interpretation = " ".join(str(item).lower() for item in as_list(data.get("interpretation")))
    require(errors, "does not execute board" in interpretation, "interpretation must preserve external execution boundary")
    require(errors, "must not close external blockers" in interpretation, "interpretation must reject preflight-as-completion")
    require(errors, "intake gate remains authoritative" in interpretation, "interpretation must preserve intake authority")
    return errors


def self_test() -> int:
    from package_genesys2_external_closure_preflight import DEFAULT_CURRENT_ROOT, package_preflight, write_json as package_write_json

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        for script in ("tools/check_fixture.py", "tools/run_fixture.py"):
            path = root / script
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("parser.add_argument('--dry-run')\n", encoding="utf-8")
        plan_records = []
        intake_records = []
        for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
            plan_records.append(
                {
                    "id": record_id,
                    "required_summary_schema": spec["schema"],
                    "operator_inputs": ["board"],
                    "required_raw_artifacts": ["raw"],
                    "acceptance_criteria": ["criterion"],
                    "no_substitution_rule": "fixtures must not be substituted for external evidence",
                    "preflight_commands": ["uv run python tools/check_fixture.py --root .", "uv run python tools/run_fixture.py --dry-run"],
                    "collection_commands": ["external: run board"],
                    "packaging_commands": [f"write {spec['path'].as_posix()} from external artifacts"],
                }
            )
            intake_records.append(
                {
                    "id": record_id,
                    "completion_status": "OPEN_NO_EXTERNAL_SUMMARY",
                    "current_blocker": True,
                    "external_summary_path": spec["path"].as_posix(),
                    "required_summary_schema": spec["schema"],
                }
            )
        package_write_json(current / "external_closure_plan.json", {"schema": "rvmt.genesys2.external_closure_plan.v1", "status": "PASS", "records": plan_records})
        package_write_json(
            current / "external_closure_intake.json",
            {
                "schema": "rvmt.genesys2.external_closure_intake.v1",
                "status": "PASS",
                "closure_status": "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
                "open_external_blocker_count": 4,
                "accepted_external_blocker_count": 0,
                "invalid_external_blocker_count": 0,
                "records": intake_records,
            },
        )
        summary = package_preflight(root, DEFAULT_CURRENT_ROOT)
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] external closure preflight good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["records"][0]["preflight_commands"][0]["dry_run_supported"] = None
        errors = check_summary(summary, root)
        if not any("dry_run_supported marker required" in error for error in errors):
            print("[FAIL] external closure preflight null capability marker fixture passed", file=sys.stderr)
            return 1
        summary["records"][0]["preflight_commands"][0]["dry_run_supported"] = NOT_REQUESTED
        summary["claim_boundary"]["hardware_full_pointer_strings_claimed"] = True
        errors = check_summary(summary, root)
        if not errors:
            print("[FAIL] external closure preflight bad fixture passed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 external closure preflight checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check local preflight readiness for remaining non-real-malware Genesys2/CVA6 external blockers.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing external closure preflight summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] external closure preflight checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] external closure preflight is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] external closure preflight accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
