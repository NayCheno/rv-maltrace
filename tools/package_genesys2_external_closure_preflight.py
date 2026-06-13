from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from check_genesys2_external_closure_intake import EXPECTED_EXTERNAL_SUMMARIES


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_PLAN = DEFAULT_CURRENT_ROOT / "external_closure_plan.json"
DEFAULT_INTAKE = DEFAULT_CURRENT_ROOT / "external_closure_intake.json"
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "external_closure_preflight.json"
NOT_APPLICABLE = "NOT_APPLICABLE"
NOT_REQUESTED = "NOT_REQUESTED"

PY_TOOL = re.compile(r"tools/[A-Za-z0-9_./-]+\.py")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def repo_path(root: Path, value: Path) -> Path:
    return value if value.is_absolute() else root / value


def repo_rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def rows_by_id(rows: Any) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in as_list(rows)
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def script_from_command(command: str) -> str | None:
    match = PY_TOOL.search(command)
    return match.group(0) if match else None


def command_row(root: Path, command: str) -> dict[str, Any]:
    script = script_from_command(command)
    row: dict[str, Any] = {
        "command": command,
        "script": script or NOT_APPLICABLE,
        "script_exists": False,
        "dry_run_supported": NOT_REQUESTED,
        "code_map_supported": NOT_REQUESTED,
        "local_preflight_ready": True,
        "notes": [],
    }
    if command.startswith("external:"):
        row["kind"] = "external_operator_action"
        row["local_preflight_ready"] = True
        row["notes"].append("external action; cannot be executed by local preflight")
        return row
    if command.startswith("collect ") or command.startswith("retain "):
        row["kind"] = "operator_collection_instruction"
        row["local_preflight_ready"] = True
        row["notes"].append("collection instruction; validated by external summary intake")
        return row
    if command.startswith("write "):
        row["kind"] = "summary_packaging_instruction"
        row["local_preflight_ready"] = True
        row["notes"].append("packaging instruction; target path is validated by intake")
        return row
    if not script:
        row["kind"] = "unknown"
        row["local_preflight_ready"] = False
        row["notes"].append("no local tool path found")
        return row
    script_path = root / script
    row["kind"] = "local_tool"
    row["script_exists"] = script_path.is_file()
    text = script_path.read_text(encoding="utf-8", errors="ignore") if script_path.is_file() else ""
    if "--dry-run" in command:
        row["dry_run_supported"] = "--dry-run" in text
        if row["dry_run_supported"] is not True:
            row["local_preflight_ready"] = False
            row["notes"].append("--dry-run command lacks parser support in script")
    if "--code-map" in command:
        row["code_map_supported"] = "--code-map" in text
        if row["code_map_supported"] is not True:
            row["local_preflight_ready"] = False
            row["notes"].append("--code-map command lacks parser support in script")
    if row["script_exists"] is not True:
        row["local_preflight_ready"] = False
        row["notes"].append("script missing")
    if row["local_preflight_ready"] is True:
        row["notes"].append("local tool entrypoint is present")
    return row


def artifact_status(root: Path, path_value: str, expected_schema: str) -> dict[str, Any]:
    path = root / path_value
    row: dict[str, Any] = {
        "path": path_value,
        "exists": path.is_file(),
        "sha256": sha256_file(path),
        "schema": None,
        "expected_schema": expected_schema,
        "status": None,
    }
    if path.is_file():
        try:
            data = load_json(path)
        except Exception as exc:
            row["status"] = "INVALID_JSON"
            row["error"] = str(exc)
        else:
            row["schema"] = data.get("schema")
            row["status"] = data.get("status")
    return row


def record_preflight(root: Path, record_id: str, plan_record: dict[str, Any], intake_record: dict[str, Any]) -> dict[str, Any]:
    spec = EXPECTED_EXTERNAL_SUMMARIES[record_id]
    preflight_commands = [str(item) for item in as_list(plan_record.get("preflight_commands"))]
    collection_commands = [str(item) for item in as_list(plan_record.get("collection_commands"))]
    packaging_commands = [str(item) for item in as_list(plan_record.get("packaging_commands"))]
    command_rows = [command_row(root, command) for command in [*preflight_commands, *collection_commands, *packaging_commands]]
    summary_path = str(intake_record.get("external_summary_path") or "")
    summary_exists = (root / summary_path).is_file() if summary_path else False
    expected_path = spec["path"].as_posix()
    expected_schema = str(spec["schema"])
    tool_ready = all(row.get("local_preflight_ready") is True for row in command_rows)
    no_substitution_rule = str(plan_record.get("no_substitution_rule") or "")
    schema_path_ready = (
        plan_record.get("required_summary_schema") == expected_schema
        and intake_record.get("required_summary_schema") == expected_schema
        and summary_path == expected_path
    )
    return {
        "id": record_id,
        "status": "PASS_LOCAL_PREFLIGHT_EXTERNAL_OPEN" if tool_ready and schema_path_ready else "FAIL",
        "completion_status": intake_record.get("completion_status"),
        "current_blocker": intake_record.get("current_blocker"),
        "external_summary_path": summary_path,
        "external_summary_exists": summary_exists,
        "required_summary_schema": expected_schema,
        "schema_path_ready": schema_path_ready,
        "tool_entrypoints_ready": tool_ready,
        "no_substitution_rule_present": "must not" in no_substitution_rule.lower() and "substitut" in no_substitution_rule.lower(),
        "operator_input_count": len(as_list(plan_record.get("operator_inputs"))),
        "required_raw_artifact_count": len(as_list(plan_record.get("required_raw_artifacts"))),
        "acceptance_criteria_count": len(as_list(plan_record.get("acceptance_criteria"))),
        "preflight_commands": [command_row(root, command) for command in preflight_commands],
        "collection_commands": [command_row(root, command) for command in collection_commands],
        "packaging_commands": [command_row(root, command) for command in packaging_commands],
        "local_preflight_ready": tool_ready and schema_path_ready,
        "external_execution_still_required": intake_record.get("completion_status") != "EXTERNAL_SUMMARY_ACCEPTED",
    }


def package_preflight(root: Path, current_root: Path) -> dict[str, Any]:
    plan_path = repo_path(root, current_root / "external_closure_plan.json")
    intake_path = repo_path(root, current_root / "external_closure_intake.json")
    plan = load_json(plan_path)
    intake = load_json(intake_path)
    plan_records = rows_by_id(plan.get("records"))
    intake_records = rows_by_id(intake.get("records"))
    records = [
        record_preflight(root, record_id, plan_records.get(record_id, {}), intake_records.get(record_id, {}))
        for record_id in EXPECTED_EXTERNAL_SUMMARIES
    ]
    status = "PASS"
    if plan.get("status") != "PASS" or intake.get("status") != "PASS":
        status = "FAIL"
    if any(row.get("local_preflight_ready") is not True for row in records):
        status = "FAIL"
    if any(row.get("no_substitution_rule_present") is not True for row in records):
        status = "FAIL"
    return {
        "schema": "rvmt.genesys2.external_closure_preflight.v1",
        "status": status,
        "canonical_evaluation_root": repo_rel(repo_path(root, current_root), root),
        "scope": "local preflight for remaining non-real-malware external closure blockers",
        "objective_exclusions": ["real_malware_validation"],
        "claim_boundary": {
            "local_preflight_only": True,
            "external_execution_completed": intake.get("closure_status") == "ALL_NON_REAL_EXTERNAL_SUMMARIES_ACCEPTED",
            "all_non_real_external_blockers_closed": intake.get("closure_status") == "ALL_NON_REAL_EXTERNAL_SUMMARIES_ACCEPTED",
            "real_malware_validation_claimed": False,
            "board_native_source_line_attribution_claimed": False,
            "hardware_full_pointer_strings_claimed": False,
            "production_streaming_dma_throughput_claimed": False,
            "genesys2_board_benign_control_claimed": False,
        },
        "source_artifacts": [
            artifact_status(root, repo_rel(plan_path, root), "rvmt.genesys2.external_closure_plan.v1"),
            artifact_status(root, repo_rel(intake_path, root), "rvmt.genesys2.external_closure_intake.v1"),
        ],
        "open_external_blocker_count": intake.get("open_external_blocker_count"),
        "accepted_external_blocker_count": intake.get("accepted_external_blocker_count"),
        "invalid_external_blocker_count": intake.get("invalid_external_blocker_count"),
        "records": records,
        "validation_commands": [
            "uv run python tools/package_genesys2_external_closure_preflight.py",
            "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
            "uv run python tools/check_genesys2_external_closure_plan.py --root .",
            "uv run python tools/check_genesys2_external_closure_intake.py --root .",
        ],
        "interpretation": [
            "This preflight proves only local scripts, dry-run hooks, schemas, paths, and no-substitution guardrails are ready.",
            "It does not execute board, RTL, host receiver, or reviewer work and must not close external blockers by itself.",
            "The intake gate remains authoritative for accepting any future external summaries.",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        for script in (
            "tools/check_fixture.py",
            "tools/run_fixture.py",
            "tools/build_fixture.py",
            "tools/package_genesys2_external_closure_preflight.py",
            "tools/check_genesys2_external_closure_preflight.py",
        ):
            path = root / script
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("parser.add_argument('--dry-run')\nparser.add_argument('--code-map')\n", encoding="utf-8")
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
                    "preflight_commands": [
                        "uv run python tools/check_fixture.py --root .",
                        "uv run python tools/run_fixture.py --dry-run",
                        "uv run python tools/build_fixture.py --code-map",
                    ],
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
        write_json(current / "external_closure_plan.json", {"schema": "rvmt.genesys2.external_closure_plan.v1", "status": "PASS", "records": plan_records})
        write_json(
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
        preflight = package_preflight(root, DEFAULT_CURRENT_ROOT)
        if preflight.get("status") != "PASS":
            print("[FAIL] external closure preflight fixture failed", file=sys.stderr)
            print(json.dumps(preflight, indent=2), file=sys.stderr)
            return 1
        (root / "tools/run_fixture.py").write_text("parser.add_argument('--other')\n", encoding="utf-8")
        preflight = package_preflight(root, DEFAULT_CURRENT_ROOT)
        if preflight.get("status") == "PASS":
            print("[FAIL] preflight fixture passed without dry-run support", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 external closure preflight packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package local preflight readiness for remaining non-real-malware Genesys2/CVA6 external blockers.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    out = repo_path(root, args.out)
    try:
        preflight = package_preflight(root, args.current_root)
        write_json(out, preflight)
    except Exception as exc:
        print(f"package_genesys2_external_closure_preflight: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{preflight['status']}] wrote Genesys2 external closure preflight to {out}")
    return 0 if preflight["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
