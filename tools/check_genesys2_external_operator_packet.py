from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from check_genesys2_external_closure_intake import EXPECTED_EXTERNAL_SUMMARIES, REQUIRED_EVIDENCE_ARTIFACT_KINDS


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/external_operator_packet.json")
DEFAULT_REPORT = Path("docs/07-evaluation-evidence/reports/ccfa_external_operator_packet.md")
VALID_INTAKE_CLOSURE_STATUSES = {
    "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
    "ALL_NON_REAL_EXTERNAL_SUMMARIES_ACCEPTED",
}
NON_CLOSURE_SOURCE_IDS = {
    "external_closure_readiness",
    "external_closure_plan",
    "external_closure_preflight",
}


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


def row_map(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def source_rows_ok(errors: list[str], data: dict[str, Any], root: Path) -> None:
    sources = as_dict(data.get("source_artifacts"))
    expected = {
        "external_closure_readiness": "rvmt.genesys2.external_closure_readiness.v1",
        "external_closure_intake": "rvmt.genesys2.external_closure_intake.v1",
        "external_closure_plan": "rvmt.genesys2.external_closure_plan.v1",
        "external_closure_preflight": "rvmt.genesys2.external_closure_preflight.v1",
    }
    require(errors, set(sources) == set(expected), "source artifact set mismatch")
    for source_id, schema in expected.items():
        row = as_dict(sources.get(source_id))
        require(errors, row.get("schema") == schema, f"{source_id}: schema mismatch")
        require(errors, row.get("expected_schema") == schema, f"{source_id}: expected_schema mismatch")
        allowed_statuses = {"PASS", "FAIL"} if source_id == "external_closure_intake" else {"PASS"}
        require(errors, row.get("status") in allowed_statuses, f"{source_id}: status mismatch")
        closure_status = row.get("closure_status")
        require(errors, isinstance(closure_status, str) and bool(closure_status), f"{source_id}: closure_status missing")
        if source_id == "external_closure_intake":
            require(errors, closure_status == data.get("closure_status"), f"{source_id}: closure_status must match packet closure_status")
            require(errors, closure_status in VALID_INTAKE_CLOSURE_STATUSES, f"{source_id}: closure_status invalid")
        if source_id in NON_CLOSURE_SOURCE_IDS:
            require(errors, closure_status == "NOT_APPLICABLE", f"{source_id}: closure_status must be NOT_APPLICABLE")
        path_value = row.get("path")
        require(errors, bool(path_value), f"{source_id}: path missing")
        if path_value:
            path = repo_path(root, path_value)
            require(errors, row.get("exists") is True, f"{source_id}: exists flag must be true")
            require(errors, path.is_file(), f"{source_id}: file missing: {path_value}")
            if path.is_file():
                require(errors, row.get("sha256") == sha256_file(path), f"{source_id}: sha256 mismatch")


def expected_template_path(record_id: str) -> str:
    summary_path = EXPECTED_EXTERNAL_SUMMARIES[record_id]["path"]
    return (summary_path.parent.parent / "external_closure_templates" / f"{summary_path.stem}.template.json").as_posix()


def check_record(errors: list[str], root: Path, record_id: str, record: dict[str, Any]) -> None:
    spec = EXPECTED_EXTERNAL_SUMMARIES[record_id]
    require(errors, record.get("required_summary_schema") == spec["schema"], f"{record_id}: required schema mismatch")
    require(errors, record.get("external_summary_path") == spec["path"].as_posix(), f"{record_id}: summary path mismatch")
    template_path = expected_template_path(record_id)
    require(errors, record.get("template_path") == template_path, f"{record_id}: template path mismatch")
    require(errors, repo_path(root, template_path).is_file(), f"{record_id}: template file missing")
    require(errors, record.get("intake_completion_status") in {"OPEN_NO_EXTERNAL_SUMMARY", "EXTERNAL_SUMMARY_PRESENT_INVALID", "EXTERNAL_SUMMARY_ACCEPTED"}, f"{record_id}: intake status invalid")
    require(errors, record.get("completion_requires_external_state") is True or record.get("intake_completion_status") == "EXTERNAL_SUMMARY_ACCEPTED", f"{record_id}: external state requirement missing")
    if record.get("intake_completion_status") != "EXTERNAL_SUMMARY_ACCEPTED":
        require(errors, record.get("completion_evidence_valid") is False, f"{record_id}: open external evidence must not be valid")
    required_kinds = set(REQUIRED_EVIDENCE_ARTIFACT_KINDS[record_id])
    kinds = set(str(item) for item in as_list(record.get("required_evidence_artifact_kinds")))
    require(errors, kinds == required_kinds, f"{record_id}: evidence artifact kinds mismatch")
    require(errors, len(as_list(record.get("operator_inputs"))) >= 3, f"{record_id}: operator inputs under-specified")
    require(errors, len(as_list(record.get("required_raw_artifacts"))) >= 4, f"{record_id}: raw artifacts under-specified")
    require(errors, len(as_list(record.get("acceptance_criteria"))) >= 4, f"{record_id}: acceptance criteria under-specified")
    no_sub = str(record.get("no_substitution_rule") or "").lower()
    require(errors, "must not" in no_sub and "substitut" in no_sub, f"{record_id}: no-substitution rule too weak")
    notes = " ".join(str(item).lower() for item in as_list(record.get("operator_notes")))
    for token in ("template-only", "external_closure", "record-specific", "sha256", "no template placeholders", "intake checker"):
        require(errors, token in notes, f"{record_id}: operator notes missing {token}")
    steps = {
        str(row.get("phase")): row
        for row in as_list(record.get("execution_steps"))
        if isinstance(row, dict) and isinstance(row.get("phase"), str) and row.get("phase")
    }
    require(errors, {"local_preflight", "external_collection", "candidate_summary_packaging", "intake_acceptance"} <= set(steps), f"{record_id}: execution steps incomplete")
    for phase, row in steps.items():
        require(errors, bool(as_list(row.get("commands"))), f"{record_id}.{phase}: commands required")
    packaging = " ".join(str(item) for item in as_list(steps.get("candidate_summary_packaging", {}).get("commands")))
    require(errors, "prepare_genesys2_external_summary.py" in packaging, f"{record_id}: candidate summary helper missing")
    require(errors, f"--record-id {record_id}" in packaging, f"{record_id}: candidate summary record id missing")
    intake = " ".join(str(item) for item in as_list(steps.get("intake_acceptance", {}).get("commands")))
    require(errors, "check_genesys2_external_closure_intake.py" in intake, f"{record_id}: intake checker missing")
    exits = " ".join(str(item) for item in as_list(record.get("exit_criteria")))
    require(errors, "EXTERNAL_SUMMARY_ACCEPTED" in exits, f"{record_id}: accepted exit criterion missing")


def check_summary(data: dict[str, Any], root: Path, report: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.external_operator_packet.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("closure_status") in VALID_INTAKE_CLOSURE_STATUSES, "closure_status invalid")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(errors, "real_malware_validation" in as_list(data.get("objective_exclusions")), "real malware exclusion missing")
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("operator_packet_only") is True, "operator_packet_only boundary required")
    require(errors, boundary.get("external_execution_completed") is False, "external execution must not be claimed")
    require(errors, boundary.get("external_readiness_substituted_for_completion") is False, "readiness must not be substituted")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("templates_treated_as_evidence") is False, "templates must not be evidence")
    require(errors, boundary.get("external_artifact_paths_scoped_to_external_closure") is True, "external artifacts must be scoped to external_closure")
    require(errors, boundary.get("external_artifact_paths_record_scoped") is True, "external artifacts must be scoped to each record directory")
    require(errors, boundary.get("placeholder_values_treated_as_invalid") is True, "placeholder values must be invalid")
    source_rows_ok(errors, data, root)
    records = row_map(as_list(data.get("records")))
    expected_ids = set(EXPECTED_EXTERNAL_SUMMARIES)
    require(errors, set(records) == expected_ids, "external record set mismatch")
    orders = [record.get("order") for record in records.values()]
    require(errors, sorted(orders) == list(range(1, len(expected_ids) + 1)), "record order must be dense")
    for record_id, record in records.items():
        check_record(errors, root, record_id, record)
    sequence = " ".join(str(item).lower() for item in as_list(data.get("operator_sequence")))
    for token in ("local preflight", "board", "candidate summaries", "record-specific external_closure artifacts", "sha256", "template placeholders", "intake", "full reproduction"):
        require(errors, token in sequence, f"operator sequence missing {token}")
    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_external_operator_packet.py" in commands, "packager command missing")
    require(errors, "tools/check_genesys2_external_operator_packet.py --root ." in commands, "checker command missing")
    require(errors, "tools/check_genesys2_external_closure_intake.py --root ." in commands, "intake checker command missing")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    for token in (
        "does not itself create board-native dwarf source-line attribution evidence",
        "does not itself create full hardware pointer-string reconstruction evidence",
        "does not complete production streaming/dma throughput evidence",
        "does not itself create genesys2 board benign-control evidence",
        "does not add real-malware validation",
    ):
        require(errors, token in non_claims, f"non-claim missing: {token}")
    report_path = repo_path(root, report)
    require(errors, report_path.is_file(), f"operator packet report missing: {report}")
    if report_path.is_file():
        text = report_path.read_text(encoding="utf-8", errors="replace")
        for token in ("External Closure Operator Packet", "not evidence", "External Records", "external_closure artifacts", "sha256", "template placeholders"):
            require(errors, token in text, f"operator packet report missing token: {token}")
    return errors


def self_test() -> int:
    from package_genesys2_external_operator_packet import DEFAULT_CURRENT_ROOT, markdown_report, package_packet, write_json as package_write_json

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        records = []
        intake_records = []
        for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
            records.append(
                {
                    "id": record_id,
                    "required_summary_schema": spec["schema"],
                    "external_summary_path": spec["path"].as_posix(),
                    "plan_status": "READY_TO_EXECUTE_WITH_EXTERNAL_STATE",
                    "readiness_status": "fixture",
                    "no_substitution_rule": "fixture must not be substituted for external evidence",
                    "operator_inputs": ["one", "two", "three"],
                    "required_raw_artifacts": ["one", "two", "three", "four"],
                    "acceptance_criteria": ["one", "two", "three", "four"],
                    "preflight_commands": ["uv run python tools/check_fixture.py --root ."],
                    "collection_commands": ["external: board fixture", "external: retain fixture"],
                    "packaging_commands": [
                        f"uv run python tools/prepare_genesys2_external_summary.py --record-id {record_id} --write-template fixture.json",
                        f"uv run python tools/prepare_genesys2_external_summary.py --record-id {record_id} --summary candidate.json",
                    ],
                    "validation_commands": ["uv run python tools/check_genesys2_external_closure_intake.py --root ."],
                    "exit_criteria": ["completion_status=EXTERNAL_SUMMARY_ACCEPTED"],
                }
            )
            intake_records.append(
                {
                    "id": record_id,
                    "completion_status": "OPEN_NO_EXTERNAL_SUMMARY",
                    "completion_requires_external_state": True,
                    "completion_evidence_valid": False,
                }
            )
        package_write_json(current / "external_closure_plan.json", {"schema": "rvmt.genesys2.external_closure_plan.v1", "status": "PASS", "records": records})
        for record_id in EXPECTED_EXTERNAL_SUMMARIES:
            template = root / expected_template_path(record_id)
            template.parent.mkdir(parents=True, exist_ok=True)
            template.write_text('{"template_only": true}\n', encoding="utf-8", newline="\n")
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
        package_write_json(current / "external_closure_readiness.json", {"schema": "rvmt.genesys2.external_closure_readiness.v1", "status": "PASS"})
        package_write_json(current / "external_closure_preflight.json", {"schema": "rvmt.genesys2.external_closure_preflight.v1", "status": "PASS"})
        packet = package_packet(root, DEFAULT_CURRENT_ROOT)
        report = root / DEFAULT_REPORT
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(markdown_report(packet), encoding="utf-8", newline="\n")
        errors = check_summary(packet, root, DEFAULT_REPORT)
        if errors:
            print("[FAIL] good operator packet fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        packet["source_artifacts"]["external_closure_plan"]["closure_status"] = None
        errors = check_summary(packet, root, DEFAULT_REPORT)
        if not any("external_closure_plan: closure_status missing" in error for error in errors):
            print("[FAIL] operator packet null source closure status fixture passed", file=sys.stderr)
            return 1
        packet["source_artifacts"]["external_closure_plan"]["closure_status"] = "NOT_APPLICABLE"
        packet["claim_boundary"]["external_execution_completed"] = True
        errors = check_summary(packet, root, DEFAULT_REPORT)
        if not any("external execution" in error for error in errors):
            print("[FAIL] operator packet overclaim fixture passed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 external operator packet checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the Genesys2/CVA6 external closure operator handoff packet.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing external operator packet: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root, args.report)
    except Exception as exc:
        print(f"[FAIL] external operator packet checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] external operator packet is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] external operator packet accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
