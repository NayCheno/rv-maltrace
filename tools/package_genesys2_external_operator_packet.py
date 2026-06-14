from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from check_genesys2_external_closure_intake import EXPECTED_EXTERNAL_SUMMARIES, REQUIRED_EVIDENCE_ARTIFACT_KINDS


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT_JSON = DEFAULT_CURRENT_ROOT / "external_operator_packet.json"
DEFAULT_OUT_MD = Path("docs/07-evaluation-evidence/reports/ccfa_external_operator_packet.md")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def repo_rel(path: Path, root: Path = ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_path(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rows_by_id(rows: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def source_row(root: Path, path_value: str, expected_schema: str, default_closure_status: str | None = None) -> dict[str, Any]:
    path = repo_path(root, path_value)
    data = load_json(path)
    closure_status = data.get("closure_status")
    if not closure_status and default_closure_status is not None:
        closure_status = default_closure_status
    return {
        "path": repo_rel(path, root),
        "exists": path.is_file(),
        "sha256": sha256_file(path),
        "schema": data.get("schema"),
        "expected_schema": expected_schema,
        "status": data.get("status"),
        "closure_status": closure_status,
    }


def template_path(record_id: str) -> str:
    summary_path = EXPECTED_EXTERNAL_SUMMARIES[record_id]["path"]
    return (DEFAULT_CURRENT_ROOT / "external_closure_templates" / f"{summary_path.stem}.template.json").as_posix()


def packet_record(order: int, plan_record: dict[str, Any], intake_record: dict[str, Any]) -> dict[str, Any]:
    record_id = str(plan_record["id"])
    spec = EXPECTED_EXTERNAL_SUMMARIES[record_id]
    return {
        "order": order,
        "id": record_id,
        "required_summary_schema": spec["schema"],
        "external_summary_path": spec["path"].as_posix(),
        "template_path": template_path(record_id),
        "plan_status": plan_record.get("plan_status"),
        "readiness_status": plan_record.get("readiness_status"),
        "intake_completion_status": intake_record.get("completion_status"),
        "completion_requires_external_state": intake_record.get("completion_requires_external_state"),
        "completion_evidence_valid": intake_record.get("completion_evidence_valid"),
        "no_substitution_rule": plan_record.get("no_substitution_rule"),
        "operator_inputs": plan_record.get("operator_inputs", []),
        "required_raw_artifacts": plan_record.get("required_raw_artifacts", []),
        "required_evidence_artifact_kinds": sorted(REQUIRED_EVIDENCE_ARTIFACT_KINDS[record_id]),
        "acceptance_criteria": plan_record.get("acceptance_criteria", []),
        "execution_steps": [
            {
                "phase": "local_preflight",
                "commands": plan_record.get("preflight_commands", []),
                "must_pass_before_external_execution": True,
            },
            {
                "phase": "external_collection",
                "commands": plan_record.get("collection_commands", []),
                "requires_board_rtl_or_host_transport": True,
            },
            {
                "phase": "candidate_summary_packaging",
                "commands": plan_record.get("packaging_commands", []),
                "candidate_must_pass_prepare_helper": True,
            },
            {
                "phase": "intake_acceptance",
                "commands": plan_record.get("validation_commands", []),
                "accepted_only_when_completion_status": "EXTERNAL_SUMMARY_ACCEPTED",
            },
        ],
        "exit_criteria": plan_record.get("exit_criteria", []),
        "operator_notes": [
            "Do not copy template-only JSON into the intake directory as evidence.",
            "Do not replace board, RTL, or host receiver artifacts with local sidecars or companion-derived fields.",
            f"Every evidence_artifacts row must point to a real nonempty record-specific file under results/evaluation/genesys2-cva6/current/external_closure/{record_id}/ with matching sha256 and no template placeholders.",
            "Run the intake checker after writing any candidate external summary.",
        ],
    }


def markdown_report(packet: dict[str, Any]) -> str:
    lines = [
        "# CCF-A External Closure Operator Packet",
        "",
        f"Status: `{packet['status']}`",
        f"Closure status: `{packet['closure_status']}`",
        "",
        "This packet is an operator handoff for the remaining non-real-malware external work. It is not evidence that the external work has already been executed.",
        "",
        "## Source Artifacts",
        "",
        "| Artifact | Status | Closure status |",
        "| --- | --- | --- |",
    ]
    for artifact_id, row in packet["source_artifacts"].items():
        closure_status = row.get("closure_status")
        lines.append(f"| `{artifact_id}` | `{row.get('status')}` | `{closure_status}` |")
    lines.extend(
        [
            "",
            "## Operator Sequence",
            "",
        ]
    )
    for index, step in enumerate(packet["operator_sequence"], start=1):
        lines.append(f"{index}. {step}")
    lines.extend(
        [
            "",
            "## External Records",
            "",
            "| Order | External id | Intake status | Expected summary | Required artifact kinds |",
            "| ---: | --- | --- | --- | --- |",
        ]
    )
    for record in packet["records"]:
        kinds = ", ".join(f"`{kind}`" for kind in record["required_evidence_artifact_kinds"])
        lines.append(
            f"| {record['order']} | `{record['id']}` | `{record['intake_completion_status']}` | `{record['external_summary_path']}` | {kinds} |"
        )
    lines.extend(
        [
            "",
            "## Non-Claims",
            "",
        ]
    )
    for item in packet["non_claims"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def package_packet(root: Path, current_root: Path) -> dict[str, Any]:
    plan_path = current_root / "external_closure_plan.json"
    intake_path = current_root / "external_closure_intake.json"
    readiness_path = current_root / "external_closure_readiness.json"
    preflight_path = current_root / "external_closure_preflight.json"
    plan = load_json(repo_path(root, plan_path))
    intake = load_json(repo_path(root, intake_path))
    plan_records = rows_by_id(plan.get("records"))
    intake_records = rows_by_id(intake.get("records"))
    records = [
        packet_record(index, plan_records[record_id], intake_records[record_id])
        for index, record_id in enumerate(EXPECTED_EXTERNAL_SUMMARIES, start=1)
    ]
    return {
        "schema": "rvmt.genesys2.external_operator_packet.v1",
        "status": "PASS",
        "canonical_evaluation_root": repo_rel(repo_path(root, current_root), root),
        "scope": "operator handoff for remaining non-real-malware Genesys2/CVA6 external closure items",
        "closure_status": intake.get("closure_status"),
        "open_external_blocker_count": intake.get("open_external_blocker_count"),
        "accepted_external_blocker_count": intake.get("accepted_external_blocker_count"),
        "invalid_external_blocker_count": intake.get("invalid_external_blocker_count"),
        "objective_exclusions": ["real_malware_validation"],
        "source_artifacts": {
            "external_closure_readiness": source_row(root, readiness_path.as_posix(), "rvmt.genesys2.external_closure_readiness.v1", "NOT_APPLICABLE"),
            "external_closure_intake": source_row(root, intake_path.as_posix(), "rvmt.genesys2.external_closure_intake.v1"),
            "external_closure_plan": source_row(root, plan_path.as_posix(), "rvmt.genesys2.external_closure_plan.v1", "NOT_APPLICABLE"),
            "external_closure_preflight": source_row(root, preflight_path.as_posix(), "rvmt.genesys2.external_closure_preflight.v1", "NOT_APPLICABLE"),
        },
        "claim_boundary": {
            "operator_packet_only": True,
            "external_execution_completed": False,
            "external_readiness_substituted_for_completion": False,
            "all_non_real_external_blockers_closed": intake.get("closure_status") == "ALL_NON_REAL_EXTERNAL_SUMMARIES_ACCEPTED",
            "real_malware_validation_claimed": False,
            "templates_treated_as_evidence": False,
            "external_artifact_paths_scoped_to_external_closure": True,
            "external_artifact_paths_record_scoped": True,
            "placeholder_values_treated_as_invalid": True,
        },
        "operator_sequence": [
            "Run the local preflight commands recorded for each external id.",
            "Execute the required board, RTL, or host-transport experiment outside the repository-only checker path.",
            "Write candidate summaries only from real record-specific external_closure artifacts with matching sha256-backed evidence rows and no template placeholders.",
            "Validate each candidate with tools/prepare_genesys2_external_summary.py before moving it into the intake path.",
            "Regenerate external_closure_intake.json, then run the intake, operator packet, current-suite, and full reproduction checks.",
        ],
        "records": records,
        "validation_commands": [
            "uv run python tools/package_genesys2_external_operator_packet.py",
            "uv run python tools/check_genesys2_external_operator_packet.py --root .",
            "uv run python tools/check_genesys2_external_closure_intake.py --root .",
            "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
            "uv run python tools/reproduce_genesys2_current.py --full --dry-run",
        ],
        "non_claims": [
            "This packet does not itself create board-native DWARF source-line attribution evidence; only accepted intake summaries close that item.",
            "This packet does not itself create full hardware pointer-string reconstruction evidence; only accepted intake summaries close that item.",
            "This packet does not complete production streaming/DMA throughput evidence.",
            "This packet does not itself create Genesys2 board benign-control evidence; only accepted intake summaries close that item.",
            "This packet does not add real-malware validation.",
        ],
    }


def self_test() -> int:
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
                    "intake_completion_status": "OPEN_NO_EXTERNAL_SUMMARY",
                    "no_substitution_rule": "fixture must not be substituted for external evidence",
                    "operator_inputs": ["one", "two", "three"],
                    "required_raw_artifacts": ["one", "two", "three", "four"],
                    "acceptance_criteria": ["one", "two", "three", "four"],
                    "preflight_commands": ["uv run python tools/check_fixture.py --root ."],
                    "collection_commands": ["external: collect fixture", "external: retain fixture"],
                    "packaging_commands": [
                        f"uv run python tools/prepare_genesys2_external_summary.py --record-id {record_id} --write-template fixture.json",
                        f"uv run python tools/prepare_genesys2_external_summary.py --record-id {record_id} --summary candidate.json",
                        "uv run python tools/package_genesys2_external_closure_intake.py",
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
        write_json(current / "external_closure_plan.json", {"schema": "rvmt.genesys2.external_closure_plan.v1", "status": "PASS", "records": records})
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
        write_json(current / "external_closure_readiness.json", {"schema": "rvmt.genesys2.external_closure_readiness.v1", "status": "PASS"})
        write_json(current / "external_closure_preflight.json", {"schema": "rvmt.genesys2.external_closure_preflight.v1", "status": "PASS"})
        packet = package_packet(root, DEFAULT_CURRENT_ROOT)
    if packet.get("status") != "PASS" or len(packet.get("records", [])) != len(EXPECTED_EXTERNAL_SUMMARIES):
        print("[FAIL] operator packet fixture failed", file=sys.stderr)
        return 1
    if packet.get("claim_boundary", {}).get("external_execution_completed") is not False:
        print("[FAIL] operator packet must not claim external execution", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 external operator packet packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package the Genesys2/CVA6 external closure operator handoff packet.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    try:
        packet = package_packet(root, args.current_root)
        write_json(repo_path(root, args.out_json), packet)
        report = repo_path(root, args.out_md)
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(markdown_report(packet), encoding="utf-8", newline="\n")
    except Exception as exc:
        print(f"package_genesys2_external_operator_packet: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{packet['status']}] wrote external operator packet to {repo_path(root, args.out_json)} and {repo_path(root, args.out_md)}")
    return 0 if packet["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
