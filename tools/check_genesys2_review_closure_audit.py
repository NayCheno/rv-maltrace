from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/review_closure_audit.json")
DEFAULT_REPORT = Path("docs/07-evaluation-evidence/reports/ccfa_review_closure_audit.md")

EXPECTED_SCHEMA = "rvmt.genesys2.review_closure_audit.v1"
EXPECTED_STATUS = "PASS"
EXPECTED_CLOSURE_STATUS = "PASS_LOCAL_SCOPE_EXTERNAL_OPEN"
EXPECTED_EXTERNAL_IDS = {
    "board_native_dwarf_source_lines",
    "full_hardware_pointer_strings",
    "production_streaming_dma_trace_sink",
    "genesys2_board_benign_control",
}
EVIDENCE_STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
ACCEPTED_EXTERNAL_STATUS = "EXTERNAL_SUMMARY_ACCEPTED"
OPEN_EXTERNAL_STATUS = "OPEN_EXTERNAL_ARTIFACTS_REQUIRED"
EXPECTED_ITEM_IDS = {
    "phase_a_claim_boundary_convergence",
    "phase_a_baseline_board_acceptance",
    "phase_b_p0_and_safe_surrogate_hardware_trace",
    "phase_b_bounded_pointer_semantics",
    "phase_b_full_hardware_pointer_strings",
    "phase_c_function_process_elf_attribution",
    "phase_c_board_native_dwarf_source_lines",
    "phase_d_safe_surrogate_behavior_case_studies",
    "phase_d_local_benign_control",
    "phase_d_genesys2_board_benign_control",
    "phase_e_evaluation_matrix_and_baselines",
    "phase_e_statistical_robustness_audit",
    "phase_e_artifact_package_and_reproduction",
    "phase_e_streaming_dma_target_baseline",
    "phase_e_production_streaming_dma_trace_sink",
    "phase_g_real_malware_validation",
}


def repo_path(root: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def row_map(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def current_external_state(root: Path) -> dict[str, dict[str, Any]]:
    intake_path = root / "results/evaluation/genesys2-cva6/current/external_closure_intake.json"
    if not intake_path.is_file():
        return {}
    intake = load_json(intake_path)
    records = intake.get("records") if isinstance(intake.get("records"), list) else []
    return row_map(records)


def check_summary(data: dict[str, Any], root: Path, report: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == EXPECTED_SCHEMA, "schema mismatch")
    require(errors, data.get("status") == EXPECTED_STATUS, "status mismatch")
    require(errors, data.get("closure_status") == EXPECTED_CLOSURE_STATUS, "closure_status mismatch")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("real_malware_validation_excluded_by_objective") is True, "real malware exclusion must be explicit")
    require(errors, boundary.get("external_readiness_substituted_for_completion") is False, "external readiness must not be substituted")
    require(errors, boundary.get("local_linux_benign_substituted_for_board_benign") is False, "local benign control must not be substituted")
    require(errors, boundary.get("bounded_prefix_substituted_for_full_strings") is False, "bounded prefixes must not be substituted for full strings")
    require(errors, boundary.get("toolchain_probe_substituted_for_board_native_dwarf") is False, "toolchain probe must not be substituted for board-native DWARF")

    summary = as_dict(data.get("summary"))
    require(errors, summary.get("local_items_evidence_present") is True, "local evidence coverage must be true")
    accepted_external_ids = set(as_list(summary.get("accepted_external_ids")))
    open_external_ids = set(as_list(summary.get("open_external_ids")))
    require(errors, accepted_external_ids | open_external_ids == EXPECTED_EXTERNAL_IDS, "external ids coverage mismatch")
    require(errors, accepted_external_ids.isdisjoint(open_external_ids), "accepted/open external ids overlap")
    require(errors, "real_malware_validation" in as_list(summary.get("objective_exclusions")), "real malware exclusion missing")
    require(errors, summary.get("local_item_count") == 11, "local item count mismatch")
    require(errors, int(summary.get("accepted_external_item_count") or 0) == len(accepted_external_ids), "accepted external item count mismatch")
    require(errors, int(summary.get("open_external_item_count") or 0) == len(open_external_ids), "open external item count mismatch")
    require(errors, summary.get("excluded_item_count") == 1, "excluded item count mismatch")

    items = row_map(as_list(data.get("items")))
    require(errors, set(items) == EXPECTED_ITEM_IDS, "review item set mismatch")
    external_items = []
    excluded_items = []
    for item_id, item in items.items():
        status = str(item.get("status") or "")
        require(errors, bool(item.get("requirement")), f"{item_id}: requirement missing")
        require(errors, bool(as_list(item.get("checker_commands"))), f"{item_id}: checker commands missing")
        evidence_rows = as_list(item.get("evidence"))
        require(errors, bool(evidence_rows), f"{item_id}: evidence rows missing")
        for evidence in evidence_rows:
            evidence_path = repo_path(root, evidence.get("path"))
            require(errors, evidence.get("exists") is True, f"{item_id}: evidence exists flag not true for {evidence.get('id')}")
            require(errors, evidence_path.is_file(), f"{item_id}: evidence file missing: {evidence.get('path')}")
            if evidence_path.is_file():
                require(errors, evidence.get("sha256") == sha256_file(evidence_path), f"{item_id}: evidence sha256 mismatch: {evidence.get('id')}")
            require(errors, isinstance(evidence.get("schema"), str) and bool(evidence.get("schema")), f"{item_id}: evidence schema marker missing: {evidence.get('id')}")
            require(errors, isinstance(evidence.get("status"), str) and bool(evidence.get("status")), f"{item_id}: evidence status marker missing: {evidence.get('id')}")
            evidence_status = evidence.get("status")
            if status.startswith("PASS"):
                require(errors, evidence_status in {EVIDENCE_STATUS_NOT_APPLICABLE, "PASS"}, f"{item_id}: local evidence status is not PASS: {evidence.get('id')}")
        if status in {OPEN_EXTERNAL_STATUS, ACCEPTED_EXTERNAL_STATUS}:
            external_items.append(item)
        elif status == "EXCLUDED_BY_OBJECTIVE":
            excluded_items.append(item)
        else:
            require(errors, status.startswith("PASS"), f"{item_id}: unexpected status {status}")

    require(errors, len(external_items) == len(EXPECTED_EXTERNAL_IDS), "external item count mismatch")
    live_external = current_external_state(root)
    for item in external_items:
        external_id = item.get("external_id")
        require(errors, external_id in EXPECTED_EXTERNAL_IDS, f"{item.get('id')}: unexpected external id")
        item_state = as_dict(item.get("external_state"))
        live_state = live_external.get(str(external_id), {})
        require(errors, live_state.get("completion_status") == item_state.get("completion_status"), f"{external_id}: live intake status mismatch")
        require(errors, live_state.get("external_summary_path") == item_state.get("external_summary_path"), f"{external_id}: live intake path mismatch")
        if item.get("status") == ACCEPTED_EXTERNAL_STATUS:
            require(errors, item_state.get("completion_status") == "EXTERNAL_SUMMARY_ACCEPTED", f"{external_id}: accepted audit status mismatch")
            require(errors, item_state.get("current_blocker") is False, f"{external_id}: accepted summary should clear blocker")
            require(errors, item_state.get("external_summary_exists") is True, f"{external_id}: accepted external summary must exist")
            require(errors, item_state.get("completion_evidence_valid") is True, f"{external_id}: accepted evidence validity must be true")
        else:
            require(errors, item_state.get("completion_status") in {"OPEN_NO_EXTERNAL_SUMMARY", "EXTERNAL_SUMMARY_PRESENT_INVALID"}, f"{external_id}: audit must remain blocked")
            require(errors, item_state.get("current_blocker") is True, f"{external_id}: audit current_blocker must be true")
            require(errors, live_state.get("current_blocker") is True, f"{external_id}: live current_blocker must be true")
            require(errors, item_state.get("completion_evidence_valid") is False, f"{external_id}: blocked external evidence validity must be false")
            if item_state.get("completion_status") == "OPEN_NO_EXTERNAL_SUMMARY":
                require(errors, item_state.get("external_summary_exists") is False, f"{external_id}: missing external summary must be absent")
            else:
                require(errors, item_state.get("external_summary_exists") is True, f"{external_id}: invalid external summary must be retained")

    require(errors, len(excluded_items) == 1, "exactly one objective-excluded item expected")
    require(errors, excluded_items and excluded_items[0].get("id") == "phase_g_real_malware_validation", "real malware item must be the only exclusion")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_review_closure_audit.py" in commands, "packager command missing")
    require(errors, "tools/check_genesys2_review_closure_audit.py --root ." in commands, "checker command missing")
    require(errors, "tools/check_genesys2_external_closure_preflight.py --root ." in commands, "external preflight checker command missing")
    require(errors, "tools/check_genesys2_external_operator_packet.py --root ." in commands, "external operator packet checker command missing")
    require(errors, "tools/check_genesys2_statistical_robustness.py --root ." in commands, "statistical robustness checker command missing")
    require(errors, "tools/check_genesys2_streaming_dma_target.py --root ." in commands, "streaming/DMA target checker command missing")
    require(errors, "tools/check_genesys2_pointer_string_readiness.py --root ." in commands, "pointer string readiness checker command missing")
    require(errors, "tools/prepare_genesys2_external_summary.py --check-templates" in commands, "external summary template checker command missing")

    report_path = repo_path(root, report)
    require(errors, report_path.is_file(), f"review closure audit report missing: {report}")
    if report_path.is_file():
        report_text = report_path.read_text(encoding="utf-8", errors="replace")
        for token in ("PASS_LOCAL_SCOPE_EXTERNAL_OPEN", "Remaining Non-Real External Items", "real malware validation"):
            require(errors, token in report_text, f"review closure audit report missing token: {token}")
        for external_id in sorted(EXPECTED_EXTERNAL_IDS):
            require(errors, external_id in report_text, f"review closure audit report missing external id: {external_id}")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        report = root / DEFAULT_REPORT
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            (
                "Status: `PASS_LOCAL_SCOPE_EXTERNAL_OPEN`\n\n"
                "## Remaining Non-Real External Items\n\n"
                "board_native_dwarf_source_lines\n"
                "full_hardware_pointer_strings\n"
                "genesys2_board_benign_control\n"
                "production_streaming_dma_trace_sink\n"
                "real malware validation\n"
            ),
            encoding="utf-8",
            newline="\n",
        )
        intake_records = [
            {
                "id": external_id,
                "completion_status": "OPEN_NO_EXTERNAL_SUMMARY",
                "current_blocker": True,
                "external_summary_path": f"external/{external_id}.json",
                "external_summary_exists": False,
                "completion_evidence_valid": False,
            }
            for external_id in sorted(EXPECTED_EXTERNAL_IDS)
        ]
        write_json(
            root / "results/evaluation/genesys2-cva6/current/external_closure_intake.json",
            {"schema": "rvmt.genesys2.external_closure_intake.v1", "status": "PASS", "records": intake_records},
        )
        items = []
        local_ids = sorted(EXPECTED_ITEM_IDS - {"phase_g_real_malware_validation"} - {
            "phase_b_full_hardware_pointer_strings",
            "phase_c_board_native_dwarf_source_lines",
            "phase_d_genesys2_board_benign_control",
            "phase_e_production_streaming_dma_trace_sink",
        })
        for item_id in local_ids:
            path = root / f"evidence/{item_id}.json"
            write_json(path, {"schema": "fixture", "status": "PASS"})
            items.append(
                {
                    "id": item_id,
                    "requirement": "fixture",
                    "status": "PASS_CURRENT",
                    "evidence": [
                        {
                            "id": item_id,
                            "path": path.relative_to(root).as_posix(),
                            "exists": True,
                            "schema": "fixture",
                            "status": "PASS",
                            "sha256": sha256_file(path),
                        }
                    ],
                    "checker_commands": ["uv run python fixture.py"],
                }
            )
        external_pairs = {
            "phase_b_full_hardware_pointer_strings": "full_hardware_pointer_strings",
            "phase_c_board_native_dwarf_source_lines": "board_native_dwarf_source_lines",
            "phase_d_genesys2_board_benign_control": "genesys2_board_benign_control",
            "phase_e_production_streaming_dma_trace_sink": "production_streaming_dma_trace_sink",
        }
        for item_id, external_id in external_pairs.items():
            path = root / f"evidence/{item_id}.json"
            write_json(path, {"schema": "fixture", "status": "PASS"})
            state = next(row for row in intake_records if row["id"] == external_id)
            items.append(
                {
                    "id": item_id,
                    "requirement": "fixture",
                    "status": "OPEN_EXTERNAL_ARTIFACTS_REQUIRED",
                    "external_id": external_id,
                    "external_state": state,
                    "evidence": [
                        {
                            "id": item_id,
                            "path": path.relative_to(root).as_posix(),
                            "exists": True,
                            "schema": "fixture",
                            "status": "PASS",
                            "sha256": sha256_file(path),
                        }
                    ],
                    "checker_commands": ["uv run python fixture.py"],
                }
            )
        path = root / "evidence/real_malware.json"
        write_json(path, {"schema": "fixture", "status": "PASS"})
        items.append(
            {
                "id": "phase_g_real_malware_validation",
                "requirement": "fixture",
                "status": "EXCLUDED_BY_OBJECTIVE",
                "evidence": [
                    {
                        "id": "real_malware",
                        "path": path.relative_to(root).as_posix(),
                        "exists": True,
                        "schema": "fixture",
                        "status": "PASS",
                        "sha256": sha256_file(path),
                    }
                ],
                "checker_commands": ["uv run python fixture.py"],
            }
        )
        audit = {
            "schema": EXPECTED_SCHEMA,
            "status": EXPECTED_STATUS,
            "closure_status": EXPECTED_CLOSURE_STATUS,
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "summary": {
                "local_item_count": 11,
                "local_items_evidence_present": True,
                "open_external_item_count": len(EXPECTED_EXTERNAL_IDS),
                "open_external_ids": sorted(EXPECTED_EXTERNAL_IDS),
                "excluded_item_count": 1,
                "objective_exclusions": ["real_malware_validation"],
            },
            "claim_boundary": {
                "real_malware_validation_claimed": False,
                "real_malware_validation_excluded_by_objective": True,
                "external_readiness_substituted_for_completion": False,
                "local_linux_benign_substituted_for_board_benign": False,
                "bounded_prefix_substituted_for_full_strings": False,
                "toolchain_probe_substituted_for_board_native_dwarf": False,
            },
            "items": items,
            "validation_commands": [
                "uv run python tools/package_genesys2_review_closure_audit.py",
                "uv run python tools/check_genesys2_review_closure_audit.py --root .",
                "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/check_genesys2_statistical_robustness.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
                "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
            ],
        }
        errors = check_summary(audit, root, DEFAULT_REPORT)
        if errors:
            print("[FAIL] good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        audit["items"][0]["evidence"][0]["status"] = None
        errors = check_summary(audit, root, DEFAULT_REPORT)
        if not any("evidence status marker missing" in error for error in errors):
            print("[FAIL] null evidence status fixture was not rejected", file=sys.stderr)
            return 1
        audit["items"][0]["evidence"][0]["status"] = "PASS"
        audit["claim_boundary"]["bounded_prefix_substituted_for_full_strings"] = True
        errors = check_summary(audit, root, DEFAULT_REPORT)
        if not any("bounded prefixes" in error for error in errors):
            print("[FAIL] overclaim fixture was not rejected", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 review closure audit checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the Genesys2/CVA6 CCF-A review closure audit.")
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
        print(f"[FAIL] missing review closure audit: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root, args.report)
    except Exception as exc:
        print(f"[FAIL] review closure audit checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] review closure audit is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] review closure audit accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
