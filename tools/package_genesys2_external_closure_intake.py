from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from check_genesys2_external_closure_intake import (
    DEFAULT_EXTERNAL_ROOT,
    DEFAULT_SUMMARY,
    EXPECTED_EXTERNAL_SUMMARIES,
    check_summary,
    expected_record_state,
    fixture_evidence_artifacts,
    good_external_summary,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")


NO_SUBSTITUTION_RULES = {
    "board_native_dwarf_source_lines": "Source-equivalent sidecars and toolchain probes must not be substituted for board-native DWARF source-line evidence.",
    "full_hardware_pointer_strings": "Bounded prefixes, fragments, qemu/strace strings, and companion strings must not be substituted for full hardware-derived pointer strings.",
    "production_streaming_dma_trace_sink": "BRAM ring captures, ILA/JTAG dumps, and local runtime benchmarks must not be substituted for production streaming or DMA throughput evidence.",
    "genesys2_board_benign_control": "Local Linux benign controls must not be substituted for Genesys2/CVA6 board benign-control traces.",
}


def repo_path(root: Path, value: Path) -> Path:
    return value if value.is_absolute() else root / value


def package_intake(root: Path = ROOT, current_root: Path = DEFAULT_CURRENT_ROOT) -> dict[str, Any]:
    del current_root
    records: list[dict[str, Any]] = []
    accepted = open_count = invalid = 0
    for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
        path = spec["path"]
        state = expected_record_state(root, record_id, path)
        if state["valid"]:
            accepted += 1
        elif state["exists"]:
            invalid += 1
        else:
            open_count += 1
        records.append(
            {
                "id": record_id,
                "required_summary_schema": spec["schema"],
                "external_summary_path": path.as_posix(),
                "external_summary_exists": state["exists"],
                "external_summary_schema": state["schema"],
                "external_summary_status": state["summary_status"],
                "completion_status": state["completion_status"],
                "completion_evidence_valid": state["valid"],
                "current_blocker": not state["valid"],
                "completion_requires_external_state": not state["valid"],
                "validation_errors": state["validation_errors"],
                "acceptance_checker": "tools/check_genesys2_external_closure_intake.py",
                "no_substitution_rule": NO_SUBSTITUTION_RULES[record_id],
            }
        )
    closure_status = "ALL_NON_REAL_EXTERNAL_SUMMARIES_ACCEPTED" if accepted == len(EXPECTED_EXTERNAL_SUMMARIES) else "OPEN_EXTERNAL_ARTIFACTS_REQUIRED"
    status = "PASS" if invalid == 0 else "FAIL"
    return {
        "schema": "rvmt.genesys2.external_closure_intake.v1",
        "status": status,
        "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
        "external_summary_root": DEFAULT_EXTERNAL_ROOT.as_posix(),
        "scope": "optional external evidence intake for remaining non-real-malware Genesys2/CVA6 blockers",
        "objective_exclusions": ["real_malware_validation"],
        "closure_status": closure_status,
        "accepted_external_blocker_count": accepted,
        "open_external_blocker_count": open_count,
        "invalid_external_blocker_count": invalid,
        "claim_boundary": {
            "intake_gate_only": True,
            "all_non_real_external_blockers_closed": accepted == len(EXPECTED_EXTERNAL_SUMMARIES),
            "real_malware_validation_claimed": False,
            "unvalidated_external_summary_accepted": False,
        },
        "records": records,
        "validation_commands": [
            "uv run python tools/package_genesys2_external_closure_intake.py",
            "uv run python tools/check_genesys2_external_closure_intake.py --root .",
        ],
        "interpretation": [
            "This intake gate accepts only strict optional external summaries and does not replace board, RTL, or reviewer execution.",
            "When no external summaries are present, the gate remains PASS with OPEN_EXTERNAL_ARTIFACTS_REQUIRED so current evidence is not overclaimed.",
            "If an external summary appears but fails the required schema, threshold, or no-substitution checks, the gate fails.",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        summary = package_intake(root)
        errors = check_summary(summary, root)
        if errors or summary.get("open_external_blocker_count") != len(EXPECTED_EXTERNAL_SUMMARIES):
            print("[FAIL] open external closure intake fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
            write_json(root / spec["path"], good_external_summary(record_id, fixture_evidence_artifacts(root, record_id)))
        summary = package_intake(root)
        errors = check_summary(summary, root)
        if errors or summary.get("accepted_external_blocker_count") != len(EXPECTED_EXTERNAL_SUMMARIES):
            print("[FAIL] accepted external closure intake fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    print("[PASS] Genesys2 external closure intake packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package optional external evidence intake status for remaining non-real-malware Genesys2/CVA6 blockers.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    out = repo_path(root, args.out)
    try:
        summary = package_intake(root, args.current_root)
        write_json(out, summary)
    except Exception as exc:
        print(f"package_genesys2_external_closure_intake: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote Genesys2 external closure intake to {out} ({summary['closure_status']})")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
