from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from check_genesys2_external_closure_intake import EXPECTED_EXTERNAL_SUMMARIES, validate_external_summary
from external_closure_artifacts import (
    ROOT,
    copy_sample_artifact,
    evidence_rows,
    external_record_root,
    load_json,
    repo_path,
    repo_relative,
    write_json_artifact,
    write_summary,
)


RECORD_ID = "genesys2_board_benign_control"
DEFAULT_OUT = EXPECTED_EXTERNAL_SUMMARIES[RECORD_ID]["path"]
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260613-board-benign-control")
BENIGN_SAMPLES = ("hello", "ls", "cat", "cp", "sha256sum")


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def board_claimed(manifest: dict[str, Any]) -> bool:
    return (
        manifest.get("genesys2_cva6_board_trace_claimed") is True
        or manifest.get("genesys2_board_trace_claimed") is True
        or manifest.get("board_trace_claimed") is True
    )


def sample_false_positive(audit: dict[str, Any]) -> tuple[bool, list[str]]:
    unexpected = [str(item) for item in as_list(audit.get("unexpected_matched_behavior"))]
    unexpected.extend(str(item) for item in as_list(audit.get("unexpected_matched_rules")))
    false_positive = bool(unexpected) or audit.get("false_positive") is True
    return false_positive, sorted(set(unexpected))


def find_sample_file(sample_dir: Path, filename: str) -> Path | None:
    direct = sample_dir / filename
    if direct.is_file():
        return direct
    matches = sorted(sample_dir.rglob(filename))
    return matches[0] if matches else None


def find_capture_manifest(sample_dir: Path) -> Path | None:
    for name in ("board_capture_manifest.json", "capture_manifest.json", "board_capture.json"):
        path = sample_dir / name
        if path.is_file():
            return path
    return None


def package_summary(root: Path, run_root_arg: Path) -> dict[str, Any]:
    record_root = external_record_root(root, RECORD_ID)
    run_root = repo_path(root, run_root_arg)
    failures: list[str] = []
    sample_rows: list[dict[str, Any]] = []
    capture_manifest_rows: list[dict[str, Any]] = []
    semantic_manifest_rows: list[dict[str, Any]] = []
    graph_manifest_rows: list[dict[str, Any]] = []
    audit_manifest_rows: list[dict[str, Any]] = []
    false_positive_rows: list[dict[str, Any]] = []

    for sample_id in BENIGN_SAMPLES:
        sample_dir = run_root / sample_id
        capture_path = find_capture_manifest(sample_dir)
        semantic_src = find_sample_file(sample_dir, "semantic_events.json")
        graph_src = find_sample_file(sample_dir, "behavior_graph.json")
        audit_src = find_sample_file(sample_dir, "behavior_audit.json")
        capture = load_json(capture_path) if capture_path else {}
        semantic = load_json(semantic_src) if semantic_src else {}
        graph = load_json(graph_src) if graph_src else {}
        audit = load_json(audit_src) if audit_src else {}
        board = board_claimed(capture)
        non_network = capture.get("non_network") is True or capture.get("network_required") is False or semantic.get("network_required") is False
        false_positive, unexpected = sample_false_positive(audit)
        if not capture_path:
            failures.append(f"{sample_id}: missing board capture manifest")
        if not board:
            failures.append(f"{sample_id}: capture manifest does not claim Genesys2/CVA6 board trace")
        if semantic_src is None:
            failures.append(f"{sample_id}: missing semantic_events.json")
        if graph_src is None:
            failures.append(f"{sample_id}: missing behavior_graph.json")
        if audit_src is None:
            failures.append(f"{sample_id}: missing behavior_audit.json")
        if semantic.get("sample_class") != "benign":
            failures.append(f"{sample_id}: semantic sample_class is not benign")
        if graph.get("sample_class") != "benign":
            failures.append(f"{sample_id}: graph sample_class is not benign")
        if audit.get("sample_class") != "benign":
            failures.append(f"{sample_id}: audit sample_class is not benign")
        if not non_network:
            failures.append(f"{sample_id}: sample is not proven non-network")
        if false_positive:
            failures.append(f"{sample_id}: unexpected false positive rules: {', '.join(unexpected) or 'reported'}")

        semantic_dest = copy_sample_artifact(root, RECORD_ID, sample_id, semantic_src, "semantic_events.json") if semantic_src else None
        graph_dest = copy_sample_artifact(root, RECORD_ID, sample_id, graph_src, "behavior_graph.json") if graph_src else None
        audit_dest = copy_sample_artifact(root, RECORD_ID, sample_id, audit_src, "behavior_audit.json") if audit_src else None
        capture_manifest_rows.append({**capture, "id": sample_id, "path": repo_relative(root, capture_path) if capture_path else None})
        semantic_manifest_rows.append({"id": sample_id, "source": repo_relative(root, semantic_src) if semantic_src else None, "copied": repo_relative(root, semantic_dest) if semantic_dest else None})
        graph_manifest_rows.append({"id": sample_id, "source": repo_relative(root, graph_src) if graph_src else None, "copied": repo_relative(root, graph_dest) if graph_dest else None})
        audit_manifest_rows.append({"id": sample_id, "source": repo_relative(root, audit_src) if audit_src else None, "copied": repo_relative(root, audit_dest) if audit_dest else None})
        false_positive_rows.append({"id": sample_id, "unexpected_false_positive": false_positive, "unexpected_matched_rules": unexpected})
        sample_rows.append(
            {
                "id": sample_id,
                "genesys2_cva6_board_trace_claimed": board,
                "non_network": non_network,
                "unexpected_false_positive": false_positive,
                "semantic_events": repo_relative(root, semantic_dest) if semantic_dest else "",
                "behavior_graph": repo_relative(root, graph_dest) if graph_dest else "",
                "behavior_audit": repo_relative(root, audit_dest) if audit_dest else "",
            }
        )

    unexpected_count = sum(1 for row in sample_rows if row.get("unexpected_false_positive") is True)
    status = "PASS" if not failures else "FAIL"
    artifacts = {
        "board_capture_manifest": write_json_artifact(root, RECORD_ID, "board_capture_manifest", {"run_root": repo_relative(root, run_root), "samples": capture_manifest_rows}),
        "semantic_events_manifest": write_json_artifact(root, RECORD_ID, "semantic_events_manifest", {"samples": semantic_manifest_rows}),
        "behavior_graph_manifest": write_json_artifact(root, RECORD_ID, "behavior_graph_manifest", {"samples": graph_manifest_rows}),
        "behavior_audit_manifest": write_json_artifact(root, RECORD_ID, "behavior_audit_manifest", {"samples": audit_manifest_rows}),
        "false_positive_report": write_json_artifact(
            root,
            RECORD_ID,
            "false_positive_report",
            {
                "unexpected_false_positive_count": unexpected_count,
                "benign_false_positive_rate": unexpected_count / len(BENIGN_SAMPLES),
                "samples": false_positive_rows,
                "failures": failures,
            },
        ),
    }
    return {
        "schema": "rvmt.genesys2.board_benign_control.v1",
        "status": status,
        "evidence_artifacts": evidence_rows(root, artifacts),
        "claim_boundary": {
            "real_malware_validation_claimed": False,
            "genesys2_board_benign_control_claimed": status == "PASS",
            "local_linux_benign_substituted": False,
        },
        "aggregate": {
            "genesys2_board_trace_claimed": status == "PASS",
            "sample_count": len(sample_rows),
            "unexpected_false_positive_count": unexpected_count,
            "benign_false_positive_rate": unexpected_count / len(sample_rows) if sample_rows else 1.0,
        },
        "samples": sample_rows,
        "failed_attempts": failures,
        "record_root": repo_relative(root, record_root),
        "validation_commands": [
            "uv run python tools/package_genesys2_board_benign_control.py --run-root <board-benign-run-root>",
            "uv run python tools/check_genesys2_board_benign_control.py --root .",
        ],
    }


def write_fixture(root: Path) -> Path:
    run_root = root / "board_benign"
    for sample_id in BENIGN_SAMPLES:
        sample_dir = run_root / sample_id
        sample_dir.mkdir(parents=True, exist_ok=True)
        (sample_dir / "board_capture_manifest.json").write_text(
            json.dumps(
                {
                    "id": sample_id,
                    "genesys2_cva6_board_trace_claimed": True,
                    "non_network": True,
                    "marker_window_passed": True,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        for filename, schema in (
            ("semantic_events.json", "rvmt.behavior.semantic.v1"),
            ("behavior_graph.json", "rvmt.behavior.graph.v1"),
            ("behavior_audit.json", "rvmt.behavior.audit.v1"),
        ):
            value: dict[str, Any] = {"schema": schema, "sample_id": sample_id, "sample_class": "benign", "network_required": False}
            if filename == "behavior_audit.json":
                value["unexpected_matched_behavior"] = []
                value["unexpected_matched_rules"] = []
                value["false_positive"] = False
            (sample_dir / filename).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return run_root


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        run_root = write_fixture(root)
        summary = package_summary(root, run_root)
        errors = validate_external_summary(RECORD_ID, summary, root)
        if errors:
            print("[FAIL] board benign PASS fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        audit_path = run_root / "hello" / "behavior_audit.json"
        audit = load_json(audit_path)
        audit["unexpected_matched_behavior"] = ["many_file_scan"]
        audit_path.write_text(json.dumps(audit) + "\n", encoding="utf-8")
        bad_summary = package_summary(root, run_root)
        if not validate_external_summary(RECORD_ID, bad_summary, root):
            print("[FAIL] board benign false-positive fixture accepted", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 board benign-control packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package Genesys2 board benign-control evidence for external closure intake.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = package_summary(root, args.run_root)
    out = write_summary(root, args.out, summary)
    errors = validate_external_summary(RECORD_ID, summary, root)
    status = "PASS" if not errors else "FAIL"
    print(f"[{status}] wrote board benign-control summary to {out}")
    for error in errors:
        print(f"- {error}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
