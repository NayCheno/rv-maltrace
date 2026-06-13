from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/board_benign_readiness_summary.json")
EXPECTED_SAMPLES = {"hello", "ls", "cat", "cp", "sha256sum"}
REQUIRED_TRACE_ROUTE_IDS = {
    "latest_manifest",
    "trace_sink",
    "p0_bram_trace",
    "safe_surrogate_bram_trace",
    "drop_accounting",
    "behavior_audit_metrics",
}
REQUIRED_PER_SAMPLE_ARTIFACTS = {
    "strace_log",
    "stdout",
    "stderr",
    "semantic_events",
    "behavior_graph",
    "behavior_audit",
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


def as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


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
    if row.get("schema"):
        require(errors, bool(row.get("status")), f"{context}: status missing for schema-bearing evidence row")


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.board_benign_readiness.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")

    local = as_dict(data.get("local_control_summary"))
    check_evidence_row(errors, root, local, "local_control_summary")
    require(errors, local.get("schema") == "rvmt.genesys2.benign_control_summary.v1", "local_control_summary schema mismatch")
    require(errors, local.get("status") == "PASS", "local_control_summary status must be PASS")

    trace_rows = row_map(as_list(data.get("trace_route_evidence")))
    missing_trace = sorted(REQUIRED_TRACE_ROUTE_IDS - set(trace_rows))
    require(errors, not missing_trace, f"missing trace route evidence ids: {', '.join(missing_trace)}")
    for artifact_id, row in trace_rows.items():
        check_evidence_row(errors, root, row, f"trace_route_evidence.{artifact_id}")

    aggregate = as_dict(data.get("local_linux_control_aggregate"))
    require(errors, as_int(aggregate.get("sample_count")) >= 5, "local aggregate sample_count must be at least 5")
    require(errors, as_int(aggregate.get("non_network_sample_count")) >= 5, "local aggregate non_network_sample_count must be at least 5")
    require(errors, as_int(aggregate.get("unexpected_false_positive_count"), default=-1) == 0, "local aggregate unexpected false positives must be zero")
    require(errors, as_float(aggregate.get("benign_false_positive_rate"), default=1.0) == 0.0, "local aggregate false-positive rate must be 0.0")

    require(errors, set(as_list(data.get("expected_board_samples"))) == EXPECTED_SAMPLES, "expected_board_samples mismatch")
    samples = {
        str(row.get("sample_id")): row
        for row in as_list(data.get("sample_readiness"))
        if isinstance(row, dict) and row.get("sample_id")
    }
    require(errors, set(samples) == EXPECTED_SAMPLES, "sample_readiness must cover exactly the expected benign samples")
    for sample_id, row in samples.items():
        require(errors, row.get("local_linux_control_available") is True, f"{sample_id}: local control must be available")
        require(errors, row.get("sample_class") == "benign", f"{sample_id}: sample_class must be benign")
        require(errors, row.get("network_required") is False, f"{sample_id}: network_required must be false")
        require(errors, row.get("local_linux_false_positive") is False, f"{sample_id}: local false positive must be false")
        require(errors, not as_list(row.get("unexpected_matched_rules")), f"{sample_id}: unexpected matched rules must be empty")
        require(errors, row.get("genesys2_board_trace_available") is False, f"{sample_id}: board trace must not be claimed")
        require(errors, row.get("board_capture_required") is True, f"{sample_id}: board capture requirement missing")
        require(errors, row.get("accepted_as_board_benign_evidence") is False, f"{sample_id}: must not be accepted as board evidence")
        artifact_rows = row_map(as_list(row.get("artifact_rows")))
        missing_artifacts = sorted(REQUIRED_PER_SAMPLE_ARTIFACTS - set(artifact_rows))
        require(errors, not missing_artifacts, f"{sample_id}: missing local artifact ids: {', '.join(missing_artifacts)}")
        for artifact_id, artifact in artifact_rows.items():
            check_evidence_row(errors, root, artifact, f"{sample_id}.{artifact_id}")

    plan = as_dict(data.get("future_board_capture_plan"))
    require(errors, plan.get("required_summary_schema") == "rvmt.genesys2.board_benign_control.v1", "future schema mismatch")
    require(
        errors,
        plan.get("external_summary_path") == "results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json",
        "future external summary path mismatch",
    )
    require(errors, as_int(plan.get("minimum_accepted_board_samples")) >= 5, "future plan must require at least five samples")
    require(errors, set(as_list(plan.get("required_sample_ids"))) == EXPECTED_SAMPLES, "future required_sample_ids mismatch")
    required_fields = set(str(item) for item in as_list(plan.get("required_summary_fields")))
    for field in ("evidence_artifacts", "genesys2_board_trace_claimed", "sample_count", "benign_false_positive_rate", "samples"):
        require(errors, field in required_fields, f"future required field missing: {field}")
    artifacts_text = " ".join(str(item).lower() for item in as_list(plan.get("required_per_sample_artifacts")))
    for needle in ("board", "semantic_events", "behavior_graph", "behavior_audit", "uart"):
        require(errors, needle in artifacts_text, f"future per-sample artifact list must mention {needle}")
    criteria_text = " ".join(str(item).lower() for item in as_list(plan.get("acceptance_criteria")))
    for needle in ("five", "genesys2/cva6", "0.0", "local linux"):
        require(errors, needle in criteria_text, f"future acceptance criteria must mention {needle}")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("board_benign_readiness_claimed") is True, "readiness claim boundary missing")
    require(errors, boundary.get("local_linux_control_available") is True, "local control boundary missing")
    for key in (
        "genesys2_board_benign_control_claimed",
        "board_benign_false_positive_claimed",
        "local_linux_benign_substituted_for_board",
        "real_malware_validation_claimed",
    ):
        require(errors, boundary.get(key) is False, f"{key} must be false")
    require(errors, boundary.get("board_capture_required_for_closure") is True, "board closure requirement missing")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "does not claim genesys2 board benign-control evidence is complete" in non_claims, "non_claims must reject board completion")
    require(errors, "must not be substituted" in non_claims, "non_claims must reject local substitution")
    require(errors, as_list(data.get("failures")) == [], "failures must be empty")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / "results/evaluation/genesys2-cva6/current"
        current.mkdir(parents=True)
        local = current / "benign_control_summary.json"
        write_json(local, {"schema": "rvmt.genesys2.benign_control_summary.v1", "status": "PASS"})
        trace_rows = []
        for artifact_id in REQUIRED_TRACE_ROUTE_IDS:
            path = current / f"{artifact_id}.json"
            write_json(path, {"schema": f"rvmt.fixture.{artifact_id}.v1", "status": "PASS"})
            trace_rows.append(
                {
                    "id": artifact_id,
                    "path": path.relative_to(root).as_posix(),
                    "exists": True,
                    "sha256": sha256_file(path),
                }
            )
        sample_rows = []
        for sample_id in EXPECTED_SAMPLES:
            artifacts = []
            for artifact_id in REQUIRED_PER_SAMPLE_ARTIFACTS:
                path = root / "build/benign_control" / sample_id / f"{artifact_id}.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n", encoding="utf-8")
                artifacts.append(
                    {
                        "id": artifact_id,
                        "path": path.relative_to(root).as_posix(),
                        "exists": True,
                        "sha256": sha256_file(path),
                    }
                )
            sample_rows.append(
                {
                    "sample_id": sample_id,
                    "local_linux_control_available": True,
                    "sample_class": "benign",
                    "network_required": False,
                    "local_linux_false_positive": False,
                    "unexpected_matched_rules": [],
                    "artifact_rows": artifacts,
                    "genesys2_board_trace_available": False,
                    "board_capture_required": True,
                    "accepted_as_board_benign_evidence": False,
                }
            )
        summary = {
            "schema": "rvmt.genesys2.board_benign_readiness.v1",
            "status": "PASS",
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "local_control_summary": {
                "id": "benign_control_summary",
                "path": local.relative_to(root).as_posix(),
                "exists": True,
                "sha256": sha256_file(local),
                "schema": "rvmt.genesys2.benign_control_summary.v1",
                "status": "PASS",
            },
            "trace_route_evidence": trace_rows,
            "expected_board_samples": sorted(EXPECTED_SAMPLES),
            "local_linux_control_aggregate": {
                "sample_count": 5,
                "non_network_sample_count": 5,
                "unexpected_false_positive_count": 0,
                "benign_false_positive_rate": 0.0,
            },
            "sample_readiness": sample_rows,
            "future_board_capture_plan": {
                "required_summary_schema": "rvmt.genesys2.board_benign_control.v1",
                "external_summary_path": "results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json",
                "minimum_accepted_board_samples": 5,
                "required_sample_ids": sorted(EXPECTED_SAMPLES),
                "required_per_sample_artifacts": ["board semantic_events behavior_graph behavior_audit uart"],
                "required_summary_fields": ["evidence_artifacts", "genesys2_board_trace_claimed", "sample_count", "benign_false_positive_rate", "samples"],
                "acceptance_criteria": ["five Genesys2/CVA6 samples with 0.0 false positive; local Linux is provenance only"],
            },
            "claim_boundary": {
                "board_benign_readiness_claimed": True,
                "local_linux_control_available": True,
                "genesys2_board_benign_control_claimed": False,
                "board_benign_false_positive_claimed": False,
                "local_linux_benign_substituted_for_board": False,
                "real_malware_validation_claimed": False,
                "board_capture_required_for_closure": True,
            },
            "non_claims": [
                "This is a readiness package and does not claim Genesys2 board benign-control evidence is complete.",
                "Local evidence must not be substituted for board-derived benign traces.",
            ],
            "failures": [],
        }
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] board benign readiness good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["genesys2_board_benign_control_claimed"] = True
        errors = check_summary(summary, root)
        if not errors:
            print("[FAIL] board benign readiness bad fixture passed", file=sys.stderr)
            return 1
        summary["claim_boundary"]["genesys2_board_benign_control_claimed"] = False
        summary["sample_readiness"][0]["artifact_rows"][0]["schema"] = "rvmt.behavior.semantic.v1"
        summary["sample_readiness"][0]["artifact_rows"][0]["status"] = None
        errors = check_summary(summary, root)
        if not any("status missing" in error for error in errors):
            print("[FAIL] board benign readiness missing artifact status fixture passed", file=sys.stderr)
            return 1
    print("[PASS] board benign readiness checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2 board benign-control readiness evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing board benign readiness summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] board benign readiness checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] board benign readiness summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] board benign readiness summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
