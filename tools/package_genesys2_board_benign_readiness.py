from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "board_benign_readiness_summary.json"

EXPECTED_BENIGN_SAMPLES = ("hello", "ls", "cat", "cp", "sha256sum")
REQUIRED_BENIGN_ARTIFACTS = (
    "strace_log",
    "stdout",
    "stderr",
    "semantic_events",
    "behavior_graph",
    "behavior_audit",
)
TRACE_ROUTE_SUMMARIES = (
    ("latest_manifest", "latest_manifest.json"),
    ("trace_sink", "trace_sink_summary.json"),
    ("p0_bram_trace", "p0_bram_trace_summary.json"),
    ("safe_surrogate_bram_trace", "safe_surrogate_bram_trace_summary.json"),
    ("drop_accounting", "drop_accounting_summary.json"),
    ("behavior_audit_metrics", "behavior_audit_metrics.json"),
)
DERIVED_STATUS_BY_SCHEMA = {
    "rvmt.behavior.semantic.v1": "DERIVED_SEMANTIC_EVENTS",
    "rvmt.behavior.graph.v1": "DERIVED_BEHAVIOR_GRAPH",
}


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_path(path: str | Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else ROOT / value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


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


def evidence_row(artifact_id: str, path_value: str | Path) -> dict[str, Any]:
    path = repo_path(path_value)
    row: dict[str, Any] = {
        "id": artifact_id,
        "path": repo_rel(path),
        "exists": path.is_file(),
        "sha256": sha256_file(path) if path.is_file() else None,
    }
    if path.suffix == ".json" and path.is_file():
        try:
            data = load_json(path)
        except Exception as exc:
            row["json_error"] = str(exc)
        else:
            row["schema"] = data.get("schema")
            row["status"] = data.get("status") or DERIVED_STATUS_BY_SCHEMA.get(str(data.get("schema") or ""))
    return row


def local_benign_sample_row(row: dict[str, Any]) -> dict[str, Any]:
    sample_id = str(row.get("sample_id"))
    artifact_rows = [evidence_row(key, str(row.get(key))) for key in REQUIRED_BENIGN_ARTIFACTS if row.get(key)]
    return {
        "sample_id": sample_id,
        "local_linux_control_available": row.get("status") == "PASS",
        "sample_class": row.get("sample_class"),
        "network_required": row.get("network_required"),
        "expected_behavior": as_list(row.get("expected_behavior")),
        "expected_syscalls": as_list(row.get("expected_syscalls")),
        "observed_syscalls": as_list(row.get("observed_syscalls")),
        "allowed_benign_rule_overlap": as_list(row.get("allowed_benign_rule_overlap")),
        "unexpected_matched_rules": as_list(row.get("unexpected_matched_rules")),
        "local_linux_false_positive": row.get("false_positive"),
        "artifact_rows": artifact_rows,
        "genesys2_board_trace_available": False,
        "board_capture_required": True,
        "accepted_as_board_benign_evidence": False,
    }


def package_summary(current_root: Path) -> dict[str, Any]:
    benign_path = current_root / "benign_control_summary.json"
    benign = load_json(ROOT / benign_path)
    sample_rows = {
        str(row.get("sample_id")): row
        for row in as_list(benign.get("samples"))
        if isinstance(row, dict) and row.get("sample_id")
    }
    samples = [local_benign_sample_row(sample_rows[sample_id]) for sample_id in EXPECTED_BENIGN_SAMPLES if sample_id in sample_rows]
    trace_route_rows = [evidence_row(artifact_id, current_root / filename) for artifact_id, filename in TRACE_ROUTE_SUMMARIES]
    failures: list[str] = []
    aggregate = as_dict(benign.get("aggregate"))
    if benign.get("status") != "PASS":
        failures.append("benign_control_summary status is not PASS")
    if set(sample_rows) & set(EXPECTED_BENIGN_SAMPLES) != set(EXPECTED_BENIGN_SAMPLES):
        failures.append("benign_control_summary does not contain the expected five benign samples")
    if as_int(aggregate.get("non_network_sample_count")) < len(EXPECTED_BENIGN_SAMPLES):
        failures.append("benign_control_summary has fewer than five non-network samples")
    if as_int(aggregate.get("unexpected_false_positive_count"), default=-1) != 0:
        failures.append("benign_control_summary reports unexpected false positives")
    if as_float(aggregate.get("benign_false_positive_rate"), default=1.0) != 0.0:
        failures.append("benign_control_summary false-positive rate is not 0.0")
    for sample in samples:
        if sample.get("network_required") is not False:
            failures.append(f"{sample['sample_id']}: network_required must be false")
        if sample.get("local_linux_control_available") is not True:
            failures.append(f"{sample['sample_id']}: local benign control is not PASS")
        if sample.get("local_linux_false_positive") is not False:
            failures.append(f"{sample['sample_id']}: local false-positive flag must be false")
        for artifact in as_list(sample.get("artifact_rows")):
            if artifact.get("exists") is not True:
                failures.append(f"{sample['sample_id']}: missing local artifact {artifact.get('path')}")
    for row in trace_route_rows:
        if row.get("exists") is not True:
            failures.append(f"missing trace-route/readiness artifact {row.get('path')}")

    return {
        "schema": "rvmt.genesys2.board_benign_readiness.v1",
        "status": "PASS" if not failures else "FAIL",
        "canonical_evaluation_root": repo_rel(ROOT / current_root),
        "scope": "readiness package for future Genesys2/CVA6 board benign-control false-positive evidence",
        "local_control_summary": evidence_row("benign_control_summary", benign_path),
        "trace_route_evidence": trace_route_rows,
        "expected_board_samples": list(EXPECTED_BENIGN_SAMPLES),
        "local_linux_control_aggregate": {
            "sample_count": aggregate.get("sample_count"),
            "non_network_sample_count": aggregate.get("non_network_sample_count"),
            "unexpected_false_positive_count": aggregate.get("unexpected_false_positive_count"),
            "benign_false_positive_rate": aggregate.get("benign_false_positive_rate"),
            "allowed_overlap_count": aggregate.get("allowed_overlap_count"),
        },
        "sample_readiness": samples,
        "future_board_capture_plan": {
            "required_summary_schema": "rvmt.genesys2.board_benign_control.v1",
            "external_summary_path": "results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json",
            "minimum_accepted_board_samples": len(EXPECTED_BENIGN_SAMPLES),
            "required_sample_ids": list(EXPECTED_BENIGN_SAMPLES),
            "trace_route": "current Genesys2/CVA6 trace route with BRAM marker windows unless superseded by an accepted non-BRAM external trace route",
            "required_per_sample_artifacts": [
                "board bram_records.jsonl or accepted external trace records",
                "capture.log",
                "uart.log",
                "board-derived semantic_events.json",
                "board-derived behavior_graph.json",
                "board-derived behavior_audit.json",
                "allowed benign overlap report",
            ],
            "required_summary_fields": [
                "evidence_artifacts",
                "genesys2_board_trace_claimed",
                "sample_count",
                "unexpected_false_positive_count",
                "benign_false_positive_rate",
                "samples",
            ],
            "acceptance_criteria": [
                "at least five non-network benign workloads run on Genesys2/CVA6 under the accepted trace route",
                "each accepted sample has board-derived semantic events, behavior graph, and behavior audit artifacts",
                "unexpected false-positive count is 0 and benign_false_positive_rate is 0.0",
                "allowed benign rule overlaps are listed separately from unexpected matches",
                "local Linux strace artifacts are provenance only and are not counted as board benign evidence",
            ],
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
        "validation_commands": [
            "uv run python tools/package_genesys2_board_benign_readiness.py",
            "uv run python tools/check_genesys2_board_benign_readiness.py --root .",
        ],
        "non_claims": [
            "This is a readiness package and does not claim Genesys2 board benign-control evidence is complete.",
            "Local Linux benign-control strace evidence must not be substituted for board-derived benign traces.",
            "The local false-positive rate is not malware detection accuracy and is not real-malware validation.",
            "The future board closure gate remains OPEN_EXTERNAL_ARTIFACTS_REQUIRED until external board artifacts are accepted.",
        ],
        "failures": failures,
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        artifact = root / "artifact.json"
        write_json(artifact, {"schema": "rvmt.fixture.v1", "status": "PASS"})
        row = evidence_row("fixture", artifact)
    if row.get("exists") is not True or row.get("schema") != "rvmt.fixture.v1" or not row.get("sha256"):
        print("[FAIL] board benign readiness packager self-test failed", file=sys.stderr)
        return 1
    print("[PASS] board benign readiness packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package readiness evidence for future Genesys2 board benign-control runs.")
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        summary = package_summary(args.current_root)
        write_json(ROOT / args.out, summary)
    except Exception as exc:
        print(f"package_genesys2_board_benign_readiness: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote board benign readiness summary to {args.out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
