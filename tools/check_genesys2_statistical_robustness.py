from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import package_genesys2_statistical_robustness as packager


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/statistical_robustness_summary.json")
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
EXPECTED_SCHEMA = "rvmt.genesys2.statistical_robustness.v1"
EXPECTED_ROW_SAMPLE_CLASSES = {
    "p0_bram_repetitions": "p0_safe_synthetic",
    "safe_surrogate_bram_repetitions": "malware_like_synthetic_syscall_only",
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


def row_map(rows: list[Any], key: str = "id") -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get(key), str) and row.get(key):
            result[str(row[key])] = row
    return result


def check_summary(data: dict[str, Any], root: Path, current_root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == EXPECTED_SCHEMA, "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(errors, data.get("evidence_scope") == "controlled_safe_surrogate_marker_window_repetition_audit", "evidence scope mismatch")

    expected = packager.package_summary(root, current_root)
    require(errors, expected.get("status") == "PASS", "recomputed statistical robustness summary must pass")
    for key in ("aggregate", "cohorts", "sample_repetition_rows", "retained_failed_attempts", "workload_classes"):
        require(errors, data.get(key) == expected.get(key), f"{key} does not match source summaries")

    aggregate = as_dict(data.get("aggregate"))
    require(errors, aggregate.get("board_sample_count") == 12, "expected 12 board samples")
    require(errors, aggregate.get("p0_sample_count") == 4, "expected 4 P0 samples")
    require(errors, aggregate.get("safe_surrogate_sample_count") == 8, "expected 8 safe-surrogate samples")
    require(errors, aggregate.get("accepted_board_repetitions") == 120, "expected 120 accepted board repetitions")
    require(errors, aggregate.get("board_attempt_count") == 121, "expected 121 board attempts including retained failure")
    require(errors, aggregate.get("retained_failed_attempt_count") == 1, "expected one retained failed board attempt")
    require(errors, aggregate.get("min_accepted_repetitions_per_board_sample") == 10, "expected at least 10 accepted repetitions per board sample")
    require(errors, aggregate.get("max_accepted_unaccounted_drop") == 0, "accepted repetitions must have zero unaccounted DROP")
    require(errors, aggregate.get("max_accepted_wrap_count") == 0, "accepted repetitions must have zero BRAM wrap")
    require(errors, aggregate.get("max_accepted_bram_dropped_count") == 0, "accepted repetitions must have zero BRAM dropped count")
    require(errors, aggregate.get("sequence_gap_sample_count") == 0, "accepted repetitions must have no sequence-gap samples")
    require(errors, aggregate.get("case_study_count") == 12, "expected 12 case studies")
    require(errors, aggregate.get("benign_control_sample_count") >= 5, "expected at least 5 benign controls")
    require(errors, aggregate.get("unexpected_benign_false_positive_count") == 0, "unexpected benign false positives must be zero")
    require(errors, aggregate.get("benign_false_positive_rate") == 0.0, "benign false-positive rate must be 0.0")

    cohorts = row_map(as_list(data.get("cohorts")))
    require(errors, set(cohorts) == {"p0_bram_repetitions", "safe_surrogate_bram_repetitions"}, "cohort ids mismatch")
    if "p0_bram_repetitions" in cohorts:
        p0 = cohorts["p0_bram_repetitions"]
        require(errors, p0.get("sample_count") == 4, "P0 cohort sample count mismatch")
        require(errors, p0.get("accepted_repetitions") == 40, "P0 cohort accepted repetition count mismatch")
        require(errors, p0.get("failed_attempt_count") == 1, "P0 cohort failed attempt count mismatch")
    if "safe_surrogate_bram_repetitions" in cohorts:
        safe = cohorts["safe_surrogate_bram_repetitions"]
        require(errors, safe.get("sample_count") == 8, "safe-surrogate cohort sample count mismatch")
        require(errors, safe.get("accepted_repetitions") == 80, "safe-surrogate accepted repetition count mismatch")
        require(errors, safe.get("failed_attempt_count") == 0, "safe-surrogate failed attempt count mismatch")

    sample_rows = as_list(data.get("sample_repetition_rows"))
    require(errors, len(sample_rows) == 12, "expected one repetition row per board sample")
    for row in sample_rows:
        if not isinstance(row, dict):
            errors.append("sample repetition rows must be objects")
            continue
        require(errors, row.get("accepted_repetitions") == 10, f"{row.get('sample_id')}: expected 10 accepted repetitions")
        require(errors, row.get("max_accepted_unaccounted_drop") == 0, f"{row.get('sample_id')}: accepted unaccounted DROP must be zero")
        require(errors, row.get("max_accepted_wrap_count") == 0, f"{row.get('sample_id')}: accepted wrap count must be zero")
        require(errors, row.get("sequence_gap_repetition_count") == 0, f"{row.get('sample_id')}: sequence gaps must be zero")
        expected_class = EXPECTED_ROW_SAMPLE_CLASSES.get(str(row.get("cohort_id") or ""))
        require(errors, bool(row.get("sample_class")), f"{row.get('sample_id')}: sample_class must be explicit")
        if expected_class:
            require(errors, row.get("sample_class") == expected_class, f"{row.get('sample_id')}: sample_class/cohort mismatch")

    failures = as_list(data.get("retained_failed_attempts"))
    require(errors, len(failures) == 1, "expected exactly one retained failed attempt")
    if failures:
        failure = as_dict(failures[0])
        require(errors, failure.get("sample_id") == "fork_exec", "retained failed attempt must be fork_exec")
        require(errors, failure.get("repetition") == "rep_03", "retained failed attempt id mismatch")
        reasons = set(as_list(failure.get("reason")))
        require(errors, {"begin_marker_count_not_one", "bram_ring_full", "bram_wrap_count_nonzero"} <= reasons, "retained failure reasons are incomplete")
        for key in ("bram_records", "bram_summary", "capture_log", "uart_log"):
            require(errors, bool(failure.get(key)), f"retained failure missing artifact path: {key}")

    source_rows = row_map(as_list(data.get("source_summaries")))
    require(errors, {"p0_bram_trace", "safe_surrogate_bram_trace", "drop_accounting", "case_study_manifest", "benign_control"} <= set(source_rows), "source summary coverage mismatch")
    for source_id, row in source_rows.items():
        path_value = row.get("path")
        require(errors, bool(path_value), f"{source_id}: source path missing")
        if path_value:
            path = repo_path(root, path_value)
            require(errors, path.is_file(), f"{source_id}: source file missing: {path_value}")
            if path.is_file():
                source = load_json(path)
                require(errors, source.get("status") == "PASS", f"{source_id}: source status must be PASS")
                require(errors, source.get("schema") == row.get("schema"), f"{source_id}: source schema mismatch")
        require(errors, "uv run python" in str(row.get("checker_command") or ""), f"{source_id}: checker command missing")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("controlled_repetition_robustness_claimed") is True, "controlled robustness claim missing")
    require(errors, boundary.get("randomized_workload_generalization_claimed") is False, "randomized generalization must not be claimed")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("real_malware_generalization_claimed") is False, "real malware generalization must not be claimed")
    require(errors, boundary.get("malware_detection_accuracy_claimed") is False, "malware detection accuracy must not be claimed")
    require(errors, boundary.get("production_long_run_stability_claimed") is False, "production long-run stability must not be claimed")
    require(errors, boundary.get("production_streaming_dma_throughput_claimed") is False, "production streaming/DMA must not be claimed")
    require(errors, boundary.get("retained_failed_attempts_counted_as_pass") is False, "failed attempts must not be counted as pass")

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not a randomized workload generalization study" in non_claims, "randomized generalization non-claim missing")
    require(errors, "does not add real-malware validation" in non_claims, "real malware non-claim missing")
    require(errors, "does not close production long-run stability" in non_claims, "production stability non-claim missing")
    require(errors, "not genesys2 board benign-control evidence" in non_claims, "board benign non-claim missing")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_statistical_robustness.py" in commands, "packager validation command missing")
    require(errors, "tools/check_genesys2_statistical_robustness.py --root ." in commands, "checker validation command missing")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        packager.write_json(current / "p0_bram_trace_summary.json", packager.fixture_board_summary(4, "p0_safe_synthetic", "p0", failed=True))
        packager.write_json(current / "safe_surrogate_bram_trace_summary.json", packager.fixture_board_summary(8, "malware_like_synthetic_syscall_only", "safe"))
        packager.write_json(current / "drop_accounting_summary.json", {"schema": "fixture", "status": "PASS", "max_unaccounted_drop": 0})
        packager.write_json(
            current / "case_study_manifest.json",
            {
                "schema": "fixture",
                "status": "PASS",
                "case_study_count": 12,
                "case_studies": [
                    {"sample_id": f"sample_{index}", "sample_class": "p0_safe_synthetic" if index < 4 else "malware_like_synthetic_syscall_only"}
                    for index in range(12)
                ],
            },
        )
        packager.write_json(
            current / "benign_control_summary.json",
            {
                "schema": "fixture",
                "status": "PASS",
                "aggregate": {"sample_count": 5, "benign_false_positive_rate": 0.0, "unexpected_false_positive_count": 0},
                "samples": [{"sample_id": f"benign_{index}"} for index in range(5)],
            },
        )
        summary = packager.package_summary(root, current)
        errors = check_summary(summary, root, current)
        if errors:
            print("[FAIL] statistical robustness good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["randomized_workload_generalization_claimed"] = True
        errors = check_summary(summary, root, current)
        if not any("randomized generalization" in error for error in errors):
            print("[FAIL] statistical robustness overclaim fixture passed", file=sys.stderr)
            return 1
        summary = packager.package_summary(root, current)
        summary["aggregate"]["accepted_board_repetitions"] = 119
        errors = check_summary(summary, root, current)
        if not any("120 accepted" in error or "aggregate does not match" in error for error in errors):
            print("[FAIL] statistical robustness count mismatch fixture passed", file=sys.stderr)
            return 1
        summary = packager.package_summary(root, current)
        summary["sample_repetition_rows"][4]["sample_class"] = None
        errors = check_summary(summary, root, current)
        if not any("sample_class" in error for error in errors):
            print("[FAIL] statistical robustness missing sample_class fixture passed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 statistical robustness checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the current Genesys2/CVA6 statistical robustness summary.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    current_root = args.current_root if args.current_root.is_absolute() else root / args.current_root
    if not path.is_file():
        print(f"[FAIL] missing statistical robustness summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root, current_root)
    except Exception as exc:
        print(f"[FAIL] statistical robustness checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] statistical robustness summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] statistical robustness summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
