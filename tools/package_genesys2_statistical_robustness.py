from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "statistical_robustness_summary.json"
DEFAULT_COHORT_SAMPLE_CLASSES = {
    "p0_bram_repetitions": "p0_safe_synthetic",
    "safe_surrogate_bram_repetitions": "malware_like_synthetic_syscall_only",
}


def repo_rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    return default


def integer(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return default


def source_row(current_root: Path, artifact_id: str, filename: str, checker: str) -> dict[str, Any]:
    path = current_root / filename
    data = load_json(path)
    return {
        "id": artifact_id,
        "path": repo_rel(ROOT, path),
        "schema": data.get("schema"),
        "status": data.get("status"),
        "checker_command": checker,
    }


def accepted_repetitions(sample: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in as_list(sample.get("repetitions")) if isinstance(row, dict)]


def failed_attempts(sample: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in as_list(sample.get("failed_attempts")) if isinstance(row, dict)]


def max_from_rows(rows: list[dict[str, Any]], *keys: str) -> int:
    values: list[int] = []
    for row in rows:
        value: Any = row
        for key in keys:
            value = as_dict(value).get(key)
        values.append(integer(value))
    return max(values) if values else 0


def sample_row(sample: dict[str, Any], cohort_id: str, default_sample_class: str | None = None) -> dict[str, Any]:
    reps = accepted_repetitions(sample)
    failures = failed_attempts(sample)
    stats = as_dict(sample.get("attempt_statistics"))
    sample_class = sample.get("sample_class") or (reps[0].get("sample_class") if reps else None) or default_sample_class
    return {
        "cohort_id": cohort_id,
        "sample_id": sample.get("sample_id"),
        "sample_class": sample_class,
        "accepted_repetitions": integer(sample.get("pass_repetition_count"), len(reps)),
        "attempt_count": integer(sample.get("attempt_count"), len(reps) + len(failures)),
        "failed_attempt_count": integer(sample.get("failed_attempt_count"), len(failures)),
        "minimum_repetitions": integer(sample.get("minimum_repetitions")),
        "max_accepted_unaccounted_drop": max_from_rows(reps, "unaccounted_drop"),
        "max_accepted_wrap_count": max_from_rows(reps, "bram_ring", "wrap_count"),
        "max_accepted_bram_dropped_count": max_from_rows(reps, "bram_ring", "dropped_count"),
        "sequence_gap_repetition_count": sum(1 for row in reps if as_list(row.get("sequence_gaps"))),
        "event_count_stats": as_dict(stats.get("event_count")),
        "marker_window_cycle_stats": as_dict(stats.get("marker_window_cycles")),
    }


def failure_reason(row: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    marker = as_dict(row.get("marker_window"))
    bram = as_dict(row.get("bram_ring"))
    if row.get("parse_success") is False:
        reasons.append("parse_success_false")
    if integer(marker.get("begin_count")) != 1:
        reasons.append("begin_marker_count_not_one")
    if integer(marker.get("end_count")) != 1:
        reasons.append("end_marker_count_not_one")
    if bram.get("full") is True:
        reasons.append("bram_ring_full")
    if integer(bram.get("wrap_count")) > 0:
        reasons.append("bram_wrap_count_nonzero")
    if integer(bram.get("dropped_count")) > 0:
        reasons.append("bram_dropped_count_nonzero")
    if integer(row.get("unaccounted_drop")) > 0:
        reasons.append("unaccounted_drop_nonzero")
    if as_list(row.get("sequence_gaps")):
        reasons.append("sequence_gaps_present")
    return reasons or ["retained_failed_attempt"]


def failure_rows(summary: dict[str, Any], cohort_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sample in as_list(summary.get("samples")):
        if not isinstance(sample, dict):
            continue
        for row in failed_attempts(sample):
            artifacts = as_dict(row.get("artifacts"))
            rows.append(
                {
                    "cohort_id": cohort_id,
                    "sample_id": row.get("sample_id") or sample.get("sample_id"),
                    "sample_class": row.get("sample_class") or sample.get("sample_class"),
                    "repetition": row.get("repetition"),
                    "reason": failure_reason(row),
                    "bram_records": artifacts.get("bram_records"),
                    "bram_summary": artifacts.get("bram_summary"),
                    "capture_log": artifacts.get("capture_log"),
                    "uart_log": artifacts.get("uart_log"),
                    "wrap_count": integer(as_dict(row.get("bram_ring")).get("wrap_count")),
                    "bram_dropped_count": integer(as_dict(row.get("bram_ring")).get("dropped_count")),
                    "unaccounted_drop": integer(row.get("unaccounted_drop")),
                }
            )
    return rows


def cohort_row(summary: dict[str, Any], cohort_id: str, label: str) -> dict[str, Any]:
    default_sample_class = DEFAULT_COHORT_SAMPLE_CLASSES.get(cohort_id)
    rows = [
        sample_row(sample, cohort_id, default_sample_class)
        for sample in as_list(summary.get("samples"))
        if isinstance(sample, dict)
    ]
    accepted = sum(integer(row.get("accepted_repetitions")) for row in rows)
    attempts = sum(integer(row.get("attempt_count")) for row in rows)
    failed = sum(integer(row.get("failed_attempt_count")) for row in rows)
    return {
        "id": cohort_id,
        "label": label,
        "run_root": summary.get("run_root"),
        "sample_count": len(rows),
        "minimum_repetitions_per_sample": integer(summary.get("minimum_repetitions_per_sample")),
        "accepted_repetitions": accepted,
        "attempt_count": attempts,
        "failed_attempt_count": failed,
        "min_accepted_repetitions_per_sample": min((integer(row.get("accepted_repetitions")) for row in rows), default=0),
        "max_accepted_repetitions_per_sample": max((integer(row.get("accepted_repetitions")) for row in rows), default=0),
        "max_accepted_unaccounted_drop": max((integer(row.get("max_accepted_unaccounted_drop")) for row in rows), default=0),
        "max_accepted_wrap_count": max((integer(row.get("max_accepted_wrap_count")) for row in rows), default=0),
        "max_accepted_bram_dropped_count": max((integer(row.get("max_accepted_bram_dropped_count")) for row in rows), default=0),
        "sequence_gap_sample_count": sum(1 for row in rows if integer(row.get("sequence_gap_repetition_count")) > 0),
        "sample_ids": [row.get("sample_id") for row in rows],
    }


def workload_class_rows(case_manifest: dict[str, Any], benign: dict[str, Any]) -> list[dict[str, Any]]:
    classes: dict[str, set[str]] = {}
    for row in as_list(case_manifest.get("case_studies")):
        if not isinstance(row, dict):
            continue
        sample_class = str(row.get("sample_class") or "unknown")
        sample_id = str(row.get("sample_id") or "")
        classes.setdefault(sample_class, set()).add(sample_id)
    benign_ids = {
        str(row.get("sample_id"))
        for row in as_list(benign.get("samples"))
        if isinstance(row, dict) and row.get("sample_id")
    }
    if benign_ids:
        classes["local_linux_benign_control"] = benign_ids
    return [
        {"sample_class": key, "sample_count": len(sorted(value)), "sample_ids": sorted(value)}
        for key, value in sorted(classes.items())
    ]


def package_summary(repo_root: Path, current_root: Path) -> dict[str, Any]:
    p0 = load_json(current_root / "p0_bram_trace_summary.json")
    safe = load_json(current_root / "safe_surrogate_bram_trace_summary.json")
    drop = load_json(current_root / "drop_accounting_summary.json")
    case_manifest = load_json(current_root / "case_study_manifest.json")
    benign = load_json(current_root / "benign_control_summary.json")

    p0_cohort = cohort_row(p0, "p0_bram_repetitions", "P0 safe synthetic board marker-window repetitions")
    safe_cohort = cohort_row(safe, "safe_surrogate_bram_repetitions", "Safe surrogate board marker-window repetitions")
    sample_rows = [
        *[
            sample_row(sample, "p0_bram_repetitions", DEFAULT_COHORT_SAMPLE_CLASSES["p0_bram_repetitions"])
            for sample in as_list(p0.get("samples"))
            if isinstance(sample, dict)
        ],
        *[
            sample_row(
                sample,
                "safe_surrogate_bram_repetitions",
                DEFAULT_COHORT_SAMPLE_CLASSES["safe_surrogate_bram_repetitions"],
            )
            for sample in as_list(safe.get("samples"))
            if isinstance(sample, dict)
        ],
    ]
    retained_failures = [
        *failure_rows(p0, "p0_bram_repetitions"),
        *failure_rows(safe, "safe_surrogate_bram_repetitions"),
    ]
    accepted_repetitions = p0_cohort["accepted_repetitions"] + safe_cohort["accepted_repetitions"]
    attempt_count = p0_cohort["attempt_count"] + safe_cohort["attempt_count"]
    failed_attempt_count = p0_cohort["failed_attempt_count"] + safe_cohort["failed_attempt_count"]
    workload_classes = workload_class_rows(case_manifest, benign)
    benign_aggregate = as_dict(benign.get("aggregate"))
    aggregate = {
        "board_sample_count": p0_cohort["sample_count"] + safe_cohort["sample_count"],
        "p0_sample_count": p0_cohort["sample_count"],
        "safe_surrogate_sample_count": safe_cohort["sample_count"],
        "accepted_board_repetitions": accepted_repetitions,
        "board_attempt_count": attempt_count,
        "retained_failed_attempt_count": failed_attempt_count,
        "min_accepted_repetitions_per_board_sample": min(
            p0_cohort["min_accepted_repetitions_per_sample"],
            safe_cohort["min_accepted_repetitions_per_sample"],
        ),
        "max_accepted_unaccounted_drop": max(
            p0_cohort["max_accepted_unaccounted_drop"],
            safe_cohort["max_accepted_unaccounted_drop"],
            integer(drop.get("max_unaccounted_drop")),
        ),
        "max_accepted_wrap_count": max(p0_cohort["max_accepted_wrap_count"], safe_cohort["max_accepted_wrap_count"]),
        "max_accepted_bram_dropped_count": max(
            p0_cohort["max_accepted_bram_dropped_count"],
            safe_cohort["max_accepted_bram_dropped_count"],
        ),
        "sequence_gap_sample_count": p0_cohort["sequence_gap_sample_count"] + safe_cohort["sequence_gap_sample_count"],
        "case_study_count": integer(case_manifest.get("case_study_count")),
        "benign_control_sample_count": integer(benign_aggregate.get("sample_count")),
        "benign_false_positive_rate": number(benign_aggregate.get("benign_false_positive_rate")),
        "unexpected_benign_false_positive_count": integer(benign_aggregate.get("unexpected_false_positive_count")),
        "workload_class_count": len(workload_classes),
    }
    status = "PASS"
    if any(data.get("status") != "PASS" for data in (p0, safe, drop, case_manifest, benign)):
        status = "FAIL"
    if aggregate["board_sample_count"] != 12 or aggregate["accepted_board_repetitions"] != 120:
        status = "FAIL"
    if aggregate["min_accepted_repetitions_per_board_sample"] < 10:
        status = "FAIL"
    if aggregate["max_accepted_unaccounted_drop"] != 0 or aggregate["max_accepted_wrap_count"] != 0:
        status = "FAIL"
    if aggregate["case_study_count"] < 12 or aggregate["benign_control_sample_count"] < 5:
        status = "FAIL"
    if aggregate["unexpected_benign_false_positive_count"] != 0:
        status = "FAIL"
    if len(retained_failures) != failed_attempt_count:
        status = "FAIL"

    return {
        "schema": "rvmt.genesys2.statistical_robustness.v1",
        "status": status,
        "canonical_evaluation_root": repo_rel(repo_root, current_root),
        "evidence_scope": "controlled_safe_surrogate_marker_window_repetition_audit",
        "source_summaries": [
            source_row(current_root, "p0_bram_trace", "p0_bram_trace_summary.json", "uv run python tools/check_genesys2_p0_bram_trace.py --root ."),
            source_row(current_root, "safe_surrogate_bram_trace", "safe_surrogate_bram_trace_summary.json", "uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root ."),
            source_row(current_root, "drop_accounting", "drop_accounting_summary.json", "uv run python tools/check_trace_drop_accounting.py --root ."),
            source_row(current_root, "case_study_manifest", "case_study_manifest.json", "uv run python tools/check_ccfa_case_study_manifest.py --root ."),
            source_row(current_root, "benign_control", "benign_control_summary.json", "uv run python tools/check_benign_control_summary.py --root ."),
        ],
        "cohorts": [p0_cohort, safe_cohort],
        "sample_repetition_rows": sample_rows,
        "retained_failed_attempts": retained_failures,
        "workload_classes": workload_classes,
        "aggregate": aggregate,
        "claim_boundary": {
            "controlled_repetition_robustness_claimed": True,
            "randomized_workload_generalization_claimed": False,
            "real_malware_validation_claimed": False,
            "real_malware_generalization_claimed": False,
            "malware_detection_accuracy_claimed": False,
            "production_long_run_stability_claimed": False,
            "production_streaming_dma_throughput_claimed": False,
            "retained_failed_attempts_counted_as_pass": False,
        },
        "allowed_claims": [
            "The current controlled Genesys2/CVA6 board evidence contains 120 accepted marker-window repetitions across 12 safe/surrogate board samples, with at least 10 accepted repetitions per board sample.",
            "Accepted board repetitions have zero unaccounted DROP, zero BRAM wrap, and no sequence-gap samples under the captured-window criteria.",
            "One failed P0 board attempt is retained as failure evidence and is not counted as an accepted PASS repetition.",
            "The current local benign-control set contains at least five benign workloads with zero unexpected false positives under the controlled local Linux audit.",
        ],
        "non_claims": [
            "This summary is a controlled repetition and failure-retention audit; it is not a randomized workload generalization study.",
            "This summary does not add real-malware validation, malware-family coverage, or malware detection accuracy.",
            "This summary does not close production long-run stability or production streaming/DMA trace sink throughput.",
            "Local Linux benign controls are not Genesys2 board benign-control evidence.",
        ],
        "validation_commands": [
            "uv run python tools/package_genesys2_statistical_robustness.py",
            "uv run python tools/check_genesys2_statistical_robustness.py --root .",
            "uv run python tools/run_check_suite.py --suite genesys2-current",
        ],
    }


def fixture_board_summary(sample_count: int, sample_class: str, prefix: str, failed: bool = False) -> dict[str, Any]:
    samples = []
    for index in range(sample_count):
        sample_id = "fork_exec" if failed and index == 0 else f"{prefix}_{index + 1}"
        reps = [
            {
                "sample_id": sample_id,
                "sample_class": sample_class,
                "repetition": f"rep_{rep + 1:02d}",
                "bram_ring": {"wrap_count": 0, "dropped_count": 0},
                "sequence_gaps": [],
                "unaccounted_drop": 0,
            }
            for rep in range(10)
        ]
        failures: list[dict[str, Any]] = []
        if failed and index == 0:
            failures.append(
                {
                    "sample_id": sample_id,
                    "sample_class": sample_class,
                    "repetition": "rep_03",
                    "parse_success": False,
                    "marker_window": {"begin_count": 0, "end_count": 1},
                    "bram_ring": {"full": True, "wrap_count": 4, "dropped_count": 1},
                    "unaccounted_drop": 1,
                    "sequence_gaps": [],
                    "artifacts": {
                        "bram_records": "raw/bram_records.jsonl",
                        "bram_summary": "raw/bram_summary.json",
                        "capture_log": "raw/capture.log",
                        "uart_log": "raw/uart.log",
                    },
                }
            )
        samples.append(
            {
                "sample_id": sample_id,
                "sample_class": sample_class,
                "minimum_repetitions": 10,
                "pass_repetition_count": 10,
                "attempt_count": 10 + len(failures),
                "failed_attempt_count": len(failures),
                "repetitions": reps,
                "failed_attempts": failures,
                "attempt_statistics": {"event_count": {"min": 1, "median": 1, "max": 1}},
            }
        )
    return {
        "schema": "fixture",
        "status": "PASS",
        "run_root": f"raw/{prefix}",
        "minimum_repetitions_per_sample": 10,
        "samples": samples,
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        write_json(current / "p0_bram_trace_summary.json", fixture_board_summary(4, "p0_safe_synthetic", "p0", failed=True))
        safe_fixture = fixture_board_summary(8, "malware_like_synthetic_syscall_only", "safe")
        for sample in safe_fixture["samples"]:
            sample.pop("sample_class", None)
            for rep in sample["repetitions"]:
                rep.pop("sample_class", None)
        write_json(current / "safe_surrogate_bram_trace_summary.json", safe_fixture)
        write_json(current / "drop_accounting_summary.json", {"schema": "fixture", "status": "PASS", "max_unaccounted_drop": 0})
        write_json(
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
        write_json(
            current / "benign_control_summary.json",
            {
                "schema": "fixture",
                "status": "PASS",
                "aggregate": {"sample_count": 5, "benign_false_positive_rate": 0.0, "unexpected_false_positive_count": 0},
                "samples": [{"sample_id": f"benign_{index}"} for index in range(5)],
            },
        )
        summary = package_summary(root, current)
        if summary.get("status") != "PASS":
            print("[FAIL] expected statistical robustness fixture to pass", file=sys.stderr)
            return 1
        if summary.get("aggregate", {}).get("accepted_board_repetitions") != 120:
            print("[FAIL] expected 120 accepted fixture repetitions", file=sys.stderr)
            return 1
        if len(summary.get("retained_failed_attempts", [])) != 1:
            print("[FAIL] expected retained failed attempt fixture", file=sys.stderr)
            return 1
        sample_classes = {
            row.get("sample_class")
            for row in summary.get("sample_repetition_rows", [])
            if row.get("cohort_id") == "safe_surrogate_bram_repetitions"
        }
        if sample_classes != {"malware_like_synthetic_syscall_only"}:
            print("[FAIL] expected safe-surrogate sample class fallback", file=sys.stderr)
            return 1
        bad = load_json(current / "safe_surrogate_bram_trace_summary.json")
        bad["samples"][0]["repetitions"][0]["unaccounted_drop"] = 1
        write_json(current / "safe_surrogate_bram_trace_summary.json", bad)
        summary = package_summary(root, current)
        if summary.get("status") != "FAIL":
            print("[FAIL] bad statistical robustness fixture passed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 statistical robustness packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package the current Genesys2/CVA6 statistical robustness summary.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.root.resolve()
    current_root = args.current_root if args.current_root.is_absolute() else repo_root / args.current_root
    out = args.out if args.out.is_absolute() else repo_root / args.out
    try:
        summary = package_summary(repo_root, current_root)
        write_json(out, summary)
    except Exception as exc:
        print(f"package_genesys2_statistical_robustness: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote Genesys2 statistical robustness summary to {out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
