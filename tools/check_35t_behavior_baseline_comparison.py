from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_MATRIX = Path("experiments/linux_behavior/real_malware_surrogate/behavior_lineage_matrix.json")
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence/35t-real-malware-derived-baseline-comparison-20260524")
RESULTS_BASE = Path("results/experiments/35t")
SCHEMA = "rvmt.35t.real_malware_derived_baseline_comparison.v1"
PASS_STATUS = "REAL_MALWARE_DERIVED_BASELINE_COMPARISON_PASS"
FAIL_STATUS = "FAIL"
BASELINE_KEYS = ("host_native", "host_strace", "qemu_native", "qemu_strace")
SNAPSHOT_FILES = (
    "README.md",
    "baseline_comparison.json",
    "baseline_comparison.md",
    "baseline_comparison.csv",
)
NON_CLAIMS = [
    "same-set baseline comparison only",
    "not true real-malware execution",
    "not qemu-plugin or eBPF advanced baseline evidence",
    "not a performance-equivalence claim",
    "not malware-family detection accuracy",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def read_json(path: Path, failures: list[str], repo_root: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return {}
    try:
        return load_json(path)
    except Exception as exc:
        failures.append(f"invalid {label}: {rel(path, repo_root)}: {exc}")
        return {}


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path, repo_root: Path) -> dict[str, Any]:
    return {"path": rel(path, repo_root), "bytes": path.stat().st_size, "sha256": file_digest(path)}


def class_digest(files: list[Path], repo_root: Path) -> str | None:
    if not files:
        return None
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: rel(item, repo_root)):
        digest.update(rel(path, repo_root).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(path.stat().st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_digest(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def dict_rows(value: Any) -> list[dict[str, Any]]:
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def rows_by_id(rows: list[dict[str, Any]], key: str = "sample_id") -> dict[str, dict[str, Any]]:
    return {str(row[key]): row for row in rows if row.get(key)}


def median_value(value: Any) -> float | None:
    if isinstance(value, dict):
        value = value.get("median")
    if isinstance(value, (int, float)):
        return float(value)
    return None


def positive_number(value: float | None) -> bool:
    return value is not None and value > 0


def safe_ratio(numerator: float | None, denominator: float | None) -> float | None:
    if numerator is None or denominator in (None, 0):
        return None
    return round(numerator / denominator, 6)


def gate_rows_by_sample(gate: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return rows_by_id(dict_rows(gate.get("samples", [])))


def check_gate_sample(gate_row: dict[str, Any], expected_behavior: list[str]) -> dict[str, Any]:
    row_checks = gate_row.get("checks", {}) if isinstance(gate_row.get("checks"), dict) else {}
    sample_status = gate_row.get("sample_status", {}) if isinstance(gate_row.get("sample_status"), dict) else {}
    matched = [str(item) for item in gate_row.get("matched_expected", [])] if isinstance(gate_row.get("matched_expected"), list) else []
    checks = {
        "sample_present": bool(gate_row),
        "status_pass": gate_row.get("status") == "PASS",
        "gate_status_pass": gate_row.get("gate_status") == "PASS",
        "sample_status_pass": sample_status.get("status") == "PASS",
        "trace_on_5_of_5": int(sample_status.get("trace_on_pass") or 0) >= 5,
        "trace_artifacts_5_of_5": int(gate_row.get("trace_artifact_count") or 0) >= 5,
        "semantic_artifacts_5_of_5": int(gate_row.get("semantic_artifact_count") or 0) >= 5,
        "behavior_audit_artifacts_5_of_5": int(gate_row.get("behavior_audit_artifact_count") or 0) >= 5,
        "unknown_corrupt_zero": int(gate_row.get("unknown_event_count") or 0) == 0
        and int(gate_row.get("corrupt_record_count") or 0) == 0,
        "drop_rate_median_le_5pct": float(gate_row.get("drop_rate_median") or 0.0) <= 0.05,
        "strong_expected_behavior_matched": row_checks.get("strong_expected_behavior_matched") is True,
        "expected_behavior_in_matched": set(expected_behavior) <= set(matched),
        "runtime_process_attribution_pass": row_checks.get("runtime_process_attribution_pass") is True,
        "marker_scope_pass": row_checks.get("marker_scope_pass") is True,
        "no_trace_cap_hit": row_checks.get("no_trace_cap_hit") is True,
    }
    return {"status": "PASS" if all(checks.values()) else "FAIL", "checks": checks, "matched_expected": matched}


def check_row(
    repo_root: Path,
    row: dict[str, Any],
    *,
    matrix: dict[str, Any],
    metrics_by_run_key: dict[str, dict[str, Any]],
    gates_by_run_key: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    lineage_id = str(row.get("lineage_id") or "unknown")
    sample_id = str(row.get("sample_id") or "")
    run_key = str(row.get("run_key") or "")
    expected_behavior = [str(item) for item in row.get("expected_behavior", [])] if isinstance(row.get("expected_behavior"), list) else []
    failures: list[str] = []

    runs = matrix.get("runs", {}) if isinstance(matrix.get("runs"), dict) else {}
    run_info = runs.get(run_key, {}) if isinstance(runs.get(run_key), dict) else {}
    run_id = str(run_info.get("run_id") or "")
    metrics = metrics_by_run_key.get(run_key, {})
    gate = gates_by_run_key.get(run_key, {})
    sample_metrics = rows_by_id(dict_rows(metrics.get("samples", []))).get(sample_id, {})
    gate_sample = gate_rows_by_sample(gate).get(sample_id, {})

    board_trace_on = median_value(sample_metrics.get("board_trace_on_runtime_ns"))
    board_trace_off = median_value(sample_metrics.get("board_trace_off_runtime_ns"))
    trace_events = median_value(sample_metrics.get("trace_events"))
    trace_compact_bytes = median_value(sample_metrics.get("trace_compact_bytes"))
    drop_rate = median_value(sample_metrics.get("drop_rate"))
    alignment_recall = median_value(sample_metrics.get("alignment_recall"))
    alignment_precision = median_value(sample_metrics.get("alignment_precision"))
    groundtruth = sample_metrics.get("groundtruth", {}) if isinstance(sample_metrics.get("groundtruth"), dict) else {}
    baselines = {key: median_value(groundtruth.get(key)) for key in BASELINE_KEYS}

    gate_check = check_gate_sample(gate_sample, expected_behavior)
    checks = {
        "run_key_defined": bool(run_info),
        "metrics_present": bool(metrics),
        "gate_present": bool(gate),
        "sample_metrics_present": bool(sample_metrics),
        "sample_status_pass": sample_metrics.get("status") == "PASS",
        "expected_behavior_matched": sample_metrics.get("expected_behavior_matched") is True,
        "any_behavior_rule_matched": sample_metrics.get("any_behavior_rule_matched") is True,
        "trace_on_rep_count_5": int(sample_metrics.get("trace_on_rep_count") or 0) >= 5,
        "board_trace_on_median_present": positive_number(board_trace_on),
        "board_trace_off_median_present": positive_number(board_trace_off),
        "trace_events_median_positive": positive_number(trace_events),
        "trace_compact_bytes_median_positive": positive_number(trace_compact_bytes),
        "drop_rate_median_le_5pct": drop_rate is not None and drop_rate <= 0.05,
        "alignment_recall_recorded": alignment_recall is not None and alignment_recall >= 0.0,
        "alignment_precision_recorded": alignment_precision is not None and alignment_precision >= 0.0,
        "host_native_baseline_present": positive_number(baselines["host_native"]),
        "host_strace_baseline_present": positive_number(baselines["host_strace"]),
        "qemu_native_baseline_present": positive_number(baselines["qemu_native"]),
        "qemu_strace_baseline_present": positive_number(baselines["qemu_strace"]),
        "gate_sample_pass": gate_check["status"] == "PASS",
    }
    failures.extend(f"{lineage_id}:{key}" for key, ok in checks.items() if not ok)

    baseline_comparison = {
        "board_trace_on_vs_host_native": safe_ratio(board_trace_on, baselines["host_native"]),
        "board_trace_on_vs_host_strace": safe_ratio(board_trace_on, baselines["host_strace"]),
        "board_trace_on_vs_qemu_native": safe_ratio(board_trace_on, baselines["qemu_native"]),
        "board_trace_on_vs_qemu_strace": safe_ratio(board_trace_on, baselines["qemu_strace"]),
        "board_trace_on_vs_trace_off": safe_ratio(board_trace_on, board_trace_off),
    }
    return {
        "lineage_id": lineage_id,
        "sample_id": sample_id,
        "sample_class": row.get("sample_class"),
        "source_family": row.get("source_family"),
        "source_category": row.get("source_category"),
        "source_behavior_point": row.get("source_behavior_point"),
        "run_key": run_key,
        "run_id": run_id,
        "status": "PASS" if not failures else "FAIL",
        "checks": checks,
        "gate": gate_check,
        "metrics_path": rel(repo_root / RESULTS_BASE / run_id / "aggregate" / "metrics.json", repo_root) if run_id else None,
        "gate_artifact": run_info.get("gate_artifact"),
        "medians": {
            "board_trace_on_runtime_ns": board_trace_on,
            "board_trace_off_runtime_ns": board_trace_off,
            "trace_events": trace_events,
            "trace_compact_bytes": trace_compact_bytes,
            "drop_rate": drop_rate,
            "alignment_recall": alignment_recall,
            "alignment_precision": alignment_precision,
            "groundtruth": baselines,
        },
        "baseline_comparison": baseline_comparison,
        "failures": failures,
    }


def build_report(repo_root_arg: Path, matrix_arg: Path) -> dict[str, Any]:
    repo_root = repo_root_arg.resolve()
    matrix_path = repo_path(repo_root, matrix_arg).resolve()
    failures: list[str] = []
    matrix = read_json(matrix_path, failures, repo_root, "lineage matrix")
    matrix_checks = {
        "schema": matrix.get("schema") == "rvmt.real_malware_derived.behavior_lineage_matrix.v1",
        "true_real_malware_false": matrix.get("true_real_malware") is False,
        "rows_present": bool(matrix.get("rows")),
        "runs_present": isinstance(matrix.get("runs"), dict) and bool(matrix.get("runs")),
    }
    failures.extend(f"matrix:{key}" for key, ok in matrix_checks.items() if not ok)

    metrics_by_run_key: dict[str, dict[str, Any]] = {}
    gates_by_run_key: dict[str, dict[str, Any]] = {}
    referenced_files = [matrix_path]
    runs = matrix.get("runs", {}) if isinstance(matrix.get("runs"), dict) else {}
    for run_key, run_info in runs.items():
        if not isinstance(run_info, dict):
            continue
        run_id = str(run_info.get("run_id") or "")
        metrics_path = repo_root / RESULTS_BASE / run_id / "aggregate" / "metrics.json"
        gate_path = repo_path(repo_root, Path(str(run_info.get("gate_artifact") or "")))
        metrics_by_run_key[str(run_key)] = read_json(metrics_path, failures, repo_root, f"{run_key} metrics")
        gates_by_run_key[str(run_key)] = read_json(gate_path, failures, repo_root, f"{run_key} gate")
        if metrics_path.is_file():
            referenced_files.append(metrics_path)
        if gate_path.is_file():
            referenced_files.append(gate_path)

    row_reports = [
        check_row(
            repo_root,
            row,
            matrix=matrix,
            metrics_by_run_key=metrics_by_run_key,
            gates_by_run_key=gates_by_run_key,
        )
        for row in dict_rows(matrix.get("rows", []))
    ]
    for row in row_reports:
        failures.extend(row["failures"])

    status = PASS_STATUS if not failures else FAIL_STATUS
    return {
        "schema": SCHEMA,
        "status": status,
        "generated_utc": utc_now(),
        "repo_root": repo_root.as_posix(),
        "matrix_path": rel(matrix_path, repo_root),
        "claim_boundary": matrix.get("claim_boundary"),
        "matrix_checks": matrix_checks,
        "row_count": len(row_reports),
        "row_pass_count": sum(1 for row in row_reports if row["status"] == "PASS"),
        "rows": row_reports,
        "referenced_file_hashes": {
            "class_digest": class_digest(referenced_files, repo_root),
            "files": [file_record(path, repo_root) for path in sorted(set(referenced_files), key=lambda item: rel(item, repo_root))],
        },
        "interpretation": (
            "Each row binds the board trace medians to same-sample host native, host strace, QEMU native, "
            "and QEMU strace medians already captured in the 35T aggregate metrics. Ratios are descriptive; "
            "the pass/fail gate is evidence presence, trace quality, and expected behavior matching."
        ),
        "non_claims": NON_CLAIMS,
        "failures": sorted(set(failures)),
    }


def csv_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in report["rows"]:
        med = row["medians"]
        groundtruth = med["groundtruth"]
        comparison = row["baseline_comparison"]
        rows.append(
            {
                "lineage_id": row["lineage_id"],
                "source_family": row["source_family"],
                "sample_id": row["sample_id"],
                "run_id": row["run_id"],
                "status": row["status"],
                "board_trace_on_runtime_ns_median": med["board_trace_on_runtime_ns"],
                "board_trace_off_runtime_ns_median": med["board_trace_off_runtime_ns"],
                "host_native_ns_median": groundtruth["host_native"],
                "host_strace_ns_median": groundtruth["host_strace"],
                "qemu_native_ns_median": groundtruth["qemu_native"],
                "qemu_strace_ns_median": groundtruth["qemu_strace"],
                "trace_events_median": med["trace_events"],
                "trace_compact_bytes_median": med["trace_compact_bytes"],
                "drop_rate_median": med["drop_rate"],
                "alignment_recall_median": med["alignment_recall"],
                "alignment_precision_median": med["alignment_precision"],
                "board_trace_on_vs_host_native": comparison["board_trace_on_vs_host_native"],
                "board_trace_on_vs_qemu_native": comparison["board_trace_on_vs_qemu_native"],
            }
        )
    return rows


def render_csv(report: dict[str, Any]) -> str:
    rows = csv_rows(report)
    if not rows:
        return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 35T Real-malware-derived Baseline Comparison",
        "",
        f"Status: {report['status']}",
        "",
        f"Rows: {report['row_pass_count']}/{report['row_count']} PASS",
        "",
        "## Rows",
        "",
        "| Lineage | Sample | Run | Host native ns | QEMU native ns | Board trace-on ns | Trace events | Drop rate | Status |",
        "|---|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for row in report["rows"]:
        med = row["medians"]
        groundtruth = med["groundtruth"]
        lines.append(
            "| `{lineage}` | `{sample}` | `{run}` | {host_native} | {qemu_native} | {board_on} | {events} | {drop} | {status} |".format(
                lineage=row["lineage_id"],
                sample=row["sample_id"],
                run=row["run_id"],
                host_native=groundtruth["host_native"],
                qemu_native=groundtruth["qemu_native"],
                board_on=med["board_trace_on_runtime_ns"],
                events=med["trace_events"],
                drop=med["drop_rate"],
                status=row["status"],
            )
        )
    lines += ["", "## Interpretation", "", report["interpretation"], "", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def snapshot_manifest(repo_root: Path, evidence_root: Path, report: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for name in SNAPSHOT_FILES:
        path = evidence_root / name
        if path.is_file():
            rows.append({"artifact": name, "committed_path": rel(path, repo_root), **file_record(path, repo_root)})
    return {
        "schema": "rvmt.35t.real_malware_derived_baseline_comparison_snapshot.v1",
        "status": "PASS",
        "generated_utc": utc_now(),
        "claim_level": "35T real-malware-derived same-set baseline comparison",
        "committed_artifacts": rows,
        "source_reports": [
            report.get("matrix_path"),
            *sorted({row.get("metrics_path") for row in report.get("rows", []) if row.get("metrics_path")}),
        ],
        "non_claims": NON_CLAIMS,
    }


def render_readme(report: dict[str, Any]) -> str:
    return (
        "# 35T Real-malware-derived Baseline Comparison\n\n"
        f"Status: {report['status']}\n\n"
        "This package records same-sample host native, host strace, QEMU native, QEMU strace, "
        "and board trace-on/off medians for the six real-malware-derived safe behavior rows.\n\n"
        "It is a comparison/provenance package, not a true real-malware execution claim.\n"
    )


def write_outputs(report: dict[str, Any], repo_root: Path, evidence_root_arg: Path) -> None:
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "baseline_comparison.json", report)
    (evidence_root / "baseline_comparison.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")
    (evidence_root / "baseline_comparison.csv").write_text(render_csv(report), encoding="utf-8", newline="\n")
    (evidence_root / "README.md").write_text(render_readme(report), encoding="utf-8", newline="\n")
    write_json(evidence_root / "evidence_manifest.json", snapshot_manifest(repo_root, evidence_root, report))


def self_test() -> None:
    if median_value({"median": 3}) != 3.0:
        raise AssertionError("median parser failed for dict value")
    if median_value(4) != 4.0:
        raise AssertionError("median parser failed for numeric value")
    if median_value({"max": 1}) is not None:
        raise AssertionError("missing median should be None")
    if safe_ratio(10, 2) != 5.0:
        raise AssertionError("safe ratio failed")
    if safe_ratio(10, 0) is not None:
        raise AssertionError("zero denominator should return None")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        a = root / "a.txt"
        b = root / "b.txt"
        a.write_text("alpha\n", encoding="utf-8")
        b.write_text("beta\n", encoding="utf-8")
        if class_digest([a, b], root) != class_digest([b, a], root):
            raise AssertionError("class digest must be order-independent")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print("SELF_TEST_PASS")
        return 0
    repo_root = args.repo_root.resolve()
    report = build_report(repo_root, args.matrix)
    if not args.no_write:
        write_outputs(report, repo_root, args.evidence_root)
    print(report["status"])
    print(f"evidence_root={rel(repo_path(repo_root, args.evidence_root).resolve(), repo_root)}")
    if report["failures"]:
        for failure in report["failures"]:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
