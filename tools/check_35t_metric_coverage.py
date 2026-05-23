from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
DEFAULT_RESOURCE_REPORT = Path("docs/reports/resource_report.md")
STATUS = "BOUNDED_METRIC_COVERAGE_READY_WITH_DEFERRED_FULL_ACCURACY"
REQUIRED_METRICS = (
    "syscall precision / recall",
    "return pairing accuracy",
    "argument reconstruction accuracy",
    "path string reconstruction accuracy",
    "fd graph accuracy",
    "process graph accuracy",
    "runtime overhead",
    "timing perturbation",
    "trace bytes per syscall",
    "DROP rate",
    "LUT / FF / BRAM / Fmax",
    "anti-debug detectability",
)


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


def stat_median(value: Any) -> float | None:
    if isinstance(value, dict) and isinstance(value.get("median"), (int, float)):
        return float(value["median"])
    if isinstance(value, (int, float)):
        return float(value)
    return None


def median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def round_or_none(value: float | None, digits: int = 6) -> float | None:
    return round(value, digits) if value is not None else None


def numeric_sample_values(samples: list[dict[str, Any]], key: str) -> list[float]:
    values = []
    for row in samples:
        value = stat_median(row.get(key))
        if value is not None:
            values.append(value)
    return values


def ratio(num: float | None, den: float | None) -> float | None:
    if num is None or den is None or den == 0:
        return None
    return num / den


def aggregate_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    samples = [row for row in metrics.get("samples", []) if isinstance(row, dict)]
    entry_return_balanced = []
    trace_bytes_per_syscall = []
    host_strace_ratios = []
    qemu_strace_ratios = []
    board_trace_ratios = []
    for row in samples:
        counts = row.get("event_counts", {}) if isinstance(row.get("event_counts"), dict) else {}
        entries = counts.get("SYSCALL_ENTRY")
        returns = counts.get("SYSCALL_RET")
        if isinstance(entries, int) and isinstance(returns, int):
            entry_return_balanced.append(entries == returns)
        trace_bytes = stat_median(row.get("trace_compact_bytes")) or stat_median(row.get("trace_jsonl_bytes"))
        trace_events = stat_median(row.get("trace_events"))
        byte_ratio = ratio(trace_bytes, trace_events)
        if byte_ratio is not None:
            trace_bytes_per_syscall.append(byte_ratio)
        groundtruth = row.get("groundtruth", {}) if isinstance(row.get("groundtruth"), dict) else {}
        host_strace_ratios.append(ratio(stat_median(groundtruth.get("host_strace")), stat_median(groundtruth.get("host_native"))))
        qemu_strace_ratios.append(ratio(stat_median(groundtruth.get("qemu_strace")), stat_median(groundtruth.get("qemu_native"))))
        board_trace_ratios.append(ratio(stat_median(row.get("board_trace_on_runtime_ns")), stat_median(row.get("board_trace_off_runtime_ns"))))
    host_strace_ratios = [value for value in host_strace_ratios if value is not None]
    qemu_strace_ratios = [value for value in qemu_strace_ratios if value is not None]
    board_trace_ratios = [value for value in board_trace_ratios if value is not None]
    drop_values = numeric_sample_values(samples, "drop_rate")
    return {
        "sample_count": len(samples),
        "alignment_precision_median": round_or_none(median(numeric_sample_values(samples, "alignment_precision"))),
        "alignment_recall_median": round_or_none(median(numeric_sample_values(samples, "alignment_recall"))),
        "alignment_argument_accuracy_median": round_or_none(median(numeric_sample_values(samples, "alignment_argument_accuracy"))),
        "entry_return_balanced_samples": sum(1 for value in entry_return_balanced if value),
        "entry_return_balance_sample_count": len(entry_return_balanced),
        "trace_bytes_per_syscall_median": round_or_none(median(trace_bytes_per_syscall)),
        "max_drop_rate_median": round_or_none(max(drop_values) if drop_values else None),
        "host_strace_over_native_median": round_or_none(median(host_strace_ratios)),
        "qemu_strace_over_native_median": round_or_none(median(qemu_strace_ratios)),
        "board_trace_on_over_off_median": round_or_none(median(board_trace_ratios)),
    }


def metric_row(status: str, evidence: list[str], value: Any, boundary: str) -> dict[str, Any]:
    return {
        "status": status,
        "evidence": evidence,
        "value": value,
        "boundary": boundary,
    }


def build_report(repo_root: Path, results_root_arg: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    results_root = repo_path(repo_root, results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    metrics_path = results_root / "aggregate/metrics.json"
    fd_path_path = evidence_root / "fd_path_case_studies.json"
    process_path = evidence_root / "process_tree_case_study.json"
    evaluation_path = evidence_root / "evaluation_table.json"
    resource_path = repo_path(repo_root, DEFAULT_RESOURCE_REPORT)
    metrics = load_json(metrics_path)
    fd_path = load_json(fd_path_path)
    process = load_json(process_path)
    evaluation = load_json(evaluation_path)
    resource_text = resource_path.read_text(encoding="utf-8")
    aggregate = aggregate_metrics(metrics)
    fd_samples = fd_path.get("samples", {}) if isinstance(fd_path.get("samples"), dict) else {}
    process_checks = process.get("checks", {}) if isinstance(process.get("checks"), dict) else {}
    eval_checks = evaluation.get("checks", {}) if isinstance(evaluation.get("checks"), dict) else {}
    coverage = {
        "syscall precision / recall": metric_row(
            "MEASURED_PROXY",
            [rel(metrics_path, repo_root)],
            {
                "alignment_precision_median": aggregate["alignment_precision_median"],
                "alignment_recall_median": aggregate["alignment_recall_median"],
            },
            "current aggregate reports alignment precision/recall proxies, not a full semantic syscall classifier precision/recall claim",
        ),
        "return pairing accuracy": metric_row(
            "MEASURED_PROXY",
            [rel(metrics_path, repo_root)],
            {
                "entry_return_balanced_samples": aggregate["entry_return_balanced_samples"],
                "sample_count": aggregate["entry_return_balance_sample_count"],
            },
            "entry/return count balance is a pairing sanity metric; full return-pairing accuracy remains bounded by available trace alignment",
        ),
        "argument reconstruction accuracy": metric_row(
            "MEASURED_PROXY",
            [rel(metrics_path, repo_root)],
            {"alignment_argument_accuracy_median": aggregate["alignment_argument_accuracy_median"]},
            "aggregate argument accuracy is an alignment-level proxy and does not imply complete pointer semantic reconstruction",
        ),
        "path string reconstruction accuracy": metric_row(
            "CASE_STUDY_MEASURED",
            [rel(fd_path_path, repo_root)],
            {
                sample: {
                    "status": row.get("status"),
                    "closed_flow_count": row.get("closed_flow_count"),
                    "unresolved_fd_count": row.get("unresolved_fd_count"),
                    "pending_openat_count": row.get("pending_openat_count"),
                }
                for sample, row in sorted(fd_samples.items())
                if isinstance(row, dict)
            },
            "measured on the three assessment-prioritized fd/path case-study samples via board syscall side-channel path strings",
        ),
        "fd graph accuracy": metric_row(
            "CASE_STUDY_MEASURED",
            [rel(fd_path_path, repo_root)],
            {
                "required_samples_pass": fd_path.get("checks", {}).get("all_required_samples_pass")
                if isinstance(fd_path.get("checks"), dict)
                else None,
                "all_have_closed_flows": fd_path.get("checks", {}).get("all_have_closed_flows")
                if isinstance(fd_path.get("checks"), dict)
                else None,
            },
            "closed fd graph evidence is case-study scoped and must not be described as full-suite fd graph accuracy",
        ),
        "process graph accuracy": metric_row(
            "CASE_STUDY_MEASURED",
            [rel(process_path, repo_root)],
            {
                "positive_child_pid": process_checks.get("positive_child_pid_recovered"),
                "exec_path": process_checks.get("execve_path_string_recovered"),
                "wait_pid": process_checks.get("parent_wait_pid_associated"),
                "graph": process_checks.get("parent_child_graph_output"),
            },
            "process graph evidence is scoped to the process_chain case study with parent PID intentionally unresolved",
        ),
        "runtime overhead": metric_row(
            "MEASURED",
            [rel(metrics_path, repo_root), rel(results_root / "aggregate/overhead_report.md", repo_root)],
            {"board_trace_on_over_off_median": aggregate["board_trace_on_over_off_median"]},
            "board trace-on/off runtime ratio is reported as measured perturbation evidence, not acceleration",
        ),
        "timing perturbation": metric_row(
            "MEASURED",
            [rel(metrics_path, repo_root), rel(evaluation_path, repo_root)],
            {
                "host_strace_over_native_median": aggregate["host_strace_over_native_median"],
                "qemu_strace_over_native_median": aggregate["qemu_strace_over_native_median"],
            },
            "covers host/QEMU strace timing, host eBPF/bpftrace timing, QEMU-plugin syscall-count timing evidence, and board trace-on/off timing",
        ),
        "trace bytes per syscall": metric_row(
            "MEASURED",
            [rel(metrics_path, repo_root), rel(results_root / "aggregate/bandwidth_report.md", repo_root)],
            {"trace_bytes_per_syscall_median": aggregate["trace_bytes_per_syscall_median"]},
            "computed from aggregate trace compact/jsonl bytes and trace event medians",
        ),
        "DROP rate": metric_row(
            "MEASURED",
            [rel(metrics_path, repo_root), rel(results_root / "aggregate/bandwidth_report.md", repo_root)],
            {"max_drop_rate_median": aggregate["max_drop_rate_median"]},
            "bounded by the primary 13-sample 35T run under the 512-record trace budget",
        ),
        "LUT / FF / BRAM / Fmax": metric_row(
            "MEASURED_SUMMARY",
            [rel(resource_path, repo_root)],
            {
                "trace_delta_recorded": "Trace-Enabled FPGA Delta" in resource_text,
                "fmax_recorded": "Approx. achieved Fmax" in resource_text,
            },
            "resource/timing evidence is a routed report summary; full raw Vivado artifacts remain outside the lightweight snapshot",
        ),
        "anti-debug detectability": metric_row(
            "BOUNDED_SYNTHETIC_MEASURED",
            [rel(evaluation_path, repo_root)],
            {
                "anti_debug_behavior_strong": eval_checks.get("anti_debug_behavior_strong"),
                "ebpf_baseline_pass": eval_checks.get("ebpf_baseline_pass"),
                "qemu_plugin_baseline_pass": eval_checks.get("qemu_plugin_baseline_pass"),
            },
            "anti_debug_like is synthetic ptrace-oriented behavior evidence; real malware anti-evasion quality is not claimed",
        ),
    }
    checks = {
        "all_required_metrics_listed": all(item in coverage for item in REQUIRED_METRICS),
        "metrics_13_samples": aggregate["sample_count"] == 13,
        "alignment_proxy_present": aggregate["alignment_precision_median"] is not None
        and aggregate["alignment_recall_median"] is not None
        and aggregate["alignment_argument_accuracy_median"] is not None,
        "return_pairing_proxy_present": aggregate["entry_return_balance_sample_count"] == 13,
        "fd_case_studies_pass": fd_path.get("status") == "PASS",
        "process_case_study_pass": process.get("status") == "PASS",
        "runtime_and_timing_present": aggregate["board_trace_on_over_off_median"] is not None
        and aggregate["host_strace_over_native_median"] is not None
        and aggregate["qemu_strace_over_native_median"] is not None,
        "trace_bytes_and_drop_present": aggregate["trace_bytes_per_syscall_median"] is not None
        and aggregate["max_drop_rate_median"] is not None,
        "resource_summary_present": "Trace-Enabled FPGA Delta" in resource_text and "Approx. achieved Fmax" in resource_text,
        "anti_debug_bounded_present": eval_checks.get("anti_debug_behavior_strong") is True,
    }
    status = STATUS if all(checks.values()) else "FAIL"
    return {
        "schema": "rvmt.35t.metric_coverage.v1",
        "run_id": RUN_ID,
        "generated_utc": utc_now(),
        "status": status,
        "checks": checks,
        "aggregate": aggregate,
        "required_metrics": list(REQUIRED_METRICS),
        "coverage": coverage,
        "interpretation": [
            "the assessment's P4 metric list is explicitly enumerated and tied to current evidence",
            "accuracy-style metrics are bounded to existing alignment proxies and fd/process case studies unless stronger full-suite ground truth exists",
            "advanced baseline perturbation and semantic enrichment accuracy remain bounded to available eBPF, QEMU-plugin, pointer snapshot, and helper evidence",
        ],
        "non_claims": [
            "no complete syscall semantic precision/recall claim",
            "no full-suite fd graph accuracy claim",
            "no full-suite process ownership accuracy claim",
            "no QEMU-plugin hardware-trace or DBI equivalence claim",
            "no real malware anti-evasion detectability claim",
        ],
        "failures": [key for key, ok in checks.items() if not ok],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Metric Coverage: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Metrics", "", "| Metric | Status | Value | Boundary |", "| --- | --- | --- | --- |"]
    for metric in report["required_metrics"]:
        row = report["coverage"][metric]
        value = json.dumps(row.get("value"), sort_keys=True)
        lines.append(f"| {metric} | `{row.get('status')}` | `{value}` | {row.get('boundary')} |")
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "metric_coverage.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "metric_coverage.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def write_fixture(root: Path) -> None:
    results = root / DEFAULT_RESULTS_ROOT
    evidence = root / DEFAULT_EVIDENCE_ROOT
    samples = []
    for index in range(13):
        samples.append(
            {
                "sample_id": f"sample_{index}",
                "alignment_precision": {"median": 0.8},
                "alignment_recall": {"median": 0.7},
                "alignment_argument_accuracy": {"median": 0.6},
                "event_counts": {"SYSCALL_ENTRY": 10, "SYSCALL_RET": 10},
                "trace_compact_bytes": {"median": 1000.0},
                "trace_events": {"median": 10.0},
                "drop_rate": {"median": 0.0},
                "board_trace_on_runtime_ns": {"median": 90.0},
                "board_trace_off_runtime_ns": {"median": 100.0},
                "groundtruth": {
                    "host_native": {"median": 10.0},
                    "host_strace": {"median": 20.0},
                    "qemu_native": {"median": 15.0},
                    "qemu_strace": {"median": 30.0},
                },
            }
        )
    (results / "aggregate").mkdir(parents=True, exist_ok=True)
    (results / "aggregate/metrics.json").write_text(json.dumps({"samples": samples}), encoding="utf-8")
    (results / "aggregate/overhead_report.md").write_text("not as acceleration claims\n", encoding="utf-8")
    (results / "aggregate/bandwidth_report.md").write_text("Worst median DROP sample\n", encoding="utf-8")
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "fd_path_case_studies.json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "checks": {"all_required_samples_pass": True, "all_have_closed_flows": True},
                "samples": {
                    "file_scan": {"status": "PASS", "closed_flow_count": 1, "unresolved_fd_count": 0, "pending_openat_count": 0},
                    "batch_open_read_write": {"status": "PASS", "closed_flow_count": 2, "unresolved_fd_count": 0, "pending_openat_count": 0},
                    "self_copy_sim": {"status": "PASS", "closed_flow_count": 2, "unresolved_fd_count": 0, "pending_openat_count": 0},
                },
            }
        ),
        encoding="utf-8",
    )
    (evidence / "process_tree_case_study.json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "checks": {
                    "positive_child_pid_recovered": True,
                    "execve_path_string_recovered": True,
                    "parent_wait_pid_associated": True,
                    "parent_child_graph_output": True,
                },
            }
        ),
        encoding="utf-8",
    )
    (evidence / "evaluation_table.json").write_text(
        json.dumps(
            {
                "checks": {
                    "anti_debug_behavior_strong": True,
                    "ebpf_baseline_pass": True,
                    "qemu_plugin_baseline_pass": True,
                }
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_RESOURCE_REPORT).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_RESOURCE_REPORT).write_text("Trace-Enabled FPGA Delta\nApprox. achieved Fmax\n", encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != STATUS:
            print(f"[FAIL] expected fixture status {STATUS}, got {report['status']}: {report['failures']}", file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "metric_coverage.md").exists():
            print("[FAIL] self-test did not write markdown output", file=sys.stderr)
            return 1
        metrics = load_json(root / DEFAULT_RESULTS_ROOT / "aggregate/metrics.json")
        metrics["samples"].pop()
        (root / DEFAULT_RESULTS_ROOT / "aggregate/metrics.json").write_text(json.dumps(metrics), encoding="utf-8")
        failed = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if failed["status"] == STATUS:
            print("[FAIL] fixture with missing sample should fail", file=sys.stderr)
            return 1
    print("[PASS] 35T metric coverage self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check bounded metric coverage for the 35T assessment P4 metric list.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        repo_root = args.repo_root.resolve()
        report = build_report(repo_root, args.results_root, args.evidence_root)
        if not args.no_write:
            write_outputs(report, repo_path(repo_root, args.evidence_root))
    except Exception as exc:
        print(f"check_35t_metric_coverage: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T metric coverage")
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
