from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    rel,
    repo_path,
    utc_now,
    write_json,
)


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_RESOURCE_REPORT = Path("docs/07-evaluation-evidence/reports/resource_report.md")
STATUS = "BOUNDED_EVALUATION_TABLE_READY_WITH_EBPF_AND_QEMU_PLUGIN"
QEMU_PLUGIN_BASELINE_STATUS = "QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES"
ADVANCED_NON_PASS_STATUSES = {"BLOCKED_CURRENT_ENVIRONMENT", "READY_NOT_RUN", "NOT_RUN", "DEFERRED"}
ADVANCED_PREFLIGHT_STATUSES = {"BLOCKED_CURRENT_ENVIRONMENT", "READY"}
REQUIRED_GROUNDTRUTH = ("host_native", "host_strace", "qemu_native", "qemu_strace")
NON_CLAIMS = [
    "no real malware detection claim",
    "no classifier accuracy claim",
    "no QEMU-plugin hardware-trace or DBI equivalence claim",
    "no eBPF baseline hardware-trace substitution claim",
    "no single-trace all-gates side-channel claim",
]


def median_stat(value: Any) -> float | None:
    if isinstance(value, dict) and isinstance(value.get("median"), (int, float)):
        return float(value["median"])
    if isinstance(value, (int, float)):
        return float(value)
    return None


def ratio(num: float | None, den: float | None) -> float | None:
    if num is None or den is None or den == 0:
        return None
    return num / den


def median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def round_or_none(value: float | None, digits: int = 6) -> float | None:
    return round(value, digits) if value is not None else None


def summarize_metric_samples(samples: list[dict[str, Any]]) -> dict[str, Any]:
    host_strace_ratios: list[float] = []
    qemu_strace_ratios: list[float] = []
    board_trace_ratios: list[float] = []
    drop_rates: list[float] = []
    event_medians: list[float] = []
    cap_hit_samples: list[str] = []
    rows = []
    for row in samples:
        groundtruth = row.get("groundtruth", {}) if isinstance(row.get("groundtruth"), dict) else {}
        host_native = median_stat(groundtruth.get("host_native"))
        host_strace = median_stat(groundtruth.get("host_strace"))
        qemu_native = median_stat(groundtruth.get("qemu_native"))
        qemu_strace = median_stat(groundtruth.get("qemu_strace"))
        trace_off = median_stat(row.get("board_trace_off_runtime_ns"))
        trace_on = median_stat(row.get("board_trace_on_runtime_ns"))
        drop_rate = median_stat(row.get("drop_rate"))
        trace_events = median_stat(row.get("trace_events"))
        host_ratio = ratio(host_strace, host_native)
        qemu_ratio = ratio(qemu_strace, qemu_native)
        board_ratio = ratio(trace_on, trace_off)
        if host_ratio is not None:
            host_strace_ratios.append(host_ratio)
        if qemu_ratio is not None:
            qemu_strace_ratios.append(qemu_ratio)
        if board_ratio is not None:
            board_trace_ratios.append(board_ratio)
        if drop_rate is not None:
            drop_rates.append(drop_rate)
        if trace_events is not None:
            event_medians.append(trace_events)
        if row.get("captured_cap_reps"):
            cap_hit_samples.append(str(row.get("sample_id")))
        rows.append(
            {
                "sample_id": row.get("sample_id"),
                "sample_class": row.get("sample_class"),
                "host_strace_over_native": round_or_none(host_ratio),
                "qemu_strace_over_native": round_or_none(qemu_ratio),
                "board_trace_on_over_off": round_or_none(board_ratio),
                "drop_rate_median": round_or_none(drop_rate),
                "trace_events_median": round_or_none(trace_events),
                "status": row.get("status"),
            }
        )
    return {
        "sample_rows": rows,
        "aggregate": {
            "sample_count": len(samples),
            "host_strace_over_native_median": round_or_none(median(host_strace_ratios)),
            "qemu_strace_over_native_median": round_or_none(median(qemu_strace_ratios)),
            "board_trace_on_over_off_median": round_or_none(median(board_trace_ratios)),
            "max_drop_rate_median": round_or_none(max(drop_rates) if drop_rates else None),
            "trace_events_median": round_or_none(median(event_medians)),
            "cap_hit_sample_count": len(cap_hit_samples),
            "cap_hit_samples": cap_hit_samples,
        },
    }


def anti_debug_summary(results_root: Path, repo_root: Path) -> dict[str, Any]:
    paths = sorted(
        (
            results_root
            / "samples/malware_like_synthetic/anti_debug_like/board/trace-on"
        ).glob("rep_*/behavior_audit/behavior_audit.json")
    )
    reps = []
    for path in paths:
        audit = load_json(path)
        matched = "anti_analysis_indicator" in set(audit.get("matched_expected_behavior", []))
        strong = any(
            isinstance(item, dict)
            and item.get("rule") == "anti_analysis_indicator"
            and item.get("matched") is True
            and item.get("evidence_strength") == "strong"
            for item in audit.get("matches", [])
            if isinstance(item, dict)
        )
        reps.append({"path": rel(path, repo_root), "matched": matched, "strong": strong})
    return {
        "sample": "anti_debug_like",
        "rep_count": len(reps),
        "matched_count": sum(1 for row in reps if row["matched"]),
        "strong_count": sum(1 for row in reps if row["strong"]),
        "all_reps_strong": bool(reps) and all(row["strong"] for row in reps),
        "evidence": reps[:5],
        "interpretation": "anti_analysis_indicator is synthetic ptrace-oriented behavior evidence, not real malware evasion quality.",
    }


def build_report(repo_root: Path, results_root_arg: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    results_root = repo_path(repo_root, results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    metrics_path = results_root / "aggregate/metrics.json"
    overhead_path = results_root / "aggregate/overhead_report.md"
    bandwidth_path = results_root / "aggregate/bandwidth_report.md"
    baseline_path = evidence_root / "baseline_evaluation_summary.json"
    advanced_path = evidence_root / "advanced_baseline_preflight.json"
    software_path = evidence_root / "software_instrumentation_baseline_summary.json"
    qemu_plugin_path = evidence_root / "qemu_plugin_baseline_summary.json"
    pointer_path = evidence_root / "pointer_semantics_preflight.json"
    resource_path = repo_path(repo_root, DEFAULT_RESOURCE_REPORT)

    metrics = load_json(metrics_path)
    baseline = load_json(baseline_path)
    advanced = load_json(advanced_path)
    software = load_json(software_path)
    qemu_plugin = load_json(qemu_plugin_path)
    pointer = load_json(pointer_path)
    samples = metrics.get("samples", []) if isinstance(metrics.get("samples"), list) else []
    sample_summary = summarize_metric_samples([row for row in samples if isinstance(row, dict)])
    baselines = baseline.get("baselines", {}) if isinstance(baseline.get("baselines"), dict) else {}
    advanced_baselines = advanced.get("baselines", {}) if isinstance(advanced.get("baselines"), dict) else {}
    resource_text = resource_path.read_text(encoding="utf-8")
    anti_debug = anti_debug_summary(results_root, repo_root)

    checks = {
        "metrics_13_samples": len(samples) == 13,
        "all_samples_pass": all(isinstance(row, dict) and row.get("status") == "PASS" for row in samples),
        "required_groundtruth_present": all(
            isinstance(row, dict)
            and isinstance(row.get("groundtruth"), dict)
            and all(key in row["groundtruth"] for key in REQUIRED_GROUNDTRUTH)
            for row in samples
        ),
        "host_qemu_strace_baselines_pass": all(
            baselines.get(key, {}).get("status") == "PASS"
            for key in ("host_native", "host_strace", "qemu_native", "qemu_strace")
        ),
        "software_instrumentation_pass": baselines.get("software_instrumentation", {}).get("status") == "PASS"
        and software.get("status") == "PASS",
        "ebpf_baseline_pass": baselines.get("ebpf_only", {}).get("status") == "PASS"
        and int(baselines.get("ebpf_only", {}).get("samples_with_evidence") or 0) == 13,
        "qemu_plugin_baseline_pass": (
            baselines.get("qemu_plugin", {}).get("status") == "PASS"
            and int(baselines.get("qemu_plugin", {}).get("samples_with_evidence") or 0) == 13
            and qemu_plugin.get("status") == QEMU_PLUGIN_BASELINE_STATUS
            and int(qemu_plugin.get("pass_count") or 0) == 13
        ),
        "trace_drop_and_cap_bounded": sample_summary["aggregate"]["cap_hit_sample_count"] == 0
        and (sample_summary["aggregate"]["max_drop_rate_median"] or 0) <= 0.05,
        "overhead_report_present": overhead_path.is_file() and "not as acceleration claims" in overhead_path.read_text(encoding="utf-8"),
        "bandwidth_report_present": bandwidth_path.is_file() and "Worst median DROP sample" in bandwidth_path.read_text(encoding="utf-8"),
        "resource_delta_present": "Trace-Enabled FPGA Delta" in resource_text and "Approx. achieved Fmax" in resource_text,
        "anti_debug_behavior_strong": anti_debug["rep_count"] >= 5 and anti_debug["all_reps_strong"] is True,
        "pointer_snapshot_deferred_recorded": pointer.get("status")
        == "SYNTHETIC_ARG_MEM_GUARDRAILS_PASS_SIDE_CHANNEL_CLOSURE_HARDWARE_POINTER_DEFERRED",
    }
    status = STATUS if all(checks.values()) else "FAIL"
    return {
        "schema": "rvmt.35t.evaluation_table.v1",
        "run_id": RUN_ID,
        "generated_utc": utc_now(),
        "status": status,
        "checks": checks,
        "aggregate": sample_summary["aggregate"],
        "baseline_table": {
            key: {
                "status": value.get("status"),
                "samples_with_evidence": value.get("samples_with_evidence"),
                "sample_count": value.get("sample_count"),
                "evidence": value.get("evidence"),
            }
            for key, value in sorted(baselines.items())
            if isinstance(value, dict)
        },
        "sample_table": sample_summary["sample_rows"],
        "anti_debug_visibility": anti_debug,
        "resource_timing": {
            "resource_report": rel(resource_path, repo_root),
            "overhead_report": rel(overhead_path, repo_root),
            "bandwidth_report": rel(bandwidth_path, repo_root),
            "trace_delta_recorded": "Trace-Enabled FPGA Delta" in resource_text,
        },
        "interpretation": [
            "available timing baselines cover host native, host strace, QEMU native, QEMU strace, source-level software instrumentation, and host eBPF/bpftrace",
            "QEMU-plugin syscall-count evidence is included only from the separate 13-sample plugin baseline summary",
            "the eBPF-only baseline is host Linux bpftrace evidence and is not a hardware trace substitute",
            "trace-on/off ratios are measured board runtime ratios and are not acceleration claims",
            "anti_debug_like provides synthetic ptrace-oriented anti-analysis behavior evidence, not real malware evasion quality evidence",
            "resource/timing evidence is available as routed report summaries; full raw Vivado artifacts remain outside the lightweight snapshot",
        ],
        "non_claims": NON_CLAIMS,
        "failures": [key for key, ok in checks.items() if not ok],
    }


def render_markdown(report: dict[str, Any]) -> str:
    aggregate = report["aggregate"]
    lines = [
        f"# 35T Bounded Evaluation Table: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Aggregate Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
    ]
    for key in (
        "sample_count",
        "host_strace_over_native_median",
        "qemu_strace_over_native_median",
        "board_trace_on_over_off_median",
        "max_drop_rate_median",
        "trace_events_median",
        "cap_hit_sample_count",
    ):
        lines.append(f"| `{key}` | {aggregate.get(key)} |")
    lines += ["", "## Baseline Coverage", "", "| Baseline | Status | Evidence |", "| --- | --- | --- |"]
    for key, row in report["baseline_table"].items():
        lines.append(f"| `{key}` | `{row.get('status')}` | {row.get('samples_with_evidence')}/{row.get('sample_count')} |")
    lines += [
        "",
        "## Anti-Debug Synthetic Evidence",
        "",
        f"- sample: `{report['anti_debug_visibility']['sample']}`",
        f"- strong reps: {report['anti_debug_visibility']['strong_count']}/{report['anti_debug_visibility']['rep_count']}",
        f"- interpretation: {report['anti_debug_visibility']['interpretation']}",
        "",
        "## Interpretation",
        "",
    ]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "evaluation_table.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "evaluation_table.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_fixture(root: Path) -> None:
    results = root / DEFAULT_RESULTS_ROOT
    evidence = root / DEFAULT_EVIDENCE_ROOT
    samples = []
    for index in range(13):
        sample_id = "anti_debug_like" if index == 12 else f"sample_{index}"
        samples.append(
            {
                "sample_id": sample_id,
                "sample_class": "malware_like_synthetic" if index >= 5 else "benign",
                "status": "PASS",
                "groundtruth": {
                    "host_native": {"median": 10.0},
                    "host_strace": {"median": 25.0},
                    "qemu_native": {"median": 20.0},
                    "qemu_strace": {"median": 35.0},
                },
                "board_trace_off_runtime_ns": {"median": 100.0},
                "board_trace_on_runtime_ns": {"median": 80.0},
                "drop_rate": {"median": 0.0},
                "trace_events": {"median": 40.0},
                "captured_cap_reps": [],
            }
        )
    write_json(results / "aggregate/metrics.json", {"samples": samples})
    for name, text in {
        "overhead_report.md": "not as acceleration claims\n",
        "bandwidth_report.md": "Worst median DROP sample\n",
    }.items():
        path = results / "aggregate" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for rep in range(5):
        write_json(
            results
            / f"samples/malware_like_synthetic/anti_debug_like/board/trace-on/rep_{rep:02d}/behavior_audit/behavior_audit.json",
            {
                "matched_expected_behavior": ["anti_analysis_indicator"],
                "matches": [
                    {
                        "rule": "anti_analysis_indicator",
                        "matched": True,
                        "evidence_strength": "strong",
                    }
                ],
            },
        )
    baselines = {
        key: {"status": "PASS", "samples_with_evidence": 13, "sample_count": 13, "evidence": "fixture"}
        for key in ("host_native", "host_strace", "qemu_native", "qemu_strace", "software_instrumentation")
    }
    baselines["ebpf_only"] = {"status": "PASS", "samples_with_evidence": 13, "sample_count": 13}
    baselines["qemu_plugin"] = {"status": "PASS", "samples_with_evidence": 13, "sample_count": 13}
    write_json(evidence / "baseline_evaluation_summary.json", {"baselines": baselines})
    write_json(
        evidence / "advanced_baseline_preflight.json",
        {"baselines": {"ebpf_only": {"status": "READY"}, "qemu_plugin": {"status": "BLOCKED_CURRENT_ENVIRONMENT"}}},
    )
    write_json(evidence / "software_instrumentation_baseline_summary.json", {"status": "PASS"})
    write_json(
        evidence / "qemu_plugin_baseline_summary.json",
        {"schema": "rvmt.35t.qemu_plugin_baseline.v1", "status": QEMU_PLUGIN_BASELINE_STATUS, "pass_count": 13},
    )
    write_json(
        evidence / "pointer_semantics_preflight.json",
        {"status": "SYNTHETIC_ARG_MEM_GUARDRAILS_PASS_SIDE_CHANNEL_CLOSURE_HARDWARE_POINTER_DEFERRED"},
    )
    (root / DEFAULT_RESOURCE_REPORT).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_RESOURCE_REPORT).write_text(
        "Trace-Enabled FPGA Delta\nApprox. achieved Fmax\n",
        encoding="utf-8",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != STATUS:
            print("[FAIL] expected evaluation table fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "evaluation_table.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        qemu_path = root / DEFAULT_EVIDENCE_ROOT / "qemu_plugin_baseline_summary.json"
        qemu_plugin = load_json(qemu_path)
        qemu_plugin["pass_count"] = 12
        write_json(qemu_path, qemu_plugin)
        report = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if "qemu_plugin_baseline_pass" not in report["failures"]:
            print("[FAIL] missed qemu_plugin PASS without summary regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        audit_path = next((root / DEFAULT_RESULTS_ROOT / "samples/malware_like_synthetic/anti_debug_like/board/trace-on").glob("rep_00/behavior_audit/behavior_audit.json"))
        audit = load_json(audit_path)
        audit["matches"][0]["evidence_strength"] = "weak"
        write_json(audit_path, audit)
        report = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if "anti_debug_behavior_strong" not in report["failures"]:
            print("[FAIL] missed anti-debug evidence regression", file=sys.stderr)
            return 1
    print("[PASS] 35T evaluation table self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build/check a bounded 35T evaluation table from available evidence.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.results_root, args.evidence_root)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_evaluation_table: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T bounded evaluation table")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
