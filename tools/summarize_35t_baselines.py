from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_METRICS = Path("results/experiments/35t") / RUN_ID / "aggregate/metrics.json"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_ADVANCED_BASELINE_PREFLIGHT = DEFAULT_EVIDENCE_ROOT / "advanced_baseline_preflight.json"
DEFAULT_QEMU_PLUGIN_BUILD_PREFLIGHT = DEFAULT_EVIDENCE_ROOT / "qemu_plugin_build_preflight.json"
DEFAULT_QEMU_PLUGIN_BASELINE_SUMMARY = DEFAULT_EVIDENCE_ROOT / "qemu_plugin_baseline_summary.json"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
HOST_QEMU_STRACE_STATUS = "HOST_QEMU_STRACE_BASELINE_PASS_WITH_MISSING_ADVANCED_BASELINES"
SOFTWARE_INSTRUMENTATION_STATUS = "HOST_QEMU_STRACE_AND_SOFTWARE_INSTRUMENTATION_PASS_WITH_MISSING_EBPF_QEMU_PLUGIN"
SOFTWARE_INSTRUMENTATION_AND_EBPF_STATUS = "HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_AND_EBPF_PASS_WITH_MISSING_QEMU_PLUGIN"
SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS = "HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS"
GROUNDTRUTH_BASELINES = ("host_native", "host_strace", "qemu_native", "qemu_strace")
MISSING_ADVANCED_BASELINES = ("ebpf_only", "qemu_plugin")
SOFTWARE_RUN_ID = "35t-software-instrumentation-baseline-20260523"
EBPF_RUN_ID = "35t-ebpf-baseline-20260523"
QEMU_PLUGIN_RUN_ID = "35t-qemu-plugin-baseline-20260523"
DEFAULT_SOFTWARE_INSTRUMENTATION_SUMMARY = (
    Path("results/experiments/35t") / SOFTWARE_RUN_ID / "aggregate/software_instrumentation_baseline_summary.json"
)
DEFAULT_EBPF_BASELINE_SUMMARY = DEFAULT_EVIDENCE_ROOT / "ebpf_baseline_summary.json"
SOFTWARE_INSTRUMENTATION_SCHEMA = "rvmt.35t.software_instrumentation_baseline.v1"
EBPF_BASELINE_SCHEMA = "rvmt.35t.ebpf_baseline.v1"
QEMU_PLUGIN_BASELINE_SCHEMA = "rvmt.35t.qemu_plugin_baseline.v1"
QEMU_PLUGIN_BASELINE_STATUS = "QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES"
ADVANCED_PREFLIGHT_SCHEMA = "rvmt.35t.advanced_baseline_preflight.v1"
QEMU_PLUGIN_BUILD_PREFLIGHT_SCHEMA = "rvmt.35t.qemu_plugin_build_preflight.v1"
QEMU_PLUGIN_BUILD_PREFLIGHT_STATUS = "QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def median(row: dict[str, Any], key: str) -> float | None:
    value = row.get(key)
    if not isinstance(value, dict):
        return None
    raw = value.get("median")
    return float(raw) if isinstance(raw, (int, float)) else None


def ratio(numerator: float | None, denominator: float | None) -> float | None:
    if numerator is None or denominator in (None, 0):
        return None
    return numerator / denominator


def sample_baseline_row(row: dict[str, Any]) -> dict[str, Any]:
    groundtruth = row.get("groundtruth", {})
    if not isinstance(groundtruth, dict):
        groundtruth = {}
    gt_medians = {
        name: median(groundtruth, name)
        for name in GROUNDTRUTH_BASELINES
    }
    trace_off = median(row, "board_trace_off_runtime_ns")
    trace_on = median(row, "board_trace_on_runtime_ns")
    return {
        "sample_id": row.get("sample_id"),
        "sample_class": row.get("sample_class"),
        "status": row.get("status"),
        "groundtruth_median_ns": gt_medians,
        "host_strace_over_host_native": ratio(gt_medians["host_strace"], gt_medians["host_native"]),
        "qemu_strace_over_qemu_native": ratio(gt_medians["qemu_strace"], gt_medians["qemu_native"]),
        "board_trace_on_over_trace_off": ratio(trace_on, trace_off),
        "board_trace_off_median_ns": trace_off,
        "board_trace_on_median_ns": trace_on,
        "trace_events_median": median(row, "trace_events"),
        "drop_rate_median": median(row, "drop_rate"),
        "cap_hit_count": len(row.get("captured_cap_reps", [])) if isinstance(row.get("captured_cap_reps"), list) else None,
        "alignment_precision_median": median(row, "alignment_precision"),
        "alignment_recall_median": median(row, "alignment_recall"),
        "alignment_argument_accuracy_median": median(row, "alignment_argument_accuracy"),
        "missing_groundtruth": [name for name, value in gt_medians.items() if value is None],
    }


def software_instrumentation_baseline_row(summary_path: Path | None, sample_count: int) -> dict[str, Any]:
    if summary_path is None or not summary_path.exists():
        return {
            "status": "NOT_RUN",
            "samples_with_evidence": 0,
            "sample_count": sample_count,
            "evidence": "not present in current committed/local 35T evidence",
        }
    try:
        summary = load_json(summary_path)
    except Exception as exc:
        return {
            "status": "FAIL",
            "samples_with_evidence": 0,
            "sample_count": sample_count,
            "evidence": f"invalid software instrumentation summary at {summary_path.as_posix()}: {exc}",
        }
    pass_count = summary.get("pass_count")
    run_sample_count = summary.get("sample_count")
    ok = (
        summary.get("schema") == SOFTWARE_INSTRUMENTATION_SCHEMA
        and summary.get("run_id") == SOFTWARE_RUN_ID
        and summary.get("status") == "PASS"
        and run_sample_count == sample_count == 13
        and pass_count == sample_count
    )
    return {
        "status": "PASS" if ok else "FAIL",
        "samples_with_evidence": pass_count if isinstance(pass_count, int) else 0,
        "sample_count": sample_count,
        "evidence": display_path(summary_path),
        "run_id": summary.get("run_id"),
        "instrumentation": summary.get("instrumentation"),
    }


def ebpf_baseline_row(summary_path: Path | None, sample_count: int) -> dict[str, Any] | None:
    if summary_path is None or not summary_path.exists():
        return None
    try:
        summary = load_json(summary_path)
    except Exception as exc:
        return {
            "status": "FAIL",
            "samples_with_evidence": 0,
            "sample_count": sample_count,
            "evidence": f"invalid eBPF baseline summary at {summary_path.as_posix()}: {exc}",
        }
    pass_count = summary.get("pass_count")
    run_sample_count = summary.get("sample_count")
    ok = (
        summary.get("schema") == EBPF_BASELINE_SCHEMA
        and summary.get("run_id") == EBPF_RUN_ID
        and summary.get("source_run_id") == RUN_ID
        and summary.get("status") == "PASS"
        and run_sample_count == sample_count == 13
        and pass_count == sample_count
    )
    return {
        "status": "PASS" if ok else "FAIL",
        "samples_with_evidence": pass_count if isinstance(pass_count, int) else 0,
        "sample_count": sample_count,
        "evidence": display_path(summary_path),
        "run_id": summary.get("run_id"),
        "instrumentation": summary.get("instrumentation"),
    }


def qemu_plugin_baseline_row(summary_path: Path | None, sample_count: int) -> dict[str, Any] | None:
    if summary_path is None or not summary_path.exists():
        return None
    try:
        summary = load_json(summary_path)
    except Exception as exc:
        return {
            "status": "FAIL",
            "samples_with_evidence": 0,
            "sample_count": sample_count,
            "evidence": f"invalid QEMU-plugin baseline summary at {summary_path.as_posix()}: {exc}",
        }
    pass_count = summary.get("pass_count")
    run_sample_count = summary.get("sample_count")
    ok = (
        summary.get("schema") == QEMU_PLUGIN_BASELINE_SCHEMA
        and summary.get("run_id") == QEMU_PLUGIN_RUN_ID
        and summary.get("source_run_id") == RUN_ID
        and summary.get("status") == QEMU_PLUGIN_BASELINE_STATUS
        and run_sample_count == sample_count == 13
        and pass_count == sample_count
    )
    return {
        "status": "PASS" if ok else "FAIL",
        "samples_with_evidence": pass_count if isinstance(pass_count, int) else 0,
        "sample_count": sample_count,
        "evidence": display_path(summary_path),
        "run_id": summary.get("run_id"),
        "instrumentation": "QEMU user-mode TCG plugin syscall-count baseline",
        "qemu_version": summary.get("qemu", {}).get("version") if isinstance(summary.get("qemu"), dict) else None,
    }


def qemu_plugin_build_preflight_row(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None
    try:
        report = load_json(path)
    except Exception as exc:
        return {"status": "FAIL", "evidence": f"invalid QEMU-plugin build preflight at {path.as_posix()}: {exc}"}
    ok = (
        report.get("schema") == QEMU_PLUGIN_BUILD_PREFLIGHT_SCHEMA
        and report.get("status") == QEMU_PLUGIN_BUILD_PREFLIGHT_STATUS
    )
    return {
        "status": "PASS" if ok else "FAIL",
        "evidence": display_path(path),
        "current_condition": report.get("current_condition"),
    }


def advanced_baseline_rows(
    preflight_path: Path | None,
    sample_count: int,
    qemu_plugin_build_preflight_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    default_rows = {
        name: {
            "status": "NOT_RUN",
            "samples_with_evidence": 0,
            "sample_count": sample_count,
            "evidence": "not present in current committed/local 35T evidence",
        }
        for name in MISSING_ADVANCED_BASELINES
    }
    if preflight_path is None or not preflight_path.exists():
        return default_rows
    try:
        preflight = load_json(preflight_path)
    except Exception as exc:
        return {
            name: {
                "status": "FAIL",
                "samples_with_evidence": 0,
                "sample_count": sample_count,
                "evidence": f"invalid advanced baseline preflight at {preflight_path.as_posix()}: {exc}",
            }
            for name in MISSING_ADVANCED_BASELINES
        }
    if preflight.get("schema") != ADVANCED_PREFLIGHT_SCHEMA:
        return {
            name: {
                "status": "FAIL",
                "samples_with_evidence": 0,
                "sample_count": sample_count,
                "evidence": f"invalid advanced baseline preflight schema at {display_path(preflight_path)}",
            }
            for name in MISSING_ADVANCED_BASELINES
        }
    baselines = preflight.get("baselines", {}) if isinstance(preflight.get("baselines"), dict) else {}
    rows: dict[str, dict[str, Any]] = {}
    for name in MISSING_ADVANCED_BASELINES:
        row = baselines.get(name, {}) if isinstance(baselines.get(name), dict) else {}
        preflight_status = str(row.get("status") or "MISSING")
        if preflight_status == "READY":
            status = "READY_NOT_RUN"
        elif preflight_status.startswith("BLOCKED"):
            status = "BLOCKED_CURRENT_ENVIRONMENT"
        else:
            status = "NOT_RUN"
        rows[name] = {
            "status": status,
            "samples_with_evidence": 0,
            "sample_count": sample_count,
            "evidence": display_path(preflight_path),
            "preflight_status": preflight_status,
            "reason": row.get("reason"),
        }
    qemu_build = qemu_plugin_build_preflight_row(qemu_plugin_build_preflight_path)
    if qemu_build and "qemu_plugin" in rows:
        rows["qemu_plugin"]["system_build_load_preflight"] = qemu_build
        rows["qemu_plugin"]["evidence"] = f"{rows['qemu_plugin']['evidence']}; {qemu_build['evidence']}"
    return rows


def aggregate_baselines(
    samples: list[dict[str, Any]],
    software_summary_path: Path | None = None,
    ebpf_summary_path: Path | None = None,
    qemu_plugin_summary_path: Path | None = None,
    advanced_preflight_path: Path | None = None,
    qemu_plugin_build_preflight_path: Path | None = None,
) -> dict[str, Any]:
    present_counts = {name: 0 for name in GROUNDTRUTH_BASELINES}
    for row in samples:
        medians = row.get("groundtruth_median_ns", {})
        if not isinstance(medians, dict):
            continue
        for name in GROUNDTRUTH_BASELINES:
            if medians.get(name) is not None:
                present_counts[name] += 1
    sample_count = len(samples)
    baseline_rows: dict[str, Any] = {}
    for name in GROUNDTRUTH_BASELINES:
        baseline_rows[name] = {
            "status": "PASS" if sample_count and present_counts[name] == sample_count else "MISSING",
            "samples_with_evidence": present_counts[name],
            "sample_count": sample_count,
            "evidence": "groundtruth median timing field in aggregate metrics",
        }
    baseline_rows.update(advanced_baseline_rows(advanced_preflight_path, sample_count, qemu_plugin_build_preflight_path))
    ebpf_row = ebpf_baseline_row(ebpf_summary_path, sample_count)
    if ebpf_row is not None:
        baseline_rows["ebpf_only"] = ebpf_row
    qemu_plugin_row = qemu_plugin_baseline_row(qemu_plugin_summary_path, sample_count)
    if qemu_plugin_row is not None:
        qemu_build = baseline_rows.get("qemu_plugin", {}).get("system_build_load_preflight")
        baseline_rows["qemu_plugin"] = qemu_plugin_row
        if qemu_build:
            baseline_rows["qemu_plugin"]["system_build_load_preflight"] = qemu_build
    baseline_rows["software_instrumentation"] = software_instrumentation_baseline_row(software_summary_path, sample_count)
    baseline_rows["rvmaltrace_event_only"] = {
        "status": "PASS",
        "samples_with_evidence": sample_count,
        "sample_count": sample_count,
        "evidence": "primary 512-record hardware trace gate and per-sample trace metrics",
    }
    baseline_rows["rvmaltrace_pointer_snapshot"] = {
        "status": "DEFERRED",
        "samples_with_evidence": 0,
        "sample_count": sample_count,
        "evidence": "selective pointer snapshot route remains gated/default-disabled",
    }
    baseline_rows["rvmaltrace_helper_or_ebpf_companion"] = {
        "status": "DEFERRED",
        "samples_with_evidence": 0,
        "sample_count": sample_count,
        "evidence": "optional enrichment route, not an MVP dependency",
    }
    return baseline_rows


def build_summary(
    metrics_path: Path,
    software_summary_path: Path | None = None,
    ebpf_summary_path: Path | None = None,
    qemu_plugin_summary_path: Path | None = None,
    advanced_preflight_path: Path | None = None,
    qemu_plugin_build_preflight_path: Path | None = None,
) -> dict[str, Any]:
    metrics = load_json(metrics_path)
    rows = metrics.get("samples", [])
    if not isinstance(rows, list):
        raise ValueError(f"{metrics_path}: missing samples list")
    samples = [sample_baseline_row(row) for row in rows if isinstance(row, dict)]
    baselines = aggregate_baselines(
        samples,
        software_summary_path,
        ebpf_summary_path,
        qemu_plugin_summary_path,
        advanced_preflight_path,
        qemu_plugin_build_preflight_path,
    )
    host_qemu_ok = all(baselines[name]["status"] == "PASS" for name in GROUNDTRUTH_BASELINES)
    missing_advanced_not_pass = all(baselines[name]["status"] != "PASS" for name in MISSING_ADVANCED_BASELINES)
    software_status = baselines["software_instrumentation"]["status"]
    ebpf_status = baselines["ebpf_only"]["status"]
    qemu_status = baselines["qemu_plugin"]["status"]
    if host_qemu_ok and software_status == "PASS" and ebpf_status == "PASS" and qemu_status == "PASS" and len(samples) == 13:
        status = SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS
    elif host_qemu_ok and software_status == "PASS" and ebpf_status == "PASS" and qemu_status != "PASS" and len(samples) == 13:
        status = SOFTWARE_INSTRUMENTATION_AND_EBPF_STATUS
    elif host_qemu_ok and missing_advanced_not_pass and software_status == "PASS" and len(samples) == 13:
        status = SOFTWARE_INSTRUMENTATION_STATUS
    elif host_qemu_ok and missing_advanced_not_pass and software_status == "NOT_RUN" and len(samples) == 13:
        status = HOST_QEMU_STRACE_STATUS
    else:
        status = "INCOMPLETE"
    return {
        "schema": "rvmt.35t.baseline_evaluation.summary.v1",
        "run_id": RUN_ID,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "status": status,
        "source_metrics": display_path(metrics_path),
        "sample_count": len(samples),
        "baselines": baselines,
        "samples": samples,
        "interpretation": [
            "host native, host strace, QEMU native, and QEMU strace timing fields are present for the 13-sample 35T run",
            "software instrumentation baseline is reported as PASS only when its independent summary has schema, run-id, sample-count, and pass-count evidence",
            "eBPF-only and QEMU-plugin are reported as PASS only when their independent summaries supply 13/13 sample evidence",
            "board trace-on/off ratios are measured runtime ratios only and are not acceleration claims",
        ],
        "limitations": [
            "timing fields alone do not prove syscall semantic accuracy or anti-debug detectability",
            "QEMU-plugin syscall-count evidence is a simulator software baseline and not a hardware trace, real malware, or DBI comparison claim",
            "the eBPF-only baseline is host Linux bpftrace evidence and is not a hardware, QEMU-plugin, or pointer-snapshot substitute",
            "software instrumentation is source-level function instrumentation and does not provide syscall argument reconstruction",
            "no real malware detection quality or classifier accuracy is measured",
        ],
        "non_claims": NON_CLAIMS,
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        f"# 35T Baseline Evaluation Summary: {summary['run_id']}",
        "",
        f"Status: {summary['status']}",
        "",
        f"Scope: {summary['scope']}.",
        "",
        f"Claim level: {summary['claim_level']}.",
        "",
        "## Baselines",
        "",
        "| Baseline | Status | Samples | Evidence |",
        "| --- | --- | ---: | --- |",
    ]
    for name, row in summary["baselines"].items():
        lines.append(
            f"| `{name}` | `{row['status']}` | {row['samples_with_evidence']}/{row['sample_count']} | {row['evidence']} |"
        )
    lines += [
        "",
        "## Per-Sample Ratios",
        "",
        "| Sample | Class | host strace/native | qemu strace/native | board trace on/off | drop median | cap hits |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary["samples"]:
        lines.append(
            "| `{sample}` | `{klass}` | {host_ratio} | {qemu_ratio} | {board_ratio} | {drop} | {cap} |".format(
                sample=row.get("sample_id"),
                klass=row.get("sample_class"),
                host_ratio=format_number(row.get("host_strace_over_host_native")),
                qemu_ratio=format_number(row.get("qemu_strace_over_qemu_native")),
                board_ratio=format_number(row.get("board_trace_on_over_trace_off")),
                drop=format_number(row.get("drop_rate_median")),
                cap=row.get("cap_hit_count"),
            )
        )
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in summary["interpretation"])
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {item}" for item in summary["limitations"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in summary["non_claims"])
    return "\n".join(lines) + "\n"


def format_number(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, (int, float)):
        return f"{value:.6g}"
    return str(value)


def write_outputs(summary: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "baseline_evaluation_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "baseline_evaluation_summary.md").write_text(
        render_markdown(summary),
        encoding="utf-8",
        newline="\n",
    )


def write_fixture_metrics(path: Path, *, missing_qemu: bool = False) -> None:
    samples = []
    for index in range(13):
        groundtruth = {
            "host_native": {"median": 10.0 + index},
            "host_strace": {"median": 20.0 + index},
            "qemu_native": {"median": 30.0 + index},
            "qemu_strace": {"median": 60.0 + index},
        }
        if missing_qemu:
            groundtruth.pop("qemu_strace")
        samples.append(
            {
                "sample_id": f"sample_{index}",
                "sample_class": "benign" if index < 5 else "malware_like_synthetic",
                "status": "PASS",
                "groundtruth": groundtruth,
                "board_trace_off_runtime_ns": {"median": 100.0 + index},
                "board_trace_on_runtime_ns": {"median": 110.0 + index},
                "trace_events": {"median": 40.0},
                "drop_rate": {"median": 0.0},
                "captured_cap_reps": [],
                "alignment_precision": {"median": 0.9},
                "alignment_recall": {"median": 0.8},
                "alignment_argument_accuracy": {"median": 0.7},
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"schema": "rvmt.35t.metrics.v1", "samples": samples}, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_software_summary_fixture(path: Path, *, pass_count: int = 13, sample_count: int = 13) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": SOFTWARE_INSTRUMENTATION_SCHEMA,
                "run_id": SOFTWARE_RUN_ID,
                "status": "PASS",
                "baseline": "software_instrumentation",
                "instrumentation": "gcc -finstrument-functions host binary",
                "sample_count": sample_count,
                "pass_count": pass_count,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_ebpf_summary_fixture(path: Path, *, pass_count: int = 13, sample_count: int = 13) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": EBPF_BASELINE_SCHEMA,
                "run_id": EBPF_RUN_ID,
                "source_run_id": RUN_ID,
                "status": "PASS",
                "baseline": "ebpf_only",
                "sample_count": sample_count,
                "pass_count": pass_count,
                "instrumentation": "bpftrace tracepoint:raw_syscalls:sys_enter comm-filtered host binaries",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_qemu_plugin_summary_fixture(path: Path, *, pass_count: int = 13, sample_count: int = 13) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": QEMU_PLUGIN_BASELINE_SCHEMA,
                "run_id": QEMU_PLUGIN_RUN_ID,
                "source_run_id": RUN_ID,
                "status": QEMU_PLUGIN_BASELINE_STATUS,
                "sample_count": sample_count,
                "pass_count": pass_count,
                "qemu": {"version": "qemu-riscv64 version 8.2.2"},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_advanced_preflight_fixture(path: Path, *, blocked: bool = True) -> None:
    status = "BLOCKED_CURRENT_ENVIRONMENT" if blocked else "READY"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": ADVANCED_PREFLIGHT_SCHEMA,
                "run_id": "35t-advanced-baseline-preflight-20260523",
                "source_run_id": RUN_ID,
                "status": "BLOCKED_CURRENT_ENVIRONMENT" if blocked else "READY_TO_RUN_ADVANCED_BASELINES",
                "baselines": {
                    "ebpf_only": {"status": status, "reason": "fixture"},
                    "qemu_plugin": {"status": status, "reason": "fixture"},
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_qemu_plugin_build_preflight_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": QEMU_PLUGIN_BUILD_PREFLIGHT_SCHEMA,
                "status": QEMU_PLUGIN_BUILD_PREFLIGHT_STATUS,
                "current_condition": "fixture qemu-system plugin build/load preflight",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        metrics = root / DEFAULT_METRICS
        write_fixture_metrics(metrics)
        summary = build_summary(metrics)
        if summary["status"] != HOST_QEMU_STRACE_STATUS:
            print("[FAIL] expected complete fixture to pass host/qemu/strace baseline summary", file=sys.stderr)
            print(json.dumps(summary, indent=2), file=sys.stderr)
            return 1
        if summary["baselines"]["ebpf_only"]["status"] == "PASS":
            print("[FAIL] advanced baseline must not become PASS without evidence", file=sys.stderr)
            return 1
        write_outputs(summary, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "baseline_evaluation_summary.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        metrics = root / DEFAULT_METRICS
        software = root / DEFAULT_SOFTWARE_INSTRUMENTATION_SUMMARY
        write_fixture_metrics(metrics)
        write_software_summary_fixture(software)
        summary = build_summary(metrics, software)
        if summary["status"] != SOFTWARE_INSTRUMENTATION_STATUS:
            print("[FAIL] expected software instrumentation fixture to pass extended baseline summary", file=sys.stderr)
            print(json.dumps(summary, indent=2), file=sys.stderr)
            return 1
        if summary["baselines"]["software_instrumentation"]["status"] != "PASS":
            print("[FAIL] expected software instrumentation baseline row to pass", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        metrics = root / DEFAULT_METRICS
        software = root / DEFAULT_SOFTWARE_INSTRUMENTATION_SUMMARY
        preflight = root / DEFAULT_ADVANCED_BASELINE_PREFLIGHT
        qemu_build = root / DEFAULT_QEMU_PLUGIN_BUILD_PREFLIGHT
        write_fixture_metrics(metrics)
        write_software_summary_fixture(software)
        write_advanced_preflight_fixture(preflight, blocked=True)
        write_qemu_plugin_build_preflight_fixture(qemu_build)
        summary = build_summary(metrics, software, None, None, preflight, qemu_build)
        if summary["baselines"]["ebpf_only"]["status"] != "BLOCKED_CURRENT_ENVIRONMENT":
            print("[FAIL] expected eBPF-only row to record current-environment block", file=sys.stderr)
            return 1
        if summary["baselines"]["qemu_plugin"]["status"] != "BLOCKED_CURRENT_ENVIRONMENT":
            print("[FAIL] expected QEMU-plugin row to record current-environment block", file=sys.stderr)
            return 1
        if summary["baselines"]["qemu_plugin"].get("system_build_load_preflight", {}).get("status") != "PASS":
            print("[FAIL] expected QEMU-plugin build/load preflight to be recorded", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        metrics = root / DEFAULT_METRICS
        software = root / DEFAULT_SOFTWARE_INSTRUMENTATION_SUMMARY
        ebpf = root / DEFAULT_EBPF_BASELINE_SUMMARY
        preflight = root / DEFAULT_ADVANCED_BASELINE_PREFLIGHT
        write_fixture_metrics(metrics)
        write_software_summary_fixture(software)
        write_ebpf_summary_fixture(ebpf)
        write_advanced_preflight_fixture(preflight, blocked=True)
        summary = build_summary(metrics, software, ebpf, None, preflight)
        if summary["status"] != SOFTWARE_INSTRUMENTATION_AND_EBPF_STATUS:
            print("[FAIL] expected eBPF baseline fixture to pass extended baseline summary", file=sys.stderr)
            print(json.dumps(summary, indent=2), file=sys.stderr)
            return 1
        if summary["baselines"]["ebpf_only"]["status"] != "PASS":
            print("[FAIL] expected eBPF-only baseline row to pass", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        metrics = root / DEFAULT_METRICS
        software = root / DEFAULT_SOFTWARE_INSTRUMENTATION_SUMMARY
        ebpf = root / DEFAULT_EBPF_BASELINE_SUMMARY
        qemu_plugin = root / DEFAULT_QEMU_PLUGIN_BASELINE_SUMMARY
        preflight = root / DEFAULT_ADVANCED_BASELINE_PREFLIGHT
        qemu_build = root / DEFAULT_QEMU_PLUGIN_BUILD_PREFLIGHT
        write_fixture_metrics(metrics)
        write_software_summary_fixture(software)
        write_ebpf_summary_fixture(ebpf)
        write_qemu_plugin_summary_fixture(qemu_plugin)
        write_advanced_preflight_fixture(preflight, blocked=True)
        write_qemu_plugin_build_preflight_fixture(qemu_build)
        summary = build_summary(metrics, software, ebpf, qemu_plugin, preflight, qemu_build)
        if summary["status"] != SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS:
            print("[FAIL] expected QEMU-plugin baseline fixture to pass complete baseline summary", file=sys.stderr)
            print(json.dumps(summary, indent=2), file=sys.stderr)
            return 1
        if summary["baselines"]["qemu_plugin"]["status"] != "PASS":
            print("[FAIL] expected QEMU-plugin baseline row to pass", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        metrics = root / DEFAULT_METRICS
        write_fixture_metrics(metrics, missing_qemu=True)
        summary = build_summary(metrics)
        if summary["status"] == HOST_QEMU_STRACE_STATUS:
            print("[FAIL] expected missing qemu_strace fixture not to pass", file=sys.stderr)
            return 1
    print("[PASS] 35T baseline summary self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize host/QEMU/strace baseline evidence for the 35T run.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--metrics", type=Path, default=DEFAULT_METRICS)
    parser.add_argument("--software-instrumentation-summary", type=Path, default=DEFAULT_SOFTWARE_INSTRUMENTATION_SUMMARY)
    parser.add_argument("--ebpf-baseline-summary", type=Path, default=DEFAULT_EBPF_BASELINE_SUMMARY)
    parser.add_argument("--qemu-plugin-baseline-summary", type=Path, default=DEFAULT_QEMU_PLUGIN_BASELINE_SUMMARY)
    parser.add_argument("--advanced-baseline-preflight", type=Path, default=DEFAULT_ADVANCED_BASELINE_PREFLIGHT)
    parser.add_argument("--qemu-plugin-build-preflight", type=Path, default=DEFAULT_QEMU_PLUGIN_BUILD_PREFLIGHT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    metrics = args.metrics if args.metrics.is_absolute() else repo_root / args.metrics
    software_summary = (
        args.software_instrumentation_summary
        if args.software_instrumentation_summary.is_absolute()
        else repo_root / args.software_instrumentation_summary
    )
    ebpf_summary = (
        args.ebpf_baseline_summary
        if args.ebpf_baseline_summary.is_absolute()
        else repo_root / args.ebpf_baseline_summary
    )
    qemu_plugin_summary = (
        args.qemu_plugin_baseline_summary
        if args.qemu_plugin_baseline_summary.is_absolute()
        else repo_root / args.qemu_plugin_baseline_summary
    )
    advanced_preflight = (
        args.advanced_baseline_preflight
        if args.advanced_baseline_preflight.is_absolute()
        else repo_root / args.advanced_baseline_preflight
    )
    qemu_plugin_build_preflight = (
        args.qemu_plugin_build_preflight
        if args.qemu_plugin_build_preflight.is_absolute()
        else repo_root / args.qemu_plugin_build_preflight
    )
    evidence_root = args.evidence_root if args.evidence_root.is_absolute() else repo_root / args.evidence_root
    try:
        summary = build_summary(
            metrics,
            software_summary,
            ebpf_summary,
            qemu_plugin_summary,
            advanced_preflight,
            qemu_plugin_build_preflight,
        )
        write_outputs(summary, evidence_root)
    except Exception as exc:
        print(f"summarize_35t_baselines: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] 35T baseline evaluation summary")
    return 0 if summary["status"] in {
        HOST_QEMU_STRACE_STATUS,
        SOFTWARE_INSTRUMENTATION_STATUS,
        SOFTWARE_INSTRUMENTATION_AND_EBPF_STATUS,
        SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS,
    } else 1


if __name__ == "__main__":
    raise SystemExit(main())
