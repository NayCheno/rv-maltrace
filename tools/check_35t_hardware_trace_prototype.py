from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    read_json,
    read_text,
    rel,
    repo_path,
    write_json,
)


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_ASSESSMENT = Path("D:/Download/rv_maltrace_35t_assessment.md")
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
SCHEMA = "rvmt.35t.hardware_trace_prototype.v1"
STATUS = "HARDWARE_TRACE_PROTOTYPE_PASS_35T_SMALL_CAPACITY"
BENIGN_SAMPLES = ["hello", "ls", "cat", "cp", "sha256sum"]
MALWARE_LIKE_SAMPLES = [
    "file_scan",
    "batch_open_read_write",
    "self_copy_sim",
    "abnormal_syscall_sequence",
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
    "anti_debug_like",
]
EXPECTED_SAMPLES = BENIGN_SAMPLES + MALWARE_LIKE_SAMPLES
EXPECTED_PROFILES = {
    **{sample: "p0a_syscall_drop" for sample in EXPECTED_SAMPLES if sample != "illegal_trap"},
    "illegal_trap": "p0c_syscall_trap_drop",
}
EXPECTED_MASKS = {
    **{sample: "0x424" for sample in EXPECTED_SAMPLES if sample != "illegal_trap"},
    "illegal_trap": "0x42c",
}
ASSESSMENT_TOKENS = [
    "trace_records = 512",
    "trace_profile_policy = 35t_small_capacity",
    "13/13 samples PASS",
    "marker scope PASS",
    "runtime process attribution PASS",
    "UNKNOWN/corrupt = 0",
    "no cap hit",
    "per-sample minimal profile",
    "固定 512-record trace budget",
]


def sample_class(sample_id: str) -> str:
    return "benign" if sample_id in BENIGN_SAMPLES else "malware_like_synthetic"


def rows_by_sample(gate: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = gate.get("samples", [])
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("sample_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("sample_id")
    }


def reps_pass(summary: Any) -> bool:
    if not isinstance(summary, dict) or summary.get("status") != "PASS":
        return False
    reps = summary.get("reps", [])
    return bool(reps) and all(isinstance(rep, dict) and rep.get("status") == "PASS" for rep in reps)


def status_pass(value: Any) -> bool:
    if isinstance(value, dict):
        return value.get("status") == "PASS"
    return value == "PASS"


def sample_summary(sample_id: str, row: dict[str, Any], results_root: Path, repo_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    drop = row.get("drop_summary", {}) if isinstance(row.get("drop_summary"), dict) else {}
    event = row.get("event_summary", {}) if isinstance(row.get("event_summary"), dict) else {}
    marker = row.get("marker_scope_summary", {}) if isinstance(row.get("marker_scope_summary"), dict) else {}
    runtime = row.get("runtime_process_attribution_summary", {}) if isinstance(row.get("runtime_process_attribution_summary"), dict) else {}
    trace_paths = sorted(
        (
            results_root
            / "samples"
            / sample_class(sample_id)
            / sample_id
            / "board/trace-on"
        ).glob("rep_*/trace.jsonl")
    )
    trace_files = [
        {
            "path": rel(path, repo_root),
            "bytes": path.stat().st_size,
            "nonempty": path.stat().st_size > 0,
        }
        for path in trace_paths
    ]
    checks = {
        "gate_status_pass": row.get("gate_status") == "PASS",
        "sample_status_pass": status_pass(row.get("sample_status")),
        "sample_class": row.get("sample_class") == sample_class(sample_id),
        "profile_policy": row.get("trace_profile") == EXPECTED_PROFILES[sample_id],
        "marker_scope_pass": reps_pass(marker),
        "runtime_process_attribution_pass": row.get("runtime_process_attribution_proven") is True and reps_pass(runtime),
        "unknown_corrupt_zero": event.get("unknown_event_count") == 0 and event.get("corrupt_record_count") == 0,
        "unexpected_events_empty": not event.get("unexpected_events"),
        "drop_within_limit": float(drop.get("drop_rate_median", 1.0) or 0.0)
        <= float(drop.get("drop_rate_median_limit", 0.05) or 0.05),
        "no_trace_record_cap_hit": not drop.get("capped_reps"),
        "decoded_trace_reps_present": len(trace_files) == 5,
        "decoded_trace_reps_nonempty": bool(trace_files) and all(item["nonempty"] for item in trace_files),
    }
    failures.extend(key for key, ok in checks.items() if not ok)
    return {
        "sample_id": sample_id,
        "sample_class": row.get("sample_class"),
        "trace_profile": row.get("trace_profile"),
        "trace_control_mask": EXPECTED_MASKS[sample_id],
        "gate_status": row.get("gate_status"),
        "drop_rate_median": drop.get("drop_rate_median"),
        "drop_rate_median_limit": drop.get("drop_rate_median_limit"),
        "unknown_event_count": event.get("unknown_event_count"),
        "corrupt_record_count": event.get("corrupt_record_count"),
        "decoded_trace_file_count": len(trace_files),
        "decoded_trace_files": trace_files,
        "checks": checks,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
    }


def build_report(
    repo_root: Path,
    assessment_arg: Path,
    results_root_arg: Path,
    evidence_root_arg: Path,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    results_root = repo_path(repo_root, results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    failures: list[str] = []
    assessment_path = repo_path(repo_root, assessment_arg).resolve()
    assessment = read_text(assessment_path, failures, repo_root, "assessment document")
    gate_path = results_root / "aggregate/gate_report.json"
    run_config_path = results_root / "run_config.json"
    gate = read_json(gate_path, failures, repo_root, "35T gate report")
    run_config = read_json(run_config_path, failures, repo_root, "35T run config")
    rows = rows_by_sample(gate)
    sample_rows = [sample_summary(sample, rows.get(sample, {"sample_id": sample}), results_root, repo_root) for sample in EXPECTED_SAMPLES]
    trace_controls = run_config.get("trace_controls", {}) if isinstance(run_config.get("trace_controls"), dict) else {}
    checks = {
        "assessment_lists_hardware_trace_gate": all(token in assessment for token in ASSESSMENT_TOKENS),
        "results_root_exists": results_root.is_dir(),
        "gate_schema": gate.get("schema") == "rvmt.35t.next_gate.v2",
        "gate_run_id": gate.get("run_id") == RUN_ID,
        "gate_claim_level": gate.get("claim_level") == "full_matrix_ready",
        "gate_trace_records_512": gate.get("trace_records") == 512,
        "run_config_trace_records_512": run_config.get("trace_records") == 512,
        "run_config_reps_5": run_config.get("reps") == 5,
        "trace_profile_policy": gate.get("trace_profile_policy") == "35t_small_capacity"
        and run_config.get("trace_profile_policy") == "35t_small_capacity",
        "sample_set_exact": list(rows) == EXPECTED_SAMPLES and run_config.get("samples") == EXPECTED_SAMPLES,
        "sample_count_13": len(rows) == 13,
        "per_sample_profiles": gate.get("trace_profiles_by_sample") == EXPECTED_PROFILES
        and run_config.get("trace_profiles_by_sample") == EXPECTED_PROFILES,
        "per_sample_control_masks": run_config.get("trace_control_masks_by_sample") == EXPECTED_MASKS,
        "trace_controls_small_capacity": trace_controls.get("enable_marker") is True
        and trace_controls.get("enable_syscall") is True
        and trace_controls.get("enable_drop") is True
        and trace_controls.get("enable_branch") is False
        and trace_controls.get("enable_context") is False
        and trace_controls.get("enable_jump") is False
        and trace_controls.get("enable_retire") is False
        and trace_controls.get("enable_arg_mem") is False,
        "real_malware_forbidden_network_disabled": run_config.get("real_malware") == "forbidden"
        and run_config.get("network") == "disabled",
        "all_samples_gate_pass": all(row["checks"]["gate_status_pass"] for row in sample_rows),
        "all_samples_marker_scope_pass": all(row["checks"]["marker_scope_pass"] for row in sample_rows),
        "all_samples_runtime_attribution_pass": all(row["checks"]["runtime_process_attribution_pass"] for row in sample_rows),
        "all_samples_unknown_corrupt_zero": all(row["checks"]["unknown_corrupt_zero"] for row in sample_rows),
        "all_samples_drop_within_limit": all(row["checks"]["drop_within_limit"] for row in sample_rows),
        "all_samples_no_cap_hit": all(row["checks"]["no_trace_record_cap_hit"] for row in sample_rows),
        "decoded_trace_artifacts_65": sum(row["decoded_trace_file_count"] for row in sample_rows) == 65,
        "decoded_trace_artifacts_nonempty": all(row["checks"]["decoded_trace_reps_nonempty"] for row in sample_rows),
    }
    failures.extend(key for key, ok in checks.items() if not ok)
    for row in sample_rows:
        failures.extend(f"{row['sample_id']}: {failure}" for failure in row["failures"])
    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "status": STATUS if not failures else "FAIL",
        "assessment_source": str(assessment_path),
        "evidence": {
            "gate_report": rel(gate_path, repo_root),
            "run_config": rel(run_config_path, repo_root),
            "evidence_root": rel(evidence_root, repo_root),
        },
        "checks": checks,
        "trace_records": gate.get("trace_records"),
        "trace_profile_policy": gate.get("trace_profile_policy"),
        "sample_count": len(sample_rows),
        "sample_gate_pass_count": sum(1 for row in sample_rows if row.get("gate_status") == "PASS"),
        "decoded_trace_file_count": sum(row["decoded_trace_file_count"] for row in sample_rows),
        "sample_rows": sample_rows,
        "interpretation": [
            "the primary 35T run is a 512-record small-capacity full-matrix hardware trace gate",
            "the pass result comes from per-sample minimal trace profiles, not from increasing the trace ring beyond the 35T budget",
            "illegal_trap alone uses the trap-enabled profile; the other 12 samples use the syscall/drop profile",
        ],
        "boundaries": [
            "35T / LiteX / VexRiscv only; no CVA6 board claim",
            "decoded trace artifacts are local evidence and large raw UART logs remain outside the lightweight snapshot",
            "hardware trace evidence supports the prototype trace gate, not complete semantic reconstruction by itself",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Hardware Trace Prototype Check: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Trace records: {report.get('trace_records')}",
        "",
        f"Trace profile policy: {report.get('trace_profile_policy')}",
        "",
        f"Samples PASS: {report.get('sample_gate_pass_count')}/{report.get('sample_count')}",
        "",
        f"Decoded trace files: {report.get('decoded_trace_file_count')}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Samples",
        "",
        "| Sample | Class | Profile | Gate | DROP median | Decoded traces | Failures |",
        "| --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for row in report["sample_rows"]:
        lines.append(
            "| `{sample}` | `{klass}` | `{profile}` | `{gate}` | {drop} | {traces} | {failures} |".format(
                sample=row["sample_id"],
                klass=row.get("sample_class"),
                profile=row.get("trace_profile"),
                gate=row.get("gate_status"),
                drop=row.get("drop_rate_median"),
                traces=row.get("decoded_trace_file_count"),
                failures=", ".join(row.get("failures", [])) or "none",
            )
        )
    lines += ["", "## Evidence", ""]
    for key, value in report["evidence"].items():
        lines.append(f"- {key}: `{value}`")
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Boundaries", ""]
    lines.extend(f"- {item}" for item in report["boundaries"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "hardware_trace_prototype.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "hardware_trace_prototype.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def make_sample(sample: str, *, bad_profile: bool = False) -> dict[str, Any]:
    profile = "p0a_syscall_drop" if bad_profile and sample == "illegal_trap" else EXPECTED_PROFILES[sample]
    return {
        "sample_id": sample,
        "sample_class": sample_class(sample),
        "sample_status": "PASS",
        "trace_profile": profile,
        "gate_status": "PASS",
        "runtime_process_attribution_proven": True,
        "marker_scope_summary": {"status": "PASS", "reps": [{"rep": "rep_00", "status": "PASS"}]},
        "runtime_process_attribution_summary": {"status": "PASS", "reps": [{"rep": "rep_00", "status": "PASS"}]},
        "event_summary": {"unknown_event_count": 0, "corrupt_record_count": 0, "unexpected_events": []},
        "drop_summary": {"drop_rate_median": 0.0, "drop_rate_median_limit": 0.05, "capped_reps": []},
    }


def write_fixture(root: Path, *, bad_profile: bool = False) -> Path:
    assessment = root / "assessment.md"
    assessment.write_text("\n".join(ASSESSMENT_TOKENS) + "\n", encoding="utf-8", newline="\n")
    results_root = root / DEFAULT_RESULTS_ROOT
    rows = [make_sample(sample, bad_profile=bad_profile) for sample in EXPECTED_SAMPLES]
    write_json(
        results_root / "aggregate/gate_report.json",
        {
            "schema": "rvmt.35t.next_gate.v2",
            "run_id": RUN_ID,
            "claim_level": "full_matrix_ready",
            "trace_records": 512,
            "trace_profile_policy": "35t_small_capacity",
            "trace_profiles_by_sample": {
                **EXPECTED_PROFILES,
                **({"illegal_trap": "p0a_syscall_drop"} if bad_profile else {}),
            },
            "samples": rows,
        },
    )
    write_json(
        results_root / "run_config.json",
        {
            "run_id": RUN_ID,
            "reps": 5,
            "trace_records": 512,
            "trace_profile_policy": "35t_small_capacity",
            "trace_profiles_by_sample": {
                **EXPECTED_PROFILES,
                **({"illegal_trap": "p0a_syscall_drop"} if bad_profile else {}),
            },
            "trace_control_masks_by_sample": EXPECTED_MASKS,
            "trace_controls": {
                "enable_marker": True,
                "enable_syscall": True,
                "enable_drop": True,
                "enable_branch": False,
                "enable_context": False,
                "enable_jump": False,
                "enable_retire": False,
                "enable_arg_mem": False,
            },
            "real_malware": "forbidden",
            "network": "disabled",
            "samples": EXPECTED_SAMPLES,
        },
    )
    for sample in EXPECTED_SAMPLES:
        for rep_index in range(5):
            trace = results_root / "samples" / sample_class(sample) / sample / "board/trace-on" / f"rep_{rep_index:02d}" / "trace.jsonl"
            trace.parent.mkdir(parents=True, exist_ok=True)
            trace.write_text('{"evt":"MARKER"}\n', encoding="utf-8", newline="\n")
    return assessment


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = write_fixture(root)
        report = build_report(root, assessment, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != STATUS:
            print("[FAIL] expected hardware trace fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "hardware_trace_prototype.md").exists():
            print("[FAIL] missing hardware trace markdown", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = write_fixture(root, bad_profile=True)
        report = build_report(root, assessment, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL" or not any("profile" in failure for failure in report["failures"]):
            print("[FAIL] expected profile-policy fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T hardware trace prototype self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the 35T hardware trace prototype gate and small-capacity profile policy.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--assessment", type=Path, default=DEFAULT_ASSESSMENT)
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
        report = build_report(repo_root, args.assessment, args.results_root, args.evidence_root)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_hardware_trace_prototype: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T hardware trace prototype")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
