from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_ASSESSMENT = Path("D:/Download/rv_maltrace_35t_assessment.md")
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_GATE_REPORT = DEFAULT_RESULTS_ROOT / "aggregate/gate_report.json"
DEFAULT_RUN_CONFIG = DEFAULT_RESULTS_ROOT / "run_config.json"
DEFAULT_SAMPLE_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
SCHEMA = "rvmt.35t.assessment_gate_criteria.v1"
STATUS = "ASSESSMENT_GATE_CRITERIA_PASS"
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
EXPECTED_RULES = {
    "file_scan": "many_file_scan",
    "batch_open_read_write": "batch_file_read_write",
    "self_copy_sim": "self_copy_simulation",
    "abnormal_syscall_sequence": "abnormal_syscall_sequence",
    "illegal_trap": "illegal_instruction_trap",
    "process_chain": "process_creation_chain",
    "dynamic_executable_memory": "dynamic_executable_memory",
    "anti_debug_like": "anti_analysis_indicator",
}


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


def read_text(path: Path, failures: list[str], repo_root: Path, label: str) -> str:
    if not path.is_file():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return ""
    return path.read_text(encoding="utf-8")


def gate_rows(gate: dict[str, Any]) -> list[dict[str, Any]]:
    rows = gate.get("samples", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def sample_manifest_rows(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest.get("samples", [])
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and row.get("id")
    } if isinstance(rows, list) else {}


def reps_pass(summary: Any) -> bool:
    if not isinstance(summary, dict) or summary.get("status") != "PASS":
        return False
    reps = summary.get("reps", [])
    return bool(reps) and all(isinstance(rep, dict) and rep.get("status") == "PASS" for rep in reps)


def status_pass(value: Any) -> bool:
    if isinstance(value, dict):
        return value.get("status") == "PASS"
    return value == "PASS"


def sample_gate_row(row: dict[str, Any]) -> dict[str, Any]:
    sample_id = str(row.get("sample_id"))
    audit = row.get("audit_rule_summary", {}) if isinstance(row.get("audit_rule_summary"), dict) else {}
    drop = row.get("drop_summary", {}) if isinstance(row.get("drop_summary"), dict) else {}
    event = row.get("event_summary", {}) if isinstance(row.get("event_summary"), dict) else {}
    expected_rule = EXPECTED_RULES.get(sample_id)
    matched_expected = set(str(item) for item in audit.get("matched_expected", []) if item)
    expected = set(str(item) for item in audit.get("expected", []) if item)
    benign_overlap = set(str(item) for item in audit.get("benign_expected_rule_overlap", []) if item)
    checks = {
        "gate_status_pass": row.get("gate_status") == "PASS",
        "sample_status_pass": status_pass(row.get("sample_status")),
        "marker_scope_pass": reps_pass(row.get("marker_scope_summary")),
        "runtime_process_attribution_pass": row.get("runtime_process_attribution_proven") is True
        and reps_pass(row.get("runtime_process_attribution_summary")),
        "unknown_corrupt_zero": event.get("unknown_event_count") == 0 and event.get("corrupt_record_count") == 0,
        "unexpected_events_empty": not event.get("unexpected_events"),
        "drop_within_limit": float(drop.get("drop_rate_median", 1.0) or 0.0)
        <= float(drop.get("drop_rate_median_limit", 0.05) or 0.05),
        "no_trace_record_cap_hit": not drop.get("capped_reps"),
        "profile_policy": (
            row.get("trace_profile") == "p0c_syscall_trap_drop"
            if sample_id == "illegal_trap"
            else row.get("trace_profile") == "p0a_syscall_drop"
        ),
        "strong_expected_rule": (
            expected_rule in expected and expected_rule in matched_expected and not audit.get("missing")
            if sample_id in EXPECTED_RULES
            else not expected
        ),
        "benign_overlap_bounded": (
            "many_file_scan" in benign_overlap and "many_file_scan" in set(str(item) for item in audit.get("matched", []) if item)
            if sample_id == "ls"
            else not benign_overlap
        ),
    }
    return {
        "sample_id": sample_id,
        "sample_class": row.get("sample_class"),
        "trace_profile": row.get("trace_profile"),
        "gate_status": row.get("gate_status"),
        "drop_rate_median": drop.get("drop_rate_median"),
        "drop_rate_median_limit": drop.get("drop_rate_median_limit"),
        "unknown_event_count": event.get("unknown_event_count"),
        "corrupt_record_count": event.get("corrupt_record_count"),
        "expected_rule": expected_rule,
        "matched_expected": sorted(matched_expected),
        "benign_expected_rule_overlap": sorted(benign_overlap),
        "checks": checks,
        "failures": [key for key, ok in checks.items() if not ok],
    }


def build_report(
    repo_root: Path,
    assessment_arg: Path,
    gate_arg: Path,
    run_config_arg: Path,
    manifest_arg: Path,
    evidence_root_arg: Path,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    failures: list[str] = []
    assessment_path = repo_path(repo_root, assessment_arg).resolve()
    gate_path = repo_path(repo_root, gate_arg).resolve()
    run_config_path = repo_path(repo_root, run_config_arg).resolve()
    manifest_path = repo_path(repo_root, manifest_arg).resolve()
    assessment = read_text(assessment_path, failures, repo_root, "assessment document")
    gate = read_json(gate_path, failures, repo_root, "gate report")
    run_config = read_json(run_config_path, failures, repo_root, "run config")
    manifest = read_json(manifest_path, failures, repo_root, "malware-like manifest")
    sample_matrix = read_json(evidence_root / "sample_matrix_summary.json", [], repo_root, "sample matrix summary")

    rows = gate_rows(gate)
    rows_by_id = {str(row.get("sample_id")): row for row in rows}
    manifest_by_id = sample_manifest_rows(manifest)
    sample_rows = [sample_gate_row(rows_by_id.get(sample, {"sample_id": sample})) for sample in EXPECTED_SAMPLES]
    trace_profiles = run_config.get("trace_profiles_by_sample", {}) if isinstance(run_config.get("trace_profiles_by_sample"), dict) else {}
    manifest_samples = {sample: manifest_by_id.get(sample, {}) for sample in MALWARE_LIKE_SAMPLES}

    checks = {
        "assessment_lists_gate_conditions": all(
            token in assessment
            for token in [
                "13/13 PASS",
                "marker scope",
                "runtime process attribution",
                "UNKNOWN/corrupt events",
                "median DROP rate",
                "trace record cap hit",
                "strong expected audit evidence",
                "benign overlap",
            ]
        ),
        "gate_schema": gate.get("schema") == "rvmt.35t.next_gate.v2",
        "gate_run_id": gate.get("run_id") == RUN_ID,
        "gate_claim_level": gate.get("claim_level") == "full_matrix_ready",
        "trace_records_512": gate.get("trace_records") == 512 and run_config.get("trace_records") == 512,
        "trace_profile_policy": gate.get("trace_profile_policy") == "35t_small_capacity"
        and run_config.get("trace_profile_policy") == "35t_small_capacity",
        "sample_set_exact": list(rows_by_id) == EXPECTED_SAMPLES,
        "sample_count_13": len(rows) == 13,
        "benign_malware_like_split": [
            str(rows_by_id.get(sample, {}).get("sample_class")) for sample in BENIGN_SAMPLES
        ] == ["benign"] * 5
        and [
            str(rows_by_id.get(sample, {}).get("sample_class")) for sample in MALWARE_LIKE_SAMPLES
        ] == ["malware_like_synthetic"] * 8,
        "sample_status_13_pass": all(row.get("gate_status") == "PASS" for row in rows)
        and all(row.get("status") == "PASS" for row in gate.get("sample_status", {}).values())
        if isinstance(gate.get("sample_status"), dict)
        else False,
        "marker_scope_all_reps_pass": all(item["checks"]["marker_scope_pass"] for item in sample_rows),
        "runtime_process_attribution_all_reps_pass": all(
            item["checks"]["runtime_process_attribution_pass"] for item in sample_rows
        ),
        "unknown_corrupt_zero_all_samples": all(item["checks"]["unknown_corrupt_zero"] for item in sample_rows),
        "drop_within_limit_all_samples": all(item["checks"]["drop_within_limit"] for item in sample_rows),
        "no_cap_hit_all_samples": all(item["checks"]["no_trace_record_cap_hit"] for item in sample_rows),
        "strong_expected_rules_all_malware_like": all(
            item["checks"]["strong_expected_rule"] for item in sample_rows if item["sample_id"] in EXPECTED_RULES
        ),
        "ls_benign_overlap_bounded": next(item for item in sample_rows if item["sample_id"] == "ls")["checks"][
            "benign_overlap_bounded"
        ],
        "per_sample_profile_policy": trace_profiles == {
            **{sample: "p0a_syscall_drop" for sample in EXPECTED_SAMPLES if sample != "illegal_trap"},
            "illegal_trap": "p0c_syscall_trap_drop",
        },
        "run_config_real_malware_forbidden": run_config.get("real_malware") == "forbidden"
        and run_config.get("network") == "disabled",
        "malware_like_manifest_synthetic_non_network": all(
            row.get("class") == "malware_like_synthetic"
            and row.get("real_malware") is False
            and row.get("network_required") is False
            for row in manifest_samples.values()
        ),
        "sample_matrix_summary_matches": sample_matrix.get("full_matrix_ready") is True
        and sample_matrix.get("gate") == "13/13 PASS"
        and sample_matrix.get("trace_records") == 512
        if sample_matrix
        else True,
    }
    failures.extend(key for key, ok in checks.items() if not ok)
    for item in sample_rows:
        failures.extend(f"{item['sample_id']}: {failure}" for failure in item["failures"])

    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "status": STATUS if not failures else "FAIL",
        "assessment_source": str(assessment_path),
        "evidence": {
            "gate_report": rel(gate_path, repo_root),
            "run_config": rel(run_config_path, repo_root),
            "sample_manifest": rel(manifest_path, repo_root),
            "sample_matrix_summary": rel(evidence_root / "sample_matrix_summary.json", repo_root),
        },
        "checks": checks,
        "sample_rows": sample_rows,
        "interpretation": [
            "the 35T primary gate is a 512-record, 13-sample full-matrix PASS under the small-capacity profile policy",
            "marker scope and runtime process attribution pass for every trace-on repetition in the primary gate",
            "benign overlap is explicitly bounded to the ls directory traversal rule and is not a malware-detection claim",
        ],
        "non_claims": [
            "no real malware detection claim",
            "no classifier accuracy claim",
            "no complete semantic reconstruction claim",
            "no CVA6 board claim",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Assessment Gate Criteria: {report['run_id']}",
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
        "## Samples",
        "",
        "| Sample | Class | Profile | Gate | DROP median | Expected rule | Benign overlap | Failures |",
        "| --- | --- | --- | --- | ---: | --- | --- | --- |",
    ]
    for row in report["sample_rows"]:
        lines.append(
            "| `{sample}` | `{klass}` | `{profile}` | `{gate}` | {drop} | {expected} | {overlap} | {failures} |".format(
                sample=row["sample_id"],
                klass=row.get("sample_class"),
                profile=row.get("trace_profile"),
                gate=row.get("gate_status"),
                drop=row.get("drop_rate_median"),
                expected=row.get("expected_rule") or "none",
                overlap=", ".join(row.get("benign_expected_rule_overlap", [])) or "none",
                failures=", ".join(row.get("failures", [])) or "none",
            )
        )
    lines += ["", "## Evidence", ""]
    for key, value in report["evidence"].items():
        lines.append(f"- {key}: `{value}`")
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "assessment_gate_criteria.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "assessment_gate_criteria.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def make_sample(sample: str, *, bad: bool = False) -> dict[str, Any]:
    expected = EXPECTED_RULES.get(sample)
    profile = "p0c_syscall_trap_drop" if sample == "illegal_trap" else "p0a_syscall_drop"
    matched_expected = [] if bad and sample == "file_scan" else ([expected] if expected else [])
    expected_list = [expected] if expected else []
    matched = matched_expected or (["many_file_scan"] if sample == "ls" else [])
    return {
        "sample_id": sample,
        "sample_class": "benign" if sample in BENIGN_SAMPLES else "malware_like_synthetic",
        "sample_status": "PASS",
        "trace_profile": profile,
        "gate_status": "PASS",
        "gate_failures": [],
        "gate_blockers": [],
        "runtime_process_attribution_proven": True,
        "marker_scope_summary": {"status": "PASS", "reps": [{"rep": "rep_00", "status": "PASS"}]},
        "runtime_process_attribution_summary": {"status": "PASS", "reps": [{"rep": "rep_00", "status": "PASS"}]},
        "event_summary": {"unknown_event_count": 0, "corrupt_record_count": 0, "unexpected_events": []},
        "drop_summary": {"drop_rate_median": 0.0, "drop_rate_median_limit": 0.05, "capped_reps": []},
        "audit_rule_summary": {
            "expected": expected_list,
            "matched": matched,
            "matched_expected": matched_expected,
            "missing": ["many_file_scan"] if bad and sample == "file_scan" else [],
            "benign_expected_rule_overlap": ["many_file_scan"] if sample == "ls" else [],
        },
    }


def write_fixture(root: Path, *, bad_expected: bool = False) -> Path:
    assessment = root / "assessment.md"
    assessment.write_text(
        "\n".join(
            [
                "13/13 PASS",
                "marker scope",
                "runtime process attribution",
                "UNKNOWN/corrupt events",
                "median DROP rate",
                "trace record cap hit",
                "strong expected audit evidence",
                "benign overlap",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    rows = [make_sample(sample, bad=bad_expected) for sample in EXPECTED_SAMPLES]
    write_json(
        root / DEFAULT_GATE_REPORT,
        {
            "schema": "rvmt.35t.next_gate.v2",
            "run_id": RUN_ID,
            "claim_level": "full_matrix_ready",
            "trace_records": 512,
            "trace_profile_policy": "35t_small_capacity",
            "samples": rows,
            "sample_status": {sample: {"status": "PASS"} for sample in EXPECTED_SAMPLES},
        },
    )
    write_json(
        root / DEFAULT_RUN_CONFIG,
        {
            "run_id": RUN_ID,
            "trace_records": 512,
            "trace_profile_policy": "35t_small_capacity",
            "real_malware": "forbidden",
            "network": "disabled",
            "trace_profiles_by_sample": {
                **{sample: "p0a_syscall_drop" for sample in EXPECTED_SAMPLES if sample != "illegal_trap"},
                "illegal_trap": "p0c_syscall_trap_drop",
            },
        },
    )
    write_json(
        root / DEFAULT_SAMPLE_MANIFEST,
        {
            "sample_class": "malware_like_synthetic",
            "samples": [
                {
                    "id": sample,
                    "class": "malware_like_synthetic",
                    "real_malware": False,
                    "network_required": False,
                }
                for sample in MALWARE_LIKE_SAMPLES
            ],
        },
    )
    write_json(
        root / DEFAULT_EVIDENCE_ROOT / "sample_matrix_summary.json",
        {"full_matrix_ready": True, "gate": "13/13 PASS", "trace_records": 512},
    )
    return assessment


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = write_fixture(root)
        report = build_report(root, assessment, DEFAULT_GATE_REPORT, DEFAULT_RUN_CONFIG, DEFAULT_SAMPLE_MANIFEST, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != STATUS:
            print("[FAIL] expected gate criteria fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "assessment_gate_criteria.md").exists():
            print("[FAIL] missing gate criteria markdown", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = write_fixture(root, bad_expected=True)
        report = build_report(root, assessment, DEFAULT_GATE_REPORT, DEFAULT_RUN_CONFIG, DEFAULT_SAMPLE_MANIFEST, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL" or not any("file_scan: strong_expected_rule" in item for item in report["failures"]):
            print("[FAIL] expected missing strong rule fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T assessment gate criteria self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the concrete 35T gate criteria named by the assessment.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--assessment", type=Path, default=DEFAULT_ASSESSMENT)
    parser.add_argument("--gate-report", type=Path, default=DEFAULT_GATE_REPORT)
    parser.add_argument("--run-config", type=Path, default=DEFAULT_RUN_CONFIG)
    parser.add_argument("--sample-manifest", type=Path, default=DEFAULT_SAMPLE_MANIFEST)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(
            repo_root,
            args.assessment,
            args.gate_report,
            args.run_config,
            args.sample_manifest,
            args.evidence_root,
        )
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_assessment_gate_criteria: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T assessment gate criteria")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
