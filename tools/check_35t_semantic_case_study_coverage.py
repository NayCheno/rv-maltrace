from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from experiment_common import (
    utc_now,
)


TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

from check_35t_fd_path_case_study_matrix import (  # noqa: E402
    DEFAULT_EVIDENCE_ROOT,
    EXTENSION_RUN_ID,
    FD_PATH_SAMPLES,
    PRIMARY_RUN_ID,
    build_report as build_fd_path_report,
    repo_path,
    rel,
    write_json,
)
from check_35t_process_tree_case_study_matrix import (  # noqa: E402
    PROCESS_TREE_SAMPLES,
    build_report as build_process_tree_report,
)


MEMORY_ANTI_ANALYSIS_SAMPLES = (
    "timing_anti_analysis_loop",
    "proc_status_tracerpid_check",
    "self_modifying_code_sim",
    "mprotect_exec_variant",
    "dynamic_executable_memory",
    "anti_debug_like",
)


def sample_dir(results_root: Path, sample: str) -> Path | None:
    candidates = [
        results_root / "samples/malware_like_synthetic" / sample,
        results_root / "samples" / sample,
    ]
    candidates.extend(sorted((results_root / "samples").glob(f"*/{sample}")) if (results_root / "samples").is_dir() else [])
    for path in candidates:
        if path.is_dir():
            return path
    return None


def behavior_audit_count(results_root: Path, sample: str) -> int:
    base = sample_dir(results_root, sample)
    if base is None:
        return 0
    trace_on = base / "board/trace-on"
    if not trace_on.is_dir():
        return 0
    return sum(1 for path in trace_on.glob("rep_*/behavior_audit/behavior_audit.json") if path.is_file())


def summarize_behavior_only(repo_root: Path, primary_run_id: str, extension_run_id: str, sample: str) -> dict[str, Any]:
    roots = [
        repo_root / "results/experiments/35t" / primary_run_id,
        repo_root / "results/experiments/35t" / extension_run_id,
    ]
    counts = [{"results_root": rel(root, repo_root), "behavior_audit_count": behavior_audit_count(root, sample)} for root in roots]
    total = sum(row["behavior_audit_count"] for row in counts)
    return {
        "sample_id": sample,
        "status": "covered" if total > 0 else "missing",
        "coverage_kind": "behavior_audit_only",
        "behavior_audit_count": total,
        "sources": counts,
        "boundary": "not required to close fd/path or process tree",
        "failures": [] if total > 0 else ["missing behavior audit artifacts"],
    }


def build_report(repo_root: Path, primary_run_id: str, extension_run_id: str, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    fd_path = build_fd_path_report(repo_root, primary_run_id, extension_run_id, evidence_root_arg)
    process_tree = build_process_tree_report(repo_root, primary_run_id, extension_run_id, evidence_root_arg)
    behavior_only = [
        summarize_behavior_only(repo_root, primary_run_id, extension_run_id, sample)
        for sample in MEMORY_ANTI_ANALYSIS_SAMPLES
    ]
    checks = {
        "fd_path_matrix_pass": fd_path.get("status") == "PASS",
        "process_tree_matrix_pass": process_tree.get("status") == "PASS",
        "behavior_only_samples_covered": all(row.get("status") == "covered" for row in behavior_only),
        "memory_anti_analysis_not_forced_into_fd_path": all(row.get("coverage_kind") == "behavior_audit_only" for row in behavior_only),
    }
    failures = [key for key, ok in checks.items() if not ok]
    for row in behavior_only:
        for failure in row.get("failures", []):
            failures.append(f"{row['sample_id']}: {failure}")
    return {
        "schema": "rvmt.35t.semantic_case_study_coverage.v1",
        "generated_utc": utc_now(),
        "status": "PASS" if not failures else "FAIL",
        "primary_run_id": primary_run_id,
        "extension_run_id": extension_run_id,
        "evidence_root": rel(evidence_root, repo_root),
        "fd_path_samples": list(FD_PATH_SAMPLES),
        "process_tree_samples": list(PROCESS_TREE_SAMPLES),
        "behavior_only_samples": behavior_only,
        "checks": checks,
        "interpretation": [
            "fd/path and process-tree samples are checked through dedicated matrices",
            "memory and anti-analysis samples are represented as behavior-audit coverage and are not overclaimed as fd/path closure",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 35T Semantic Case Study Coverage",
        "",
        f"Status: {report['status']}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Behavior-only Samples", "", "| Sample | Status | Audit artifacts | Boundary |", "| --- | --- | ---: | --- |"]
    for row in report["behavior_only_samples"]:
        lines.append(f"| `{row['sample_id']}` | `{row['status']}` | {row['behavior_audit_count']} | {row['boundary']} |")
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "semantic_case_study_coverage.json", report)
    (evidence_root / "semantic_case_study_coverage.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check overall 35T semantic case-study coverage.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--primary-run-id", default=PRIMARY_RUN_ID)
    parser.add_argument("--extension-run-id", default=EXTENSION_RUN_ID)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = build_report(args.repo_root, args.primary_run_id, args.extension_run_id, args.evidence_root)
        if not args.no_write:
            write_outputs(report, repo_path(args.repo_root.resolve(), args.evidence_root))
    except Exception as exc:
        print(f"check_35t_semantic_case_study_coverage: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T semantic case-study coverage")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
