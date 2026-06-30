from __future__ import annotations

import argparse
import json
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


PRIMARY_RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
EXTENSION_RUN_ID = "35t-extension-r512-nonnetwork-20260523"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence/35t-semantic-case-study-matrix-20260523")
PROCESS_TREE_SAMPLES = ("process_chain", "multi_level_process_chain")


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


def semantic_paths(results_root: Path, sample: str) -> list[Path]:
    base = sample_dir(results_root, sample)
    if base is None:
        return []
    trace_on = base / "board/trace-on"
    if not trace_on.is_dir():
        return []
    return sorted(trace_on.glob("rep_*/behavior_recovery/semantic_events.json"))


def sequence(path: Path) -> list[dict[str, Any]]:
    data = load_json(path)
    rows = data.get("syscall_sequence", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def has_exec_path(row: dict[str, Any]) -> bool:
    if row.get("name") != "execve":
        return False
    if isinstance(row.get("path"), str) and row.get("path"):
        return True
    args = row.get("args")
    return isinstance(args, dict) and bool(args.get("a0_string"))


def summarize_candidate(repo_root: Path, path: Path) -> dict[str, Any]:
    rows = sequence(path)
    names = [str(row.get("name")) for row in rows if row.get("name")]
    has_chain = all(name in names for name in ("clone", "execve", "waitid"))
    has_wait = "waitid" in names or "wait4" in names or "waitpid" in names
    status = "closed" if has_chain and any(has_exec_path(row) for row in rows) else ("partial" if ("clone" in names and "execve" in names and has_wait) else "missing")
    return {
        "source": rel(path, repo_root),
        "rep": path.parents[1].name,
        "status": status,
        "clone_count": names.count("clone"),
        "execve_count": names.count("execve"),
        "wait_count": sum(names.count(name) for name in ("waitid", "wait4", "waitpid")),
        "exec_path_count": sum(1 for row in rows if has_exec_path(row)),
        "limitations": [] if status == "closed" else ["parent-child PID ownership or exec path string is partial"],
    }


def summarize_sample(repo_root: Path, results_roots: list[Path], sample: str) -> dict[str, Any]:
    candidates = []
    for root in results_roots:
        for path in semantic_paths(root, sample):
            candidates.append(summarize_candidate(repo_root, path))
    if not candidates:
        return {"sample_id": sample, "status": "missing", "candidate_count": 0, "selected_candidate": None, "failures": ["missing semantic candidates"]}
    rank = {"closed": 3, "partial": 2, "missing": 1}
    selected = max(candidates, key=lambda row: (rank.get(str(row.get("status")), 0), row.get("exec_path_count", 0), row.get("clone_count", 0), row.get("rep", "")))
    return {
        "sample_id": sample,
        "status": selected["status"],
        "candidate_count": len(candidates),
        "selected_candidate": selected,
        "candidate_status_counts": {state: sum(1 for row in candidates if row.get("status") == state) for state in ("closed", "partial", "missing")},
        "failures": [] if selected["status"] in {"closed", "partial"} else ["process-tree flow missing"],
    }


def build_report(repo_root: Path, primary_run_id: str, extension_run_id: str, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    results_roots = [
        repo_root / "results/experiments/35t" / primary_run_id,
        repo_root / "results/experiments/35t" / extension_run_id,
    ]
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    rows = [summarize_sample(repo_root, results_roots, sample) for sample in PROCESS_TREE_SAMPLES]
    failures = [f"{row['sample_id']}: {failure}" for row in rows for failure in row.get("failures", [])]
    checks = {
        "primary_results_root_exists": results_roots[0].is_dir(),
        "extension_results_root_exists": results_roots[1].is_dir(),
        "all_required_samples_accounted": all(row.get("status") in {"closed", "partial"} for row in rows),
        "matrix_keeps_partial_boundaries": all("status" in row and "selected_candidate" in row for row in rows),
    }
    failures.extend(key for key, ok in checks.items() if not ok)
    return {
        "schema": "rvmt.35t.process_tree_case_study_matrix.v1",
        "generated_utc": utc_now(),
        "status": "PASS" if not failures else "FAIL",
        "primary_run_id": primary_run_id,
        "extension_run_id": extension_run_id,
        "evidence_root": rel(evidence_root, repo_root),
        "samples": rows,
        "checks": checks,
        "interpretation": [
            "process-tree matrix distinguishes closed, partial, and missing evidence",
            "partial means clone/exec/wait shape is present but ownership or path closure remains bounded",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 35T Process Tree Case Study Matrix",
        "",
        f"Status: {report['status']}",
        "",
        "| Sample | Status | Candidates | Selected source |",
        "| --- | --- | ---: | --- |",
    ]
    for row in report["samples"]:
        selected = row.get("selected_candidate") if isinstance(row.get("selected_candidate"), dict) else {}
        lines.append(f"| `{row['sample_id']}` | `{row['status']}` | {row.get('candidate_count')} | `{selected.get('source', 'none')}` |")
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "process_tree_case_study_matrix.json", report)
    (evidence_root / "process_tree_case_study_matrix.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def write_fixture(root: Path, run_id: str, sample: str, *, exec_path: bool) -> None:
    rep = root / "results/experiments/35t" / run_id / "samples/malware_like_synthetic" / sample / "board/trace-on/rep_00/behavior_recovery"
    rows: list[dict[str, Any]] = [{"name": "clone"}, {"name": "execve"}, {"name": "waitid"}]
    if exec_path:
        rows[1]["args"] = {"a0_string": "/bin/true"}
    write_json(rep / "semantic_events.json", {"syscall_sequence": rows})


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, PRIMARY_RUN_ID, "process_chain", exec_path=True)
        write_fixture(root, EXTENSION_RUN_ID, "multi_level_process_chain", exec_path=False)
        report = build_report(root, PRIMARY_RUN_ID, EXTENSION_RUN_ID, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "PASS":
            print("[FAIL] expected process-tree matrix fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T process-tree case-study matrix self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the 35T process-tree case-study matrix.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--primary-run-id", default=PRIMARY_RUN_ID)
    parser.add_argument("--extension-run-id", default=EXTENSION_RUN_ID)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        report = build_report(args.repo_root, args.primary_run_id, args.extension_run_id, args.evidence_root)
        if not args.no_write:
            write_outputs(report, repo_path(args.repo_root.resolve(), args.evidence_root))
    except Exception as exc:
        print(f"check_35t_process_tree_case_study_matrix: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T process-tree case-study matrix")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
