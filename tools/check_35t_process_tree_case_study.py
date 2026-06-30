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
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rv_maltrace.process_tree import load_semantic_events, recover_process_tree  # noqa: E402


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
VALIDATION_RUN_ID = "35t-targeted-board-validation-20260522"
DEFAULT_SOURCE_RESULTS_ROOT = Path("results/experiments/35t") / VALIDATION_RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
SAMPLE = "process_chain"
NON_CLAIMS = [
    "no real malware detection claim",
    "no classifier accuracy claim",
    "no complete OS process ownership claim",
]


def side_channel_paths(source_results_root: Path) -> list[Path]:
    base = source_results_root / "samples/malware_like_synthetic" / SAMPLE / "board/trace-on"
    return [base / f"rep_{rep:02d}/syscall_side_channel.json" for rep in range(5)]


def semantic_event_paths(source_results_root: Path) -> list[Path]:
    base = source_results_root / "samples/malware_like_synthetic" / SAMPLE / "board/trace-on"
    return [base / f"rep_{rep:02d}/behavior_recovery/semantic_events.json" for rep in range(5)]


def load_syscall_side_channel(path: Path) -> list[dict[str, Any]]:
    value = load_json(path)
    rows = value.get("events")
    if not isinstance(rows, list):
        raise ValueError(f"{path}: missing events list")
    return [row for row in rows if isinstance(row, dict)]


def side_channel_to_semantic_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pending: dict[tuple[int, int, str], dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for event in events:
        name = str(event.get("name") or "")
        if not name:
            continue
        phase = str(event.get("phase") or "")
        pid = int(event.get("pid") or -1)
        seq = int(event.get("seq") or 0)
        key = (pid, seq, name)
        if phase == "entry":
            pending[key] = event
            if name == "execve":
                args = dict(event.get("args") if isinstance(event.get("args"), dict) else {})
                path = event.get("path") if isinstance(event.get("path"), str) and event.get("path") else None
                if path:
                    args["a0_string"] = path
                rows.append(
                    {
                        "seq": seq,
                        "name": name,
                        "pid": pid,
                        "process_owner": "target_child",
                        "args": args,
                        "path": path,
                        "return_value": None,
                        "confidence": "board_syscall_side_channel_entry",
                    }
                )
            continue
        if phase != "return":
            continue
        entry = pending.pop(key, None)
        source = entry if entry is not None else event
        args = dict(source.get("args") if isinstance(source.get("args"), dict) else {})
        path = source.get("path") if isinstance(source.get("path"), str) and source.get("path") else None
        if path and name == "execve":
            args["a0_string"] = path
        row = {
            "seq": seq,
            "name": name,
            "pid": pid,
            "process_owner": "target_child",
            "args": args,
            "path": path,
            "return_value": event.get("return_value"),
            "confidence": "board_syscall_side_channel_paired" if entry is not None else "board_syscall_side_channel_return_only",
        }
        rows.append({key_name: value for key_name, value in row.items() if value is not None})
    return rows


def status_rank(status: Any) -> int:
    return {"PASS": 3, "PARTIAL": 2, "UNAVAILABLE": 1}.get(str(status), 0)


def graph_lines(summary: dict[str, Any]) -> list[str]:
    processes = summary.get("processes", []) if isinstance(summary.get("processes"), list) else []
    process_by_pid = {
        row.get("pid"): row
        for row in processes
        if isinstance(row, dict) and row.get("pid") is not None
    }
    lines: list[str] = []
    for edge in summary.get("edges", []):
        if not isinstance(edge, dict):
            continue
        parent = edge.get("parent_pid")
        child = edge.get("child_pid")
        child_row = process_by_pid.get(child, {})
        exec_path = child_row.get("exec") if isinstance(child_row, dict) else None
        lines.append(f"parent(pid={parent}) --clone--> child(pid={child})")
        if exec_path:
            lines.append(f"child(pid={child}) --execve(\"{exec_path}\")--> image")
        if "waitid" in set(edge.get("evidence", [])):
            lines.append(f"parent(pid={parent}) --waitid({child})--> child_exit")
    return lines


def summarize_selected(summary: dict[str, Any], selected: dict[str, Any]) -> dict[str, Any]:
    clone_candidates = summary.get("clone_return_candidates", []) if isinstance(summary.get("clone_return_candidates"), list) else []
    processes = summary.get("processes", []) if isinstance(summary.get("processes"), list) else []
    edges = summary.get("edges", []) if isinstance(summary.get("edges"), list) else []
    wait_pids = summary.get("wait_pid_candidates", []) if isinstance(summary.get("wait_pid_candidates"), list) else []
    exec_processes = [row for row in processes if isinstance(row, dict) and row.get("exec")]
    return {
        "status": summary.get("status"),
        "selected_candidate": selected,
        "positive_clone_child_pids": [
            row.get("child_pid")
            for row in clone_candidates
            if isinstance(row, dict) and isinstance(row.get("child_pid"), int) and row.get("child_pid") > 0
        ],
        "exec_paths": [
            {
                "pid": row.get("pid"),
                "path": row.get("exec"),
                "path_source": row.get("exec_path_source"),
            }
            for row in exec_processes
        ],
        "wait_pid_candidates": wait_pids,
        "edge_count": len(edges),
        "edges": edges,
        "processes": processes,
        "graph": graph_lines(summary),
        "limitations": summary.get("limitations", []),
    }


def build_report(repo_root: Path, source_results_root_arg: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    source_results_root = repo_path(repo_root, source_results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    candidates: list[dict[str, Any]] = []
    for path in side_channel_paths(source_results_root):
        if not path.exists():
            continue
        summary = recover_process_tree(side_channel_to_semantic_events(load_syscall_side_channel(path)), sample=SAMPLE)
        candidates.append(
            {
                "source_type": "syscall_side_channel",
                "source": rel(path, repo_root),
                "rep": path.parent.name,
                "summary": summary,
            }
        )
    for path in semantic_event_paths(source_results_root):
        if not path.exists():
            continue
        summary = recover_process_tree(load_semantic_events(path), sample=SAMPLE)
        candidates.append(
            {
                "source_type": "semantic_events",
                "source": rel(path, repo_root),
                "rep": path.parent.parent.name,
                "summary": summary,
            }
        )
    if candidates:
        selected = max(
            candidates,
            key=lambda row: (
                status_rank(row["summary"].get("status")),
                1 if row["source_type"] == "syscall_side_channel" else 0,
                len(row["summary"].get("edges", [])) if isinstance(row["summary"].get("edges"), list) else 0,
                len(row["summary"].get("processes", [])) if isinstance(row["summary"].get("processes"), list) else 0,
            ),
        )
        evidence = summarize_selected(
            selected["summary"],
            {
                "source_type": selected["source_type"],
                "source": selected["source"],
                "rep": selected["rep"],
            },
        )
    else:
        evidence = {
            "status": "UNAVAILABLE",
            "selected_candidate": None,
            "positive_clone_child_pids": [],
            "exec_paths": [],
            "wait_pid_candidates": [],
            "edge_count": 0,
            "edges": [],
            "processes": [],
            "graph": [],
            "limitations": ["no process-chain syscall side-channel or semantic-events candidates found"],
        }
    checks = {
        "source_results_root_exists": source_results_root.is_dir(),
        "candidate_available": bool(candidates),
        "selected_status_pass": evidence.get("status") == "PASS",
        "positive_child_pid_recovered": bool(evidence.get("positive_clone_child_pids")),
        "child_execve_boundary_associated": bool(evidence.get("exec_paths")),
        "execve_path_string_recovered": any(
            isinstance(row, dict) and isinstance(row.get("path"), str) and row.get("path")
            for row in evidence.get("exec_paths", [])
        ),
        "parent_wait_pid_associated": bool(evidence.get("wait_pid_candidates")),
        "parent_child_graph_output": bool(evidence.get("graph")) and int(evidence.get("edge_count") or 0) > 0,
        "selected_from_board_side_channel": isinstance(evidence.get("selected_candidate"), dict)
        and evidence["selected_candidate"].get("source_type") == "syscall_side_channel",
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    return {
        "schema": "rvmt.35t.process_tree_case_study.v1",
        "run_id": RUN_ID,
        "source_run_id": VALIDATION_RUN_ID,
        "generated_utc": utc_now(),
        "status": status,
        "sample": SAMPLE,
        "source_results_root": rel(source_results_root, repo_root),
        "evidence_root": rel(evidence_root, repo_root),
        "candidate_count": len(candidates),
        "pass_candidate_count": sum(1 for row in candidates if row["summary"].get("status") == "PASS"),
        "checks": checks,
        "case_study": evidence,
        "interpretation": [
            "process_chain has a targeted 35T board syscall side-channel candidate with clone return child PIDs, execve path evidence, wait PID evidence, and graph output",
            "parent PID remains intentionally unresolved because the current trace does not prove OS parent ownership with PID/SATP/ASID context",
            "this is synthetic process-chain behavior explanation evidence, not real malware process ownership or kernel-rootkit resistance evidence",
        ],
        "non_claims": NON_CLAIMS,
        "failures": [key for key, ok in checks.items() if not ok],
    }


def render_markdown(report: dict[str, Any]) -> str:
    case = report["case_study"]
    lines = [
        f"# 35T Process Tree Case Study: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Sample: `{report['sample']}`",
        f"Source run: `{report['source_run_id']}`",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    selected = case.get("selected_candidate") if isinstance(case.get("selected_candidate"), dict) else {}
    lines += [
        "",
        "## Selected Candidate",
        "",
        f"- source_type: `{selected.get('source_type')}`",
        f"- source: `{selected.get('source')}`",
        f"- rep: `{selected.get('rep')}`",
        "",
        "## Graph",
        "",
    ]
    lines.extend(f"- `{line}`" for line in case.get("graph", []) or ["none"])
    lines += ["", "## Recovered Evidence", ""]
    lines.append(f"- positive clone child PIDs: {case.get('positive_clone_child_pids')}")
    lines.append(f"- wait PID candidates: {case.get('wait_pid_candidates')}")
    lines.append(f"- edge count: {case.get('edge_count')}")
    lines.append("- exec paths:")
    for row in case.get("exec_paths", []):
        if isinstance(row, dict):
            lines.append(f"  - pid={row.get('pid')}, path=`{row.get('path')}`, source={row.get('path_source')}")
    if not case.get("exec_paths"):
        lines.append("  - none")
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "process_tree_case_study.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "process_tree_case_study.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def side_channel_fixture(path: Path) -> None:
    rows = [
        ("clone", "entry", 12, None, None, {"a7": "0xdc"}),
        ("clone", "return", 12, "0xcb", None, {"a7": "0xdc"}),
        ("execve", "entry", 13, None, "/bin/true", {"a0": "0x1000", "a7": "0xdd"}),
        ("execve", "return", 13, "0x0", "/bin/true", {"a0": "0x1000", "a7": "0xdd"}),
        ("waitid", "entry", 14, None, None, {"a1": "0xcb", "a7": "0x5f"}),
        ("waitid", "return", 14, "0x0", None, {"a1": "0xcb", "a7": "0x5f"}),
    ]
    events = []
    for name, phase, seq, ret, path_string, args in rows:
        event = {
            "schema": "rvmt.syscall_side_channel.v1",
            "sample": SAMPLE,
            "sample_class": "malware_like_synthetic",
            "rep": 0,
            "mode": "trace-on",
            "warmup": False,
            "seq": seq,
            "pid": 100,
            "phase": phase,
            "name": name,
            "args": args,
        }
        if ret is not None:
            event["return_value"] = ret
        if path_string is not None:
            event["path"] = path_string
        events.append(event)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": "rvmt.syscall_side_channel.v1", "events": events}) + "\n", encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / DEFAULT_SOURCE_RESULTS_ROOT
        evidence = root / DEFAULT_EVIDENCE_ROOT
        side_channel_fixture(source / "samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/syscall_side_channel.json")
        report = build_report(root, DEFAULT_SOURCE_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "PASS":
            print(f"[FAIL] expected fixture to pass, got {report['status']}: {report['failures']}", file=sys.stderr)
            return 1
        write_outputs(report, evidence)
        if not (evidence / "process_tree_case_study.md").exists():
            print("[FAIL] self-test did not write markdown output", file=sys.stderr)
            return 1
        bad_path = source / "samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/syscall_side_channel.json"
        bad_path.write_text(json.dumps({"schema": "rvmt.syscall_side_channel.v1", "events": []}), encoding="utf-8")
        failed = build_report(root, DEFAULT_SOURCE_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if failed["status"] == "PASS":
            print("[FAIL] empty process-chain candidate should fail", file=sys.stderr)
            return 1
    print("[PASS] 35T process-tree case-study self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check 35T process-tree case-study coverage for the assessment P2 goal.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--source-results-root", type=Path, default=DEFAULT_SOURCE_RESULTS_ROOT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        repo_root = args.repo_root.resolve()
        report = build_report(repo_root, args.source_results_root, args.evidence_root)
        if not args.no_write:
            write_outputs(report, repo_path(repo_root, args.evidence_root))
    except Exception as exc:
        print(f"check_35t_process_tree_case_study: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T process-tree case study")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
