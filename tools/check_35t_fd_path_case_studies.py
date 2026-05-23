from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rv_maltrace.fd_path_flow import load_semantic_events, recover_fd_path_flow  # noqa: E402


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
VALIDATION_RUN_ID = "35t-targeted-board-validation-20260522"
DEFAULT_SOURCE_RESULTS_ROOT = Path("results/experiments/35t") / VALIDATION_RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
REQUIRED_SAMPLES = ("file_scan", "batch_open_read_write", "self_copy_sim")
EXPECTED_STATUS = "PASS"
NON_CLAIMS = [
    "no real malware detection claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
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


def side_channel_paths(source_results_root: Path, sample: str) -> list[Path]:
    base = source_results_root / "samples/malware_like_synthetic" / sample / "board/trace-on"
    return [base / f"rep_{rep:02d}/syscall_side_channel.json" for rep in range(5)]


def semantic_event_paths(source_results_root: Path, sample: str) -> list[Path]:
    base = source_results_root / "samples/malware_like_synthetic" / sample / "board/trace-on"
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
        if path and name == "openat":
            args["a1_string"] = path
        elif path and name == "execve":
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


def flow_examples(summary: dict[str, Any]) -> list[dict[str, Any]]:
    examples = []
    for flow in summary.get("flows", []):
        if not isinstance(flow, dict):
            continue
        examples.append(
            {
                "path": flow.get("path"),
                "path_source": flow.get("path_source"),
                "fd": flow.get("fd"),
                "fd_generation": flow.get("fd_generation"),
                "ops": flow.get("ops", []),
                "status": flow.get("status"),
                "confidence": flow.get("confidence"),
            }
        )
    return examples


def summarize_sample(source_results_root: Path, repo_root: Path, sample: str) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for path in side_channel_paths(source_results_root, sample):
        if not path.exists():
            continue
        summary = recover_fd_path_flow(side_channel_to_semantic_events(load_syscall_side_channel(path)), sample=sample)
        candidates.append(
            {
                "source_type": "syscall_side_channel",
                "source": rel(path, repo_root),
                "rep": path.parent.name,
                "summary": summary,
            }
        )
    for path in semantic_event_paths(source_results_root, sample):
        if not path.exists():
            continue
        summary = recover_fd_path_flow(load_semantic_events(path), sample=sample)
        candidates.append(
            {
                "source_type": "semantic_events",
                "source": rel(path, repo_root),
                "rep": path.parent.parent.name,
                "summary": summary,
            }
        )
    if not candidates:
        return {
            "sample": sample,
            "status": "UNAVAILABLE",
            "candidate_count": 0,
            "pass_candidate_count": 0,
            "selected_candidate": None,
            "flow_examples": [],
            "limitations": ["no syscall side-channel or semantic-events candidates found"],
        }
    selected = max(
        candidates,
        key=lambda row: (
            status_rank(row["summary"].get("status")),
            1 if row["source_type"] == "syscall_side_channel" else 0,
            int(row["summary"].get("observed_counts", {}).get("closed_flows", 0))
            if isinstance(row["summary"].get("observed_counts"), dict)
            else 0,
            int(row["summary"].get("observed_counts", {}).get("flows", 0))
            if isinstance(row["summary"].get("observed_counts"), dict)
            else 0,
        ),
    )
    summary = selected["summary"]
    observed = summary.get("observed_counts", {}) if isinstance(summary.get("observed_counts"), dict) else {}
    return {
        "sample": sample,
        "status": summary.get("status"),
        "candidate_count": len(candidates),
        "pass_candidate_count": sum(1 for row in candidates if row["summary"].get("status") == "PASS"),
        "selected_candidate": {
            "source_type": selected["source_type"],
            "source": selected["source"],
            "rep": selected["rep"],
        },
        "closed_flow_count": observed.get("closed_flows", 0),
        "flow_count": observed.get("flows", 0),
        "unresolved_fd_count": observed.get("unresolved_fds", 0),
        "pending_openat_count": observed.get("pending_openats", 0),
        "return_only_fd_op_count": observed.get("return_only_fd_ops", 0),
        "flow_examples": flow_examples(summary),
        "limitations": summary.get("limitations", []),
    }


def build_report(repo_root: Path, source_results_root_arg: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    source_results_root = repo_path(repo_root, source_results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    samples = {sample: summarize_sample(source_results_root, repo_root, sample) for sample in REQUIRED_SAMPLES}
    checks = {
        "source_results_root_exists": source_results_root.is_dir(),
        "all_required_samples_present": set(samples) == set(REQUIRED_SAMPLES),
        "all_required_samples_pass": all(row.get("status") == "PASS" for row in samples.values()),
        "all_have_closed_flows": all(int(row.get("closed_flow_count") or 0) > 0 for row in samples.values()),
        "all_selected_from_board_side_channel": all(
            isinstance(row.get("selected_candidate"), dict)
            and row["selected_candidate"].get("source_type") == "syscall_side_channel"
            for row in samples.values()
        ),
        "all_keep_unresolved_fields_explicit": all(
            "unresolved_fd_count" in row and "pending_openat_count" in row and "limitations" in row
            for row in samples.values()
        ),
    }
    status = EXPECTED_STATUS if all(checks.values()) else "FAIL"
    return {
        "schema": "rvmt.35t.fd_path_case_studies.v1",
        "run_id": RUN_ID,
        "source_run_id": VALIDATION_RUN_ID,
        "generated_utc": utc_now(),
        "status": status,
        "source_results_root": rel(source_results_root, repo_root),
        "evidence_root": rel(evidence_root, repo_root),
        "required_samples": list(REQUIRED_SAMPLES),
        "checks": checks,
        "samples": samples,
        "interpretation": [
            "file_scan, batch_open_read_write, and self_copy_sim each have at least one board syscall side-channel candidate with closed fd/path flows",
            "path strings come from the targeted board syscall side-channel, not from raw hardware user-pointer snapshots",
            "canonical fd_path_flow_summary.json remains the selected compact file_scan explanation; this artifact records the broader P1 case-study coverage",
        ],
        "non_claims": NON_CLAIMS,
        "failures": [key for key, ok in checks.items() if not ok],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T fd/path Case Studies: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Source run: `{report['source_run_id']}`",
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
        "| Sample | Status | PASS Candidates | Closed Flows | Selected Source |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for sample in report["required_samples"]:
        row = report["samples"].get(sample, {})
        selected = row.get("selected_candidate") if isinstance(row.get("selected_candidate"), dict) else {}
        lines.append(
            f"| `{sample}` | `{row.get('status')}` | {row.get('pass_candidate_count')}/{row.get('candidate_count')} | "
            f"{row.get('closed_flow_count')} | `{selected.get('source', 'none')}` |"
        )
    lines += ["", "## Flow Examples", ""]
    for sample in report["required_samples"]:
        row = report["samples"].get(sample, {})
        lines.append(f"### `{sample}`")
        for flow in row.get("flow_examples", []):
            if not isinstance(flow, dict):
                continue
            ops = ", ".join(str(item) for item in flow.get("ops", []))
            lines.append(
                f"- path=`{flow.get('path')}`, fd={flow.get('fd')}, status={flow.get('status')}, "
                f"path_source={flow.get('path_source')}, ops={ops}"
            )
        if not row.get("flow_examples"):
            lines.append("- none")
        lines.append("")
    lines += ["## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "fd_path_case_studies.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "fd_path_case_studies.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def side_channel_fixture(path: Path, sample: str, flows: list[tuple[str, int, list[str]]]) -> None:
    events: list[dict[str, Any]] = []
    seq = 10
    for path_string, fd, ops in flows:
        open_args = {"a0": "0xffffffffffffff9c", "a1": hex(0x1000 + seq), "a7": "0x38"}
        events.append(
            {
                "schema": "rvmt.syscall_side_channel.v1",
                "sample": sample,
                "sample_class": "malware_like_synthetic",
                "rep": 0,
                "mode": "trace-on",
                "warmup": False,
                "seq": seq,
                "pid": 100,
                "phase": "entry",
                "name": "openat",
                "nr": 56,
                "args": open_args,
                "path": path_string,
            }
        )
        events.append(
            {
                "schema": "rvmt.syscall_side_channel.v1",
                "sample": sample,
                "sample_class": "malware_like_synthetic",
                "rep": 0,
                "mode": "trace-on",
                "warmup": False,
                "seq": seq,
                "pid": 100,
                "phase": "return",
                "name": "openat",
                "nr": 56,
                "args": open_args,
                "path": path_string,
                "return_value": hex(fd),
            }
        )
        seq += 1
        for op in ops:
            args = {"a0": hex(fd), "a7": "0x3e" if op == "close" else "0x3f"}
            events.append(
                {
                    "schema": "rvmt.syscall_side_channel.v1",
                    "sample": sample,
                    "sample_class": "malware_like_synthetic",
                    "rep": 0,
                    "mode": "trace-on",
                    "warmup": False,
                    "seq": seq,
                    "pid": 100,
                    "phase": "entry",
                    "name": op,
                    "nr": 57 if op == "close" else 63,
                    "args": args,
                }
            )
            events.append(
                {
                    "schema": "rvmt.syscall_side_channel.v1",
                    "sample": sample,
                    "sample_class": "malware_like_synthetic",
                    "rep": 0,
                    "mode": "trace-on",
                    "warmup": False,
                    "seq": seq,
                    "pid": 100,
                    "phase": "return",
                    "name": op,
                    "nr": 57 if op == "close" else 63,
                    "args": args,
                    "return_value": "0x0",
                }
            )
            seq += 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": "rvmt.syscall_side_channel.v1", "events": events}) + "\n", encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / DEFAULT_SOURCE_RESULTS_ROOT
        evidence = root / DEFAULT_EVIDENCE_ROOT
        fixtures = {
            "file_scan": [("fixtures/scan_root", 3, ["getdents64", "close"])],
            "batch_open_read_write": [("fixtures/in.txt", 3, ["read", "close"]), ("/tmp/out.txt", 4, ["write", "close"])],
            "self_copy_sim": [("/usr/bin/self_copy_sim", 3, ["read", "close"]), ("/tmp/rvmt_self_copy_sim.bin", 4, ["write", "close"])],
        }
        for sample, flows in fixtures.items():
            side_channel_fixture(
                source / "samples/malware_like_synthetic" / sample / "board/trace-on/rep_00/syscall_side_channel.json",
                sample,
                flows,
            )
        report = build_report(root, DEFAULT_SOURCE_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "PASS":
            print(f"[FAIL] expected fixture to pass, got {report['status']}: {report['failures']}", file=sys.stderr)
            return 1
        write_outputs(report, evidence)
        if not (evidence / "fd_path_case_studies.md").exists():
            print("[FAIL] self-test did not write markdown output", file=sys.stderr)
            return 1
        missing_source = source / "samples/malware_like_synthetic/self_copy_sim/board/trace-on/rep_00/syscall_side_channel.json"
        missing_source.unlink()
        failed = build_report(root, DEFAULT_SOURCE_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if failed["status"] == "PASS":
            print("[FAIL] missing required case-study sample should fail", file=sys.stderr)
            return 1
    print("[PASS] 35T fd/path case-study self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check 35T fd/path case-study coverage for the assessment P1 goal.")
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
        print(f"check_35t_fd_path_case_studies: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T fd/path case studies")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
