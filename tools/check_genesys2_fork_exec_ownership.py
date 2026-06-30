from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    require,
)

import official_image_evidence_common as common
import run_genesys2_fork_exec_ownership as runner


DEFAULT_SUMMARY = common.CURRENT_ROOT / "official_image_fork_exec_ownership_summary.json"


def check_file(root: Path, errors: list[str], row: dict[str, Any], label: str) -> None:
    path = common.repo_path(root, str(row.get("path") or ""))
    require(errors, row.get("exists") is True and path.is_file(), f"{label}: file missing")
    if path.is_file():
        require(errors, row.get("sha256") == common.sha256_file(path), f"{label}: sha256 mismatch")


def check_summary(root: Path, path: Path) -> list[str]:
    data = common.load_json(path)
    errors: list[str] = []
    status = str(data.get("status") or "")
    require(errors, data.get("schema") == runner.SCHEMA, "schema mismatch")
    require(errors, status == "PASS" or status.startswith("BLOCKED_"), "status must be PASS or BLOCKED")
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("qemu_or_strace_substitution_used") is False, "must not use qemu/strace substitution")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "must not claim cycle overhead")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "must not claim real malware")
    for name, row in (data.get("artifacts") or {}).items():
        if isinstance(row, dict) and name != "proc_snapshots":
            check_file(root, errors, row, f"artifact.{name}")
    for name, row in ((data.get("artifacts") or {}).get("proc_snapshots") or {}).items():
        if isinstance(row, dict):
            check_file(root, errors, row, f"proc.{name}")
    snapshots = data.get("runtime_snapshots") if isinstance(data.get("runtime_snapshots"), dict) else {}
    require(errors, snapshots.get("child_pre_exec_exe_matches_probe") in {True, False}, "child pre-exec probe flag missing")
    require(errors, snapshots.get("child_post_exec_exe_matches_busybox") in {True, False}, "child post-exec busybox flag missing")
    if status == "PASS":
        require(errors, boundary.get("fork_exec_process_ownership_claimed") is True, "PASS must claim process ownership")
        hardware_pid = data.get("trace_pid_tgid_fields_present") is True
        marker_pid = data.get("trace_pid_tgid_marker_fields_present") is True
        require(errors, hardware_pid or marker_pid, "PASS requires hardware PID/TGID fields or marker-assisted PID/TGID fields")
        if marker_pid:
            require(errors, boundary.get("marker_assisted_pid_tgid_pairing") is True, "marker-assisted PASS must declare marker boundary")
            markers = data.get("pid_tgid_markers") if isinstance(data.get("pid_tgid_markers"), list) else []
            marker_names = {str(row.get("name")) for row in markers if isinstance(row, dict)}
            required = {"parent_pid", "parent_tgid", "child_pid", "child_tgid", "child_pre_exec_pid", "child_pre_exec_tgid"}
            require(errors, required <= marker_names, "marker-assisted PASS missing required PID/TGID marker kinds")
    else:
        require(errors, boundary.get("fork_exec_process_ownership_claimed") is False, "BLOCKED must not claim process ownership")
        require(errors, bool(data.get("blocked_reason")), "BLOCKED summary must include blocked_reason")
        if status == "BLOCKED_TRACE_PID_TGID_NOT_EXPOSED_IN_BRAM_RECORDS":
            require(errors, data.get("trace_pid_tgid_fields_present") is False, "PID/TGID blocker requires absent fields")
            require(errors, data.get("trace_pid_tgid_marker_fields_present") is not True, "PID/TGID blocker cannot include complete marker-assisted fields")
            require(errors, boundary.get("runtime_proc_snapshots_captured") is True, "PID/TGID blocker should retain runtime snapshots")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-fork-owner-check-") as tmp:
        root = Path(tmp)
        run_root = root / "run"
        run_root.mkdir()
        for name in ("uart.log", "capture.csv", "capture.log", "capture.err.log", "bram_records.jsonl", "bram_summary.json", "fork_exec_transfer.log", "build.json"):
            (run_root / name).write_text(name, encoding="utf-8")
        proc = run_root / "proc.txt"
        proc.write_text("proc\n", encoding="utf-8")
        summary = root / "summary.json"
        common.write_json(summary, {
            "schema": runner.SCHEMA,
            "status": "BLOCKED_TRACE_PID_TGID_NOT_EXPOSED_IN_BRAM_RECORDS",
            "blocked_reason": "missing pid",
            "trace_pid_tgid_fields_present": False,
            "runtime_snapshots": {
                "child_pre_exec_exe_matches_probe": True,
                "child_post_exec_exe_matches_busybox": True,
            },
            "artifacts": {
                "uart_log": common.file_row(run_root / "uart.log"),
                "capture_csv": common.file_row(run_root / "capture.csv"),
                "capture_log": common.file_row(run_root / "capture.log"),
                "capture_err_log": common.file_row(run_root / "capture.err.log"),
                "bram_records": common.file_row(run_root / "bram_records.jsonl"),
                "bram_summary": common.file_row(run_root / "bram_summary.json"),
                "transfer_log": common.file_row(run_root / "fork_exec_transfer.log"),
                "build_manifest": common.file_row(run_root / "build.json"),
                "proc_snapshots": {"child": common.file_row(proc)},
            },
            "claim_boundary": {
                "fork_exec_process_ownership_claimed": False,
                "runtime_proc_snapshots_captured": True,
                "qemu_or_strace_substitution_used": False,
                "cycle_level_overhead_claimed": False,
                "real_malware_validation_claimed": False,
            },
        })
        errors = check_summary(root, summary)
        if errors:
            print("[FAIL] fork/exec checker blocked fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        common.write_json(summary, {
            "schema": runner.SCHEMA,
            "status": "PASS",
            "trace_pid_tgid_fields_present": False,
            "trace_pid_tgid_marker_fields_present": True,
            "pid_tgid_markers": [
                {"name": "parent_pid"},
                {"name": "parent_tgid"},
                {"name": "child_pid"},
                {"name": "child_tgid"},
                {"name": "child_pre_exec_pid"},
                {"name": "child_pre_exec_tgid"},
            ],
            "runtime_snapshots": {
                "child_pre_exec_exe_matches_probe": True,
                "child_post_exec_exe_matches_busybox": True,
            },
            "artifacts": {
                "uart_log": common.file_row(run_root / "uart.log"),
                "capture_csv": common.file_row(run_root / "capture.csv"),
                "capture_log": common.file_row(run_root / "capture.log"),
                "capture_err_log": common.file_row(run_root / "capture.err.log"),
                "bram_records": common.file_row(run_root / "bram_records.jsonl"),
                "bram_summary": common.file_row(run_root / "bram_summary.json"),
                "transfer_log": common.file_row(run_root / "fork_exec_transfer.log"),
                "build_manifest": common.file_row(run_root / "build.json"),
                "proc_snapshots": {"child": common.file_row(proc)},
            },
            "claim_boundary": {
                "fork_exec_process_ownership_claimed": True,
                "runtime_proc_snapshots_captured": True,
                "marker_assisted_pid_tgid_pairing": True,
                "qemu_or_strace_substitution_used": False,
                "cycle_level_overhead_claimed": False,
                "real_malware_validation_claimed": False,
            },
        })
        errors = check_summary(root, summary)
    if errors:
        print("[FAIL] fork/exec checker fixture failed", file=sys.stderr)
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("[PASS] official-image fork/exec ownership checker self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check official-image fork/exec ownership evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = args.summary if args.summary.is_absolute() else root / args.summary
    if not path.is_file():
        print(f"[FAIL] fork/exec ownership summary missing: {path}", file=sys.stderr)
        return 1
    errors = check_summary(root, path)
    if errors:
        print("[FAIL] fork/exec ownership summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] fork/exec ownership summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
