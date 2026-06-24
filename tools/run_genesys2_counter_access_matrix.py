from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from check_genesys2_counter_access_matrix import (
    SUMMARY_SCHEMA,
    artifact_row,
    counter_available,
    clock_available,
    parse_matrix_log,
    repo_rel,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUILD_MANIFEST = Path("build/board/genesys2_counter_access_matrix/build_manifest.json")
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260623-counter-access-matrix")
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/counter_access_matrix_summary.json")
DEFAULT_TARGET = "/tmp/rvmt_cycle/counter_access_matrix"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def run(command: list[str], *, cwd: Path, dry_run: bool) -> None:
    print("+ " + " ".join(command))
    if dry_run:
        return
    subprocess.run(command, cwd=cwd, check=True)


def make_artifacts(root: Path, source: Path, binary: Path, build_manifest: Path, transfer_log: Path, run_log: Path) -> dict[str, Any]:
    artifacts = {
        "source": artifact_row(root, source),
        "binary": artifact_row(root, binary),
        "build_manifest": artifact_row(root, build_manifest),
        "run_log": artifact_row(root, run_log),
    }
    if transfer_log.is_file():
        artifacts["transfer_log"] = artifact_row(root, transfer_log)
    return artifacts


def summarize_run(
    *,
    root: Path,
    source: Path,
    binary: Path,
    build_manifest: Path,
    transfer_log: Path,
    run_log: Path,
    summary: Path,
    minimum_repetitions: int,
    reps: int,
    iters: int,
    target: str,
) -> dict[str, Any]:
    parsed = parse_matrix_log(run_log)
    cycle_ok = counter_available(parsed, "cycle")
    rdtime_ok = counter_available(parsed, "time")
    monotonic_ok = clock_available(parsed, "clock_monotonic") or clock_available(parsed, "clock_monotonic_raw")
    cycle_rows = [row for row in parsed["counter_rows"] if row.get("name") == "cycle"]
    enough_cycle_rows = len(cycle_rows) >= minimum_repetitions
    positive_cycle_rows = all(
        int(row.get("loop_delta") or 0) > 0
        and int(row.get("syscall_delta") or 0) >= 0
        and int(row.get("total_delta") or 0) > 0
        for row in cycle_rows
    )
    if cycle_ok and enough_cycle_rows and positive_cycle_rows:
        status = "PASS"
        blocked_reason = None
    elif rdtime_ok or monotonic_ok:
        status = "BLOCKED_BOARD_CYCLE_COUNTER_UNAVAILABLE_NONCYCLE_TIME_AVAILABLE"
        blocked_reason = "user rdcycle is unavailable or incomplete; rdtime and/or clock_gettime remain available as non-cycle time sources"
    else:
        status = "BLOCKED_BOARD_COUNTER_SOURCES_UNAVAILABLE"
        blocked_reason = "user rdcycle, rdtime, and clock_gettime sources are unavailable or incomplete"
    data: dict[str, Any] = {
        "schema": SUMMARY_SCHEMA,
        "status": status,
        "run_root": repo_rel(root, run_log.parent),
        "target": target,
        "requested_repetitions": reps,
        "minimum_repetitions": minimum_repetitions,
        "iters": iters,
        **parsed,
        "artifacts": make_artifacts(root, source, binary, build_manifest, transfer_log, run_log),
        "claim_boundary": {
            "board_cycle_counter_claimed": status == "PASS",
            "board_rdtime_source_observed": rdtime_ok,
            "board_clock_gettime_source_observed": monotonic_ok,
            "cycle_level_overhead_claimed": False,
            "production_runtime_slowdown_claimed": False,
            "paper_runtime_overhead_claimed": False,
        },
        "non_claims": [
            "This probe tests user-visible counter CSR and Linux clock source accessibility on the live board.",
            "rdtime and clock_gettime are non-cycle time sources and do not close the cycle-level overhead claim.",
            "A PASS here only means user rdcycle produced monotonic-positive rows; it is not a trace-on/trace-off slowdown measurement.",
        ],
    }
    if blocked_reason:
        data["blocked_reason"] = blocked_reason
    write_json(summary, data)
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a Genesys2/CVA6 counter-access matrix over UART.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--iters", type=int, default=10000)
    parser.add_argument("--minimum-repetitions", type=int, default=5)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--build-manifest", type=Path, default=DEFAULT_BUILD_MANIFEST)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.reps <= 0 or args.iters <= 0 or args.minimum_repetitions <= 0:
        parser.error("--reps, --iters, and --minimum-repetitions must be positive")

    if not args.skip_build:
        run([sys.executable, "tools/build_genesys2_counter_access_matrix.py"], cwd=ROOT, dry_run=args.dry_run)
    build_manifest = args.build_manifest
    if args.dry_run:
        print(
            f"[DRY-RUN] would transfer built ELF from {build_manifest}, run {args.target}, "
            f"and write {args.summary}"
        )
        return 0
    if not build_manifest.is_file():
        raise FileNotFoundError(f"build manifest missing: {build_manifest}")
    build_data = load_json(build_manifest)
    source = Path(str(build_data["source"]))
    binary = Path(str(build_data["binary"]))
    if not source.is_file() or sha256_file(source) != build_data.get("source_sha256"):
        raise RuntimeError("source hash mismatch in counter-access build manifest")
    if not binary.is_file() or sha256_file(binary) != build_data.get("binary_sha256"):
        raise RuntimeError("binary hash mismatch in counter-access build manifest")

    run_root = args.run_root
    transfer_log = run_root / "transfer.log"
    run_log = run_root / "uart.log"
    run_root.mkdir(parents=True, exist_ok=True)
    run(
        [
            sys.executable,
            "tools/serial_base64_transfer.py",
            "--port",
            args.port,
            "--baud",
            str(args.baud),
            "--source",
            str(binary),
            "--target",
            args.target,
            "--log",
            str(transfer_log),
            "--chunk-read",
            "0.25",
            "--final-read",
            "3.0",
            "--disable-echo",
        ],
        cwd=ROOT,
        dry_run=False,
    )
    board_command = (
        f"echo RVMT_COUNTER_MATRIX_SHELL_READY; "
        f"{args.target} {args.reps} {args.iters}; "
        "rc=$?; echo RVMT_COUNTER_MATRIX_RC=$rc"
    )
    run(
        [
            sys.executable,
            "tools/serial_direct_command_capture.py",
            "--port",
            args.port,
            "--baud",
            str(args.baud),
            "--out",
            str(run_log),
            "--pre-read",
            "0.2",
            "--post-read",
            "10.0",
            board_command,
        ],
        cwd=ROOT,
        dry_run=False,
    )
    summary = summarize_run(
        root=ROOT,
        source=source,
        binary=binary,
        build_manifest=build_manifest,
        transfer_log=transfer_log,
        run_log=run_log,
        summary=args.summary,
        minimum_repetitions=args.minimum_repetitions,
        reps=args.reps,
        iters=args.iters,
        target=args.target,
    )
    print(f"[{summary['status']}] wrote {args.summary}")
    if summary["status"] == "PASS":
        print("[PASS] user rdcycle is available for the requested counter matrix")
        return 0
    if str(summary["status"]).startswith("BLOCKED_"):
        print(f"[{summary['status']}] {summary.get('blocked_reason')}")
        return 2
    print(f"[{summary['status']}] {summary.get('blocked_reason')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
