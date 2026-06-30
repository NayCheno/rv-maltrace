from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from check_genesys2_cycle_counter_smoke import SUMMARY_SCHEMA, parse_cycle_log
from genesys2_experiment_common import (
    capture_board_command,
    load_checked_build_artifacts,
    make_run_artifacts,
    repo_rel,
    report_summary_exit,
    run,
    transfer_binary,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUILD_MANIFEST = Path("build/board/genesys2_cycle_counter_smoke/build_manifest.json")
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260623-cycle-counter-smoke")
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/cycle_counter_smoke_summary.json")
DEFAULT_TARGET = "/tmp/rvmt_cycle/cycle_counter_smoke"


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
    rows, unavailable = parse_cycle_log(run_log)
    enough_rows = len(rows) >= minimum_repetitions
    positive_rows = all(
        int(row.get("loop_delta") or 0) > 0
        and int(row.get("syscall_delta") or 0) > 0
        and int(row.get("total_delta") or 0) > 0
        for row in rows
    )
    if unavailable:
        status = "BLOCKED_BOARD_RDCYCLE_UNAVAILABLE"
        blocked_reason = unavailable
    elif enough_rows and positive_rows:
        status = "PASS"
        blocked_reason = None
    else:
        status = "BLOCKED_BOARD_CYCLE_SMOKE_INCOMPLETE"
        blocked_reason = f"parsed_rows={len(rows)} minimum_repetitions={minimum_repetitions}"
    data: dict[str, Any] = {
        "schema": SUMMARY_SCHEMA,
        "status": status,
        "run_root": repo_rel(root, run_log.parent),
        "target": target,
        "requested_repetitions": reps,
        "minimum_repetitions": minimum_repetitions,
        "iters": iters,
        "rows": rows,
        "row_count": len(rows),
        "artifacts": make_run_artifacts(root, source, binary, build_manifest, transfer_log, run_log),
        "claim_boundary": {
            "board_rdcycle_smoke_claimed": status == "PASS",
            "cycle_level_overhead_claimed": False,
            "production_runtime_slowdown_claimed": False,
            "paper_runtime_overhead_claimed": False,
        },
        "non_claims": [
            "This is a board-native rdcycle accessibility and monotonic-positive smoke test.",
            "It is not a production runtime slowdown claim and is not normalized against trace-off/trace-on modes.",
        ],
    }
    if blocked_reason:
        data["blocked_reason"] = blocked_reason
    write_json(summary, data)
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a Genesys2/CVA6 board-native rdcycle smoke benchmark over UART.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--reps", type=int, default=10)
    parser.add_argument("--iters", type=int, default=100000)
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
        run([sys.executable, "tools/build_genesys2_cycle_counter_smoke.py"], cwd=ROOT, dry_run=args.dry_run)
    build_manifest = args.build_manifest
    if args.dry_run:
        print(
            f"[DRY-RUN] would transfer built ELF from {build_manifest}, run {args.target} "
            f"--reps {args.reps} --iters {args.iters}, and write {args.summary}"
        )
        return 0
    source, binary = load_checked_build_artifacts(build_manifest, label="cycle-counter")

    run_root = args.run_root
    transfer_log = run_root / "transfer.log"
    run_log = run_root / "uart.log"
    run_root.mkdir(parents=True, exist_ok=True)
    transfer_binary(ROOT, port=args.port, baud=args.baud, binary=binary, target=args.target, transfer_log=transfer_log)
    board_command = (
        f"echo RVMT_CYCLE_SMOKE_SHELL_READY; "
        f"{args.target} --reps {args.reps} --iters {args.iters}; "
        "rc=$?; echo RVMT_CYCLE_SMOKE_RC=$rc"
    )
    capture_board_command(ROOT, port=args.port, baud=args.baud, run_log=run_log, board_command=board_command, post_read="8.0")
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
    return report_summary_exit(summary, args.summary, pass_message=f"[PASS] parsed {summary['row_count']} rdcycle rows")


if __name__ == "__main__":
    raise SystemExit(main())
