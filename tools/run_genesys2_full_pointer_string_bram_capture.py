from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from package_genesys2_hardware_pointer_strings import DEFAULT_RUN_ROOT, REQUIRED_REPS_PER_SAMPLE, REQUIRED_SAMPLES


def run(args: argparse.Namespace) -> int:
    capture_cmd = [
        sys.executable,
        "tools/run_genesys2_pointer_snapshot_bram_capture.py",
        "--root",
        str(args.root),
        "--run-root",
        str(args.run_root),
        "--runtime-root",
        args.runtime_root,
        "--repetitions",
        str(args.repetitions),
        "--ltx",
        str(args.ltx),
        "--hw-server-url",
        args.hw_server_url,
        "--port",
        args.port,
        "--baud",
        str(args.baud),
        "--timeout-seconds",
        str(args.timeout_seconds),
        "--post-read",
        str(args.post_read),
        "--arm-timeout",
        str(args.arm_timeout),
        "--process-wait-timeout",
        str(args.process_wait_timeout),
    ]
    for sample_id in args.sample or REQUIRED_SAMPLES:
        capture_cmd.extend(["--sample", sample_id])
    if args.force:
        capture_cmd.append("--force")
    if args.dry_run:
        capture_cmd.append("--dry-run")
    print("[RUN] " + " ".join(capture_cmd), flush=True)
    result = subprocess.run(capture_cmd, cwd=args.root)
    if result.returncode != 0 or args.dry_run:
        return result.returncode
    package_cmd = [
        sys.executable,
        "tools/package_genesys2_hardware_pointer_strings.py",
        "--root",
        str(args.root),
        "--run-root",
        str(args.run_root),
        "--resource-timing-report",
        str(args.resource_timing_report),
    ]
    print("[RUN] " + " ".join(package_cmd), flush=True)
    result = subprocess.run(package_cmd, cwd=args.root)
    if result.returncode != 0:
        return result.returncode
    check_cmd = [sys.executable, "tools/check_genesys2_hardware_pointer_strings.py", "--root", str(args.root)]
    print("[RUN] " + " ".join(check_cmd), flush=True)
    return subprocess.run(check_cmd, cwd=args.root).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the formal Genesys2 v3 full hardware pointer-string BRAM capture package.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--runtime-root", default="/tmp/rvmt_p2")
    parser.add_argument("--resource-timing-report", type=Path, required=True)
    parser.add_argument("--sample", action="append", choices=REQUIRED_SAMPLES)
    parser.add_argument("--repetitions", type=int, default=REQUIRED_REPS_PER_SAMPLE)
    parser.add_argument("--ltx", type=Path, default=Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx"))
    parser.add_argument("--hw-server-url", default="localhost:3121")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--post-read", type=float, default=360.0)
    parser.add_argument("--arm-timeout", type=float, default=45.0)
    parser.add_argument("--process-wait-timeout", type=float, default=360.0)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    args.root = args.root.resolve()
    if args.repetitions < REQUIRED_REPS_PER_SAMPLE:
        parser.error(f"--repetitions must be >= {REQUIRED_REPS_PER_SAMPLE} for formal evidence")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
