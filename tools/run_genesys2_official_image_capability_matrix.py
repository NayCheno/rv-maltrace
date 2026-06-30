from __future__ import annotations

import argparse
import base64
import subprocess
import sys
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
)

from check_genesys2_official_image_capability_matrix import package_summary, write_json


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUILD_MANIFEST = Path("build/board/genesys2_official_image_probe/build_manifest.json")
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260625-official-image-capability-matrix")
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/official_image_capability_matrix.json")
DEFAULT_TARGET = "/tmp/rvmt_official/official_image_probe"


SHELL_COMMANDS = [
    "echo RVMT_CAPABILITY_BEGIN",
    "uname -a 2>&1 || true",
    "id 2>&1 || true",
    "busybox --list 2>&1 || true",
    (
        "for x in sh busybox cat ls dd find grep sha256sum base64 strace perf bpftool readelf objdump file ldd devmem; do "
        "if command -v \"$x\" >/dev/null 2>&1; then echo RVMT_TOOL_PRESENT $x $(command -v \"$x\"); "
        "else echo RVMT_TOOL_MISSING $x; fi; done"
    ),
    (
        "for p in /proc/config.gz /proc/modules /proc/sys/kernel/perf_event_paranoid "
        "/proc/sys/kernel/randomize_va_space /sys/kernel/debug /sys/kernel/tracing /sys/fs/bpf "
        "/sys/bus/event_source/devices /lib/modules/$(uname -r); do "
        "if [ -e \"$p\" ]; then echo RVMT_PATH_PRESENT $p; ls -ld \"$p\" 2>&1; "
        "else echo RVMT_PATH_MISSING $p; fi; done"
    ),
    "mount 2>&1 || true",
    "cat /proc/modules 2>&1 || true",
    "cat /proc/sys/kernel/randomize_va_space 2>&1 || true",
    "dmesg 2>&1 | grep -Ei 'sbi|pmu|perf|bpf|debugfs|trace|counter|riscv' | tail -120 || true",
    "echo RVMT_CAPABILITY_DONE",
]


def run(command: list[str], *, cwd: Path, dry_run: bool, allowed: set[int] | None = None) -> None:
    print("+ " + " ".join(command))
    if dry_run:
        return
    result = subprocess.run(command, cwd=cwd)
    if result.returncode not in (allowed or {0}):
        raise subprocess.CalledProcessError(result.returncode, command)


def static_binary_from_manifest(path: Path) -> Path:
    manifest = load_json(path)
    row = manifest.get("variants", {}).get("static_exec", {})
    binary = Path(str(row.get("binary") or ""))
    if not binary.is_file():
        raise FileNotFoundError(f"static_exec binary missing in {path}: {binary}")
    return binary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the official CVA6 SD-image capability matrix on Genesys2.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--build-manifest", type=Path, default=DEFAULT_BUILD_MANIFEST)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-transfer", action="store_true")
    parser.add_argument("--skip-capture", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.skip_build:
        run([sys.executable, "tools/build_genesys2_official_image_probe.py"], cwd=ROOT, dry_run=args.dry_run)
    binary = static_binary_from_manifest(args.build_manifest)
    args.run_root.mkdir(parents=True, exist_ok=True)
    transfer_log = args.run_root / "capability_probe_transfer.log"
    shell_log = args.run_root / "capability_shell.log"
    probe_log = args.run_root / "capability_probe_uart.log"
    if not args.skip_transfer:
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
            dry_run=args.dry_run,
        )
    if not args.skip_capture:
        shell_capture = [
            sys.executable,
            "tools/serial_direct_command_capture.py",
            "--port",
            args.port,
            "--baud",
            str(args.baud),
            "--out",
            str(shell_log),
            "--pre-read",
            "0.2",
            "--between-read",
            "1.0",
            "--post-read",
            "8.0",
        ]
        for command in SHELL_COMMANDS:
            shell_capture.extend(["--command-b64", base64.b64encode(command.encode("utf-8")).decode("ascii")])
        run(shell_capture, cwd=ROOT, dry_run=args.dry_run)
        run(
            [
                sys.executable,
                "tools/serial_direct_command_capture.py",
                "--port",
                args.port,
                "--baud",
                str(args.baud),
                "--out",
                str(probe_log),
                "--pre-read",
                "0.2",
                "--post-read",
                "8.0",
                f"{args.target} capability; rc=$?; echo RVMT_CAPABILITY_PROBE_RC=$rc",
            ],
            cwd=ROOT,
            dry_run=args.dry_run,
        )
    if args.dry_run:
        return 0
    summary = package_summary(
        root=ROOT,
        run_root=args.run_root,
        build_manifest=args.build_manifest,
        transfer_log=transfer_log,
        shell_log=shell_log,
        probe_log=probe_log,
        target=args.target,
    )
    write_json(args.summary, summary)
    print(f"[{summary['status']}] wrote {args.summary}")
    return 0 if summary["status"] == "PASS" or str(summary["status"]).startswith("BLOCKED_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
