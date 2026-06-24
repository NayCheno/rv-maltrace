from __future__ import annotations

import argparse
import base64
import subprocess
import sys
from pathlib import Path

from check_genesys2_live_kernel_config_export import (
    DEFAULT_CONFIG,
    DEFAULT_LOG,
    DEFAULT_SUMMARY,
    summarize_export,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUN_ROOT = DEFAULT_LOG.parent


EXPORT_COMMAND = (
    "echo RVMT_LIVE_KERNEL_CONFIG_EXPORT_BEGIN; "
    "id 2>&1 || true; "
    "uname -a 2>&1 || true; "
    "rm -f /tmp/rvmt_live_kernel_config.txt; "
    "found=0; "
    "for p in /proc/config.gz /boot/config-$(uname -r) /lib/modules/$(uname -r)/build/.config; do "
    "if [ -e \"$p\" ] && [ \"$found\" = 0 ]; then "
    "echo RVMT_KERNEL_CONFIG_FOUND $p; "
    "if echo \"$p\" | grep -q '\\.gz$'; then zcat \"$p\" > /tmp/rvmt_live_kernel_config.txt 2>/dev/null; "
    "else cat \"$p\" > /tmp/rvmt_live_kernel_config.txt 2>/dev/null; fi; "
    "echo RVMT_KERNEL_CONFIG_CONTENT_BEGIN $p; "
    "cat /tmp/rvmt_live_kernel_config.txt 2>/dev/null || true; "
    "echo RVMT_KERNEL_CONFIG_CONTENT_END $p; "
    "sha256sum /tmp/rvmt_live_kernel_config.txt 2>/dev/null | sed 's/^/RVMT_KERNEL_CONFIG_TEXT_SHA256 /' || true; "
    "found=1; "
    "else echo RVMT_KERNEL_CONFIG_MISSING $p; fi; "
    "done; "
    "ls -la /sys/bus/event_source/devices 2>&1 || true; "
    "dmesg 2>&1 | grep -Ei 'SBI|PMU|perf|counter' | tail -40 || true; "
    "echo RVMT_LIVE_KERNEL_CONFIG_EXPORT_DONE"
)


def run(command: list[str], *, cwd: Path, dry_run: bool) -> None:
    print("+ " + " ".join(command))
    if dry_run:
        return
    subprocess.run(command, cwd=cwd, check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export live Genesys2/CVA6 Linux kernel config over UART when available.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--live-config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--skip-capture", action="store_true", help="Summarize an existing UART log without touching the board.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    log = args.run_root / "uart.log"
    if not args.skip_capture:
        capture_cmd = [
            sys.executable,
            "tools/serial_direct_command_capture.py",
            "--port",
            args.port,
            "--baud",
            str(args.baud),
            "--out",
            str(log),
            "--pre-read",
            "0.2",
            "--between-read",
            "0.5",
            "--post-read",
            "8.0",
            "--command-b64",
            base64.b64encode(EXPORT_COMMAND.encode("utf-8")).decode("ascii"),
        ]
        run(capture_cmd, cwd=ROOT, dry_run=args.dry_run)
    if args.dry_run:
        print(f"[DRY-RUN] would summarize {log} to {args.summary}")
        return 0
    if not log.is_file():
        raise FileNotFoundError(f"live kernel config UART log missing: {log}")
    summary = args.summary if args.summary.is_absolute() else ROOT / args.summary
    live_config = args.live_config if args.live_config.is_absolute() else ROOT / args.live_config
    data = summarize_export(ROOT, log, summary, live_config)
    print(f"[{data['status']}] wrote {summary}")
    if str(data["status"]).startswith("BLOCKED_"):
        print(f"[{data['status']}] {data.get('blocked_reason')}")
        return 2
    return 0 if data["status"] == "PASS_LIVE_KERNEL_CONFIG_EXPORTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
