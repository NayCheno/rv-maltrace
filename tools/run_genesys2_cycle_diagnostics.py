from __future__ import annotations

import argparse
import base64
import subprocess
import sys
from pathlib import Path

from check_genesys2_cycle_diagnostics import DEFAULT_LOG, DEFAULT_SUMMARY, summarize_diagnostics


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260623-cycle-source-diagnostics")

DIAGNOSTIC_COMMANDS = [
    "echo RVMT_CYCLE_DIAG_BEGIN",
    "uname -a",
    "id",
    "echo RVMT_CPUINFO_BEGIN",
    "cat /proc/cpuinfo",
    "echo RVMT_PERF_PARANOID_BEGIN",
    "cat /proc/sys/kernel/perf_event_paranoid 2>&1 || true",
    "echo RVMT_KERNEL_CONFIG_SCAN_BEGIN",
    "for p in /proc/config.gz /boot/config-$(uname -r) /lib/modules/$(uname -r)/build/.config; do "
    "if [ -e \"$p\" ]; then "
    "echo RVMT_KERNEL_CONFIG_PATH $p; "
    "if echo \"$p\" | grep -q '\\.gz$'; then zcat \"$p\"; else cat \"$p\"; fi | "
    "grep -E '^(# )?CONFIG_(PERF|HW_PERF|HAVE_PERF|GENERIC_PERF|RISCV.*PMU|RISCV_PMU|PMU|DEBUG_INFO|KALLSYMS)' || true; "
    "else echo RVMT_KERNEL_CONFIG_MISSING $p; fi; done",
    "echo RVMT_EVENT_SOURCES_BEGIN",
    "ls -la /sys/bus/event_source/devices 2>&1 || true",
    "for d in /sys/bus/event_source/devices/*; do echo RVMT_EVENT_SOURCE $d; cat $d/type 2>/dev/null; done",
    "echo RVMT_DEVICE_TREE_COUNTER_BEGIN",
    "for f in /proc/device-tree/compatible /proc/device-tree/cpus/cpu@0/riscv,isa /proc/device-tree/cpus/cpu@0/compatible /proc/device-tree/cpus/timebase-frequency; do "
    "if [ -e \"$f\" ]; then echo RVMT_DTB_FILE $f; tr '\\000' '\\n' < \"$f\" | sed 's/^/RVMT_DTB_VALUE /'; "
    "else echo RVMT_DTB_MISSING $f; fi; done",
    "echo RVMT_DEVICE_TREE_PMU_BEGIN",
    "find /proc/device-tree -maxdepth 4 -iname '*pmu*' -print 2>/dev/null | sed 's/^/RVMT_DTB_PMU_PATH /' || true",
    "find /proc/device-tree -maxdepth 4 -iname '*perf*' -print 2>/dev/null | sed 's/^/RVMT_DTB_PERF_PATH /' || true",
    "for f in /proc/device-tree/pmu/compatible /proc/device-tree/soc/pmu/compatible /proc/device-tree/soc/pmu@0/compatible; do "
    "if [ -e \"$f\" ]; then echo RVMT_DTB_PMU_FILE $f; tr '\\000' '\\n' < \"$f\" | sed 's/^/RVMT_DTB_PMU_VALUE /'; "
    "else echo RVMT_DTB_PMU_MISSING $f; fi; done",
    "echo RVMT_MODULE_SCAN_BEGIN",
    "if [ -d /lib/modules/$(uname -r) ]; then echo RVMT_MODULE_DIR /lib/modules/$(uname -r); "
    "find /lib/modules/$(uname -r) -maxdepth 4 -type f 2>/dev/null | grep -Ei 'perf|pmu|riscv|counter' | sed 's/^/RVMT_MODULE_PATH /' || true; "
    "else echo RVMT_MODULE_DIR_MISSING /lib/modules/$(uname -r); fi",
    "echo RVMT_DTB_CPU_FILES_BEGIN",
    "find /proc/device-tree/cpus -maxdepth 3 -type f 2>/dev/null | sort | head -80",
    "echo RVMT_DMESG_SBI_BEGIN",
    "dmesg 2>&1 | grep -i sbi | tail -40 || true",
    "echo RVMT_DMESG_PMU_BEGIN",
    "dmesg 2>&1 | grep -i pmu | tail -40 || true",
    "echo RVMT_DMESG_PERF_BEGIN",
    "dmesg 2>&1 | grep -i perf | tail -40 || true",
    "echo RVMT_DMESG_COUNTER_BEGIN",
    "dmesg 2>&1 | grep -i counter | tail -40 || true",
    "echo RVMT_DMESG_RISCV_BEGIN",
    "dmesg 2>&1 | grep -i riscv | tail -40 || true",
    "echo RVMT_CYCLE_DIAG_DONE",
]


def run(command: list[str], *, cwd: Path, dry_run: bool) -> None:
    print("+ " + " ".join(command))
    if dry_run:
        return
    subprocess.run(command, cwd=cwd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture Genesys2/CVA6 Linux cycle-source diagnostics over UART.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--skip-capture", action="store_true", help="Package/check an existing UART log without touching the board.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

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
            "30.0",
            "--post-read",
            "30.0",
            "--send-char-delay",
            "0.004",
            "--read-until-prompt",
        ]
        for command in DIAGNOSTIC_COMMANDS:
            capture_cmd.extend(["--command-b64", base64.b64encode(command.encode("utf-8")).decode("ascii")])
        run(capture_cmd, cwd=ROOT, dry_run=args.dry_run)
    if args.dry_run:
        print(f"[DRY-RUN] would summarize {log} to {args.summary}")
        return 0
    if not log.is_file():
        raise FileNotFoundError(f"cycle diagnostics UART log missing: {log}")
    summary = args.summary if args.summary.is_absolute() else ROOT / args.summary
    data = summarize_diagnostics(ROOT, log, summary)
    print(f"[{data['status']}] wrote {summary}")
    if str(data["status"]).startswith("BLOCKED_"):
        print(f"[{data['status']}] {data.get('blocked_reason')}")
        return 2
    return 0 if data["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
