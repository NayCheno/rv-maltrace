from __future__ import annotations

import argparse
import base64
import subprocess
import sys
from pathlib import Path

from check_genesys2_sdcard_linux_manifest import DEFAULT_LOG, DEFAULT_SUMMARY, PASS_STATUS, summarize_manifest


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUN_ROOT = DEFAULT_LOG.parent


def section(name: str, command: str) -> str:
    return f"echo RVMT_SECTION_BEGIN {name}; {command}; echo RVMT_SECTION_END {name}"


MANIFEST_COMMANDS = [
    "echo RVMT_SDCARD_MANIFEST_BEGIN",
    section("uname_a", "uname -a 2>&1 || true"),
    section("uname_r", "uname -r 2>&1 || true"),
    section("id", "id 2>&1 || true"),
    section("proc_cmdline", "cat /proc/cmdline 2>&1 || true"),
    section("proc_version", "cat /proc/version 2>&1 || true"),
    section("etc_os_release", "cat /etc/os-release 2>&1 || echo RVMT_FILE_MISSING /etc/os-release"),
    section("proc_cpuinfo", "cat /proc/cpuinfo 2>&1 || true"),
    section("proc_mounts", "cat /proc/mounts 2>&1 || true"),
    section("proc_partitions", "cat /proc/partitions 2>&1 || true"),
    section(
        "block_inventory",
        "cat /proc/partitions 2>&1 || true; "
        "df -T 2>&1 || true; "
        "mount 2>&1 || true; "
        "ls -l /dev/mmc* /dev/sd* 2>&1 || true; "
        "for d in /sys/block/*; do "
        "b=$(basename \"$d\"); echo RVMT_BLOCK_DEVICE $b; "
        "if [ -e \"$d/size\" ]; then echo RVMT_BLOCK_SIZE_SECTORS $b $(cat \"$d/size\"); fi; "
        "if [ -e \"$d/removable\" ]; then echo RVMT_BLOCK_REMOVABLE $b $(cat \"$d/removable\"); fi; "
        "if [ -e \"$d/device/model\" ]; then echo RVMT_BLOCK_MODEL $b $(cat \"$d/device/model\"); fi; "
        "done",
    ),
    section(
        "rootfs_identity_hashes",
        "for f in /bin/busybox /sbin/init /init /linuxrc /etc/inittab /etc/os-release /etc/buildroot-release; do "
        "if [ -e \"$f\" ]; then sha256sum \"$f\" 2>/dev/null || echo RVMT_HASH_UNAVAILABLE $f; "
        "else echo RVMT_FILE_MISSING $f; fi; done",
    ),
    section(
        "boot_file_hashes",
        "if [ -d /boot ]; then "
        "find /boot -maxdepth 2 -type f 2>/dev/null | sort | while read f; do "
        "sha256sum \"$f\" 2>/dev/null || echo RVMT_HASH_UNAVAILABLE $f; done; "
        "else echo RVMT_BOOT_DIR_MISSING /boot; fi",
    ),
    section(
        "dtb_identity_hashes",
        "if [ -d /proc/device-tree ]; then "
        "for f in /proc/device-tree/compatible /proc/device-tree/model /proc/device-tree/cpus/cpu@0/riscv,isa "
        "/proc/device-tree/cpus/timebase-frequency; do "
        "if [ -e \"$f\" ]; then "
        "h=$(sha256sum \"$f\" 2>/dev/null | awk '{print $1}'); "
        "s=$(wc -c < \"$f\" 2>/dev/null); "
        "if [ -n \"$h\" ]; then echo RVMT_DTB_FILE $h $s $f; else echo RVMT_DTB_HASH_UNAVAILABLE $f; fi; "
        "else echo RVMT_DTB_FILE_MISSING $f; fi; done; "
        "find /proc/device-tree -maxdepth 4 ! -type d 2>/dev/null | sort | while read f; do "
        "case \"$f\" in /proc/device-tree/compatible|/proc/device-tree/model|/proc/device-tree/cpus/cpu@0/riscv,isa|/proc/device-tree/cpus/timebase-frequency) continue ;; esac; "
        "h=$(sha256sum \"$f\" 2>/dev/null | awk '{print $1}'); "
        "s=$(wc -c < \"$f\" 2>/dev/null); "
        "if [ -n \"$h\" ]; then echo RVMT_DTB_FILE $h $s $f; fi; "
        "done; "
        "else echo RVMT_DTB_DIR_MISSING /proc/device-tree; fi",
    ),
    section(
        "dtb_readable_identity",
        "for f in /proc/device-tree/compatible /proc/device-tree/model /proc/device-tree/cpus/cpu@0/riscv,isa "
        "/proc/device-tree/cpus/timebase-frequency; do "
        "if [ -e \"$f\" ]; then echo RVMT_DTB_VALUE_FILE $f; tr '\\000' '\\n' < \"$f\" 2>/dev/null | sed 's/^/RVMT_DTB_VALUE /'; "
        "else echo RVMT_DTB_VALUE_MISSING $f; fi; done",
    ),
    section(
        "kernel_config_probe",
        "for p in /proc/config.gz /boot/config-$(uname -r) /lib/modules/$(uname -r)/build/.config; do "
        "if [ -e \"$p\" ]; then echo RVMT_KERNEL_CONFIG_PATH $p; sha256sum \"$p\" 2>/dev/null || true; "
        "if echo \"$p\" | grep -q '\\.gz$'; then zcat \"$p\"; else cat \"$p\"; fi 2>/dev/null | "
        "grep -E '^(# )?CONFIG_(PERF|HW_PERF|HAVE_PERF|GENERIC_PERF|RISCV.*PMU|RISCV_PMU|PMU|IKCONFIG|KALLSYMS)' || true; "
        "else echo RVMT_KERNEL_CONFIG_MISSING $p; fi; done",
    ),
    section(
        "sbi_pmu_dmesg_probe",
        "dmesg 2>&1 | grep -Ei 'sbi|pmu|perf|counter|riscv' | tail -80 || true",
    ),
    "echo RVMT_SDCARD_MANIFEST_DONE",
]


def run(command: list[str], *, cwd: Path, dry_run: bool, allowed_returncodes: set[int] | None = None) -> None:
    print("+ " + " ".join(command))
    if dry_run:
        return
    completed = subprocess.run(command, cwd=cwd)
    allowed = allowed_returncodes or {0}
    if completed.returncode not in allowed:
        raise subprocess.CalledProcessError(completed.returncode, command)


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture a live Genesys2/CVA6 SD-card Linux identity manifest over UART.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--skip-capture", action="store_true", help="Summarize/check an existing UART log without touching the board.")
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
            "2.0",
            "--post-read",
            "10.0",
            "--send-delay",
            "0.1",
        ]
        for command in MANIFEST_COMMANDS:
            capture_cmd.extend(["--command-b64", base64.b64encode(command.encode("utf-8")).decode("ascii")])
        run(capture_cmd, cwd=ROOT, dry_run=args.dry_run)
    if args.dry_run:
        print(f"[DRY-RUN] would summarize {log} to {args.summary}")
        return 0
    if not log.is_file():
        raise FileNotFoundError(f"SD-card Linux manifest UART log missing: {log}")
    summary = args.summary if args.summary.is_absolute() else ROOT / args.summary
    data = summarize_manifest(ROOT, log, summary)
    print(f"[{data['status']}] wrote {summary}")
    return 0 if data.get("status") == PASS_STATUS else 2


if __name__ == "__main__":
    raise SystemExit(main())
