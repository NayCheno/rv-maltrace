from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUILD_MANIFEST = Path("build/board/genesys2_official_image_probe/build_manifest.json")
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260625-official-image-workloads")
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/official_image_workload_summary.json")
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker-syscall/work-fpga/ariane_xilinx.ltx")
DEFAULT_TARGET = "/tmp/rvmt_official/official_image_probe"


SAMPLES: dict[str, dict[str, Any]] = {
    "native_sh": {"marker": 0x0000B01, "argv": ["/bin/sh", "-c", "printf rvmt-native-sh\\n"]},
    "native_cat_proc": {"marker": 0x0000B02, "argv": ["/bin/busybox", "cat", "/proc/version"]},
    "native_ls_proc": {"marker": 0x0000B03, "argv": ["/bin/busybox", "ls", "/proc"]},
    "native_dd_tmp": {"marker": 0x0000B04, "argv": ["/bin/busybox", "dd", "if=/dev/zero", "of=/tmp/rvmt-dd.bin", "bs=4096", "count=16"]},
    "native_grep": {"marker": 0x0000B05, "argv": ["/bin/busybox", "grep", "Linux", "/proc/version"]},
    "native_sha256sum": {"marker": 0x0000B06, "argv": ["/bin/busybox", "sha256sum", "/bin/busybox"]},
    "native_mount_read": {"marker": 0x0000B07, "argv": ["/bin/busybox", "cat", "/proc/mounts"]},
    "native_file_rw": {
        "marker": 0x0000B08,
        "argv": ["/bin/sh", "-c", "printf rvmt-file-rw >/tmp/rvmt-file-rw.txt; cat /tmp/rvmt-file-rw.txt; sha256sum /tmp/rvmt-file-rw.txt; rm -f /tmp/rvmt-file-rw.txt"],
    },
}


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def marker_begin(marker: int) -> str:
    return f"b{marker:07x}"


def marker_end(marker: int) -> str:
    return f"e{marker:07x}"


def static_binary_from_manifest(path: Path) -> Path:
    row = load_json(path).get("variants", {}).get("static_exec", {})
    binary = Path(str(row.get("binary") or ""))
    if not binary.is_file():
        raise FileNotFoundError(f"static_exec binary missing in {path}: {binary}")
    return binary


def run(command: list[str], *, cwd: Path, dry_run: bool) -> None:
    print("+ " + " ".join(command), flush=True)
    if dry_run:
        return
    subprocess.run(command, cwd=cwd, check=True)


def run_allow_blocked_package(command: list[str], *, cwd: Path) -> None:
    print("+ " + " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=cwd)
    if completed.returncode not in {0, 1}:
        raise subprocess.CalledProcessError(completed.returncode, command)


def transfer_probe(args: argparse.Namespace, binary: Path) -> None:
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
            str(args.run_root / "launcher_transfer.log"),
            "--chunk-read",
            "0.25",
            "--final-read",
            "3.0",
            "--disable-echo",
        ],
        cwd=ROOT,
        dry_run=args.dry_run,
    )


def program_command(args: argparse.Namespace, sample_id: str, rep_name: str) -> str:
    sample = SAMPLES[sample_id]
    begin = "0x" + marker_begin(int(sample["marker"]))
    end = "0x" + marker_end(int(sample["marker"]))
    argv = " ".join(shell_quote(str(item)) for item in sample["argv"])
    return (
        f"rm -f /tmp/rvmt-dd.bin; "
        f"printf 'RVMT_OFFICIAL_WORKLOAD_CAPTURE_START sample={sample_id} rep={rep_name}\\n'; "
        f"{shell_quote(args.target)} workload {shell_quote(sample_id)} {shell_quote(begin)} {shell_quote(end)} {argv}; "
        "rc=$?; "
        f"printf 'RVMT_OFFICIAL_WORKLOAD_CAPTURE_%s sample={sample_id} rep={rep_name} rc=%s\\n' DONE \"$rc\""
    )


def capture_one(args: argparse.Namespace, sample_id: str, rep: int) -> None:
    sample = SAMPLES[sample_id]
    rep_name = f"rep_{rep:02d}"
    rep_dir = args.run_root / sample_id / rep_name
    rep_dir.mkdir(parents=True, exist_ok=True)
    end = marker_end(int(sample["marker"]))
    command = [
            sys.executable,
            "tools/run_genesys2_ila_command_capture.py",
            "--root",
            ".",
            "--evt-hex",
            "c",
            "--primary",
            end,
            "--csv",
            str(rep_dir / "capture.csv"),
            "--timeout-seconds",
            str(args.timeout_seconds),
            "--trigger-position",
            "0",
            "--ltx",
            str(args.ltx),
            "--hw-server-url",
            args.hw_server_url,
            "--capture-log",
            str(rep_dir / "capture.log"),
            "--capture-err",
            str(rep_dir / "capture.err.log"),
            "--program-log",
            str(rep_dir / "uart.log"),
            "--program-command",
            program_command(args, sample_id, rep_name),
            "--port",
            args.port,
            "--baud",
            str(args.baud),
            "--pre-read",
            str(args.pre_read),
            "--post-read",
            str(args.post_read),
            "--post-read-until",
            f"RVMT_OFFICIAL_WORKLOAD_CAPTURE_DONE sample={sample_id} rep={rep_name}",
            "--post-read-loose-required",
            "rc=0",
            "--arm-timeout",
            str(args.arm_timeout),
            "--process-wait-timeout",
            str(args.process_wait_timeout),
            "--bram-out-jsonl",
            str(rep_dir / "bram_records.jsonl"),
            "--bram-summary",
            str(rep_dir / "bram_summary.json"),
            "--bram-trigger-primary",
            end,
            "--sample-id",
            sample_id,
    ]
    if not args.no_event_only_capture:
        command.insert(command.index("--ltx"), "--event-only-capture")
    run(command, cwd=ROOT, dry_run=args.dry_run)


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture official CVA6 image BusyBox/shell workloads on Genesys2.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--build-manifest", type=Path, default=DEFAULT_BUILD_MANIFEST)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--sample", action="append", choices=list(SAMPLES))
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--start-repetition", type=int, default=1)
    parser.add_argument("--minimum-repetitions", type=int, default=1)
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--hw-server-url", default="localhost:3121")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--pre-read", type=float, default=0.2)
    parser.add_argument("--post-read", type=float, default=8.0)
    parser.add_argument("--arm-timeout", type=float, default=60.0)
    parser.add_argument("--process-wait-timeout", type=float, default=240.0)
    parser.add_argument(
        "--no-event-only-capture",
        action="store_true",
        help="Use a normal ILA capture window. This avoids Vivado readback failures seen with BASIC event-only capture on some runs.",
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-transfer", action="store_true")
    parser.add_argument("--skip-capture", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.repetitions < args.start_repetition:
        parser.error("--repetitions must be >= --start-repetition")
    args.run_root.mkdir(parents=True, exist_ok=True)
    if not args.skip_build:
        run([sys.executable, "tools/build_genesys2_official_image_probe.py"], cwd=ROOT, dry_run=args.dry_run)
    binary = static_binary_from_manifest(args.build_manifest)
    if not args.skip_transfer:
        transfer_probe(args, binary)
    selected = args.sample or list(SAMPLES)
    if not args.skip_capture:
        for sample_id in selected:
            for rep in range(args.start_repetition, args.repetitions + 1):
                capture_one(args, sample_id, rep)
    if args.dry_run:
        return 0
    run_allow_blocked_package(
        [
            sys.executable,
            "tools/package_genesys2_official_image_workloads.py",
            "--run-root",
            str(args.run_root),
            "--minimum-repetitions",
            str(args.minimum_repetitions),
            "--out",
            str(args.summary),
        ],
        cwd=ROOT,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
