from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


SAMPLES = [
    "file_scan",
    "batch_open_read_write",
    "self_copy_sim",
    "abnormal_syscall_sequence",
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
    "anti_debug_like",
]

DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait")
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx")
END_MARKER = "e0000a11"


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def rep_is_pass(rep_dir: Path) -> bool:
    summary = rep_dir / "bram_summary.json"
    records = rep_dir / "bram_records.jsonl"
    if not summary.is_file() or not records.is_file():
        return False
    try:
        data = load_json(summary)
    except Exception:
        return False
    bram = data.get("bram_ring", {}) if isinstance(data.get("bram_ring"), dict) else {}
    return (
        data.get("status") == "PASS"
        and int(bram.get("event_count", 0) or 0) > 0
        and int(bram.get("dropped_count", 0) or 0) == 0
        and int(bram.get("wrap_count", 0) or 0) == 0
    )


def program_command(sample_id: str, rep_name: str, runtime_root: str) -> str:
    runtime_path = f"{runtime_root.rstrip('/')}/{sample_id}"
    return (
        f"printf 'RVMT_P2_BUSY_BRAM_START sample={sample_id} rep={rep_name}\\n'; "
        f"{runtime_path}; "
        "rc=$?; "
        f"printf 'RVMT_P2_BUSY_BRAM_DONE sample={sample_id} rep={rep_name} rc=%s\\n' \"$rc\""
    )


def capture_command(args: argparse.Namespace, sample_id: str, rep: int) -> list[str]:
    rep_name = f"rep_{rep:02d}"
    rep_dir = args.run_root / sample_id / rep_name
    command = program_command(sample_id, rep_name, args.runtime_root)
    return [
        sys.executable,
        "tools/run_genesys2_ila_command_capture.py",
        "--root",
        ".",
        "--evt-hex",
        "c",
        "--primary",
        END_MARKER,
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
        command,
        "--port",
        args.port,
        "--baud",
        str(args.baud),
        "--pre-read",
        str(args.pre_read),
        "--post-read",
        str(args.post_read),
        "--arm-timeout",
        str(args.arm_timeout),
        "--process-wait-timeout",
        str(args.process_wait_timeout),
        "--bram-out-jsonl",
        str(rep_dir / "bram_records.jsonl"),
        "--bram-summary",
        str(rep_dir / "bram_summary.json"),
        "--bram-trigger-primary",
        END_MARKER,
        "--sample-id",
        sample_id,
    ]


def package_command(args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        "tools/package_genesys2_safe_surrogate_bram_trace.py",
        "--run-root",
        str(args.run_root),
        "--minimum-repetitions",
        str(args.repetitions),
    ]


def run(args: argparse.Namespace) -> int:
    selected = args.sample or SAMPLES
    unknown = [sample for sample in selected if sample not in SAMPLES]
    if unknown:
        print(f"unknown sample(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    args.run_root.mkdir(parents=True, exist_ok=True)
    for sample_id in selected:
        for rep in range(1, args.repetitions + 1):
            rep_name = f"rep_{rep:02d}"
            rep_dir = args.run_root / sample_id / rep_name
            if rep_is_pass(rep_dir) and not args.force:
                print(f"[SKIP] {sample_id}/{rep_name}: existing PASS BRAM repetition")
                continue
            rep_dir.mkdir(parents=True, exist_ok=True)
            command = capture_command(args, sample_id, rep)
            print(f"[RUN] {sample_id}/{rep_name}: {' '.join(command)}", flush=True)
            if args.dry_run:
                continue
            result = subprocess.run(command, cwd=args.root)
            if result.returncode != 0:
                print(f"[FAIL] {sample_id}/{rep_name}: capture exited {result.returncode}", file=sys.stderr)
                return result.returncode
    if args.dry_run:
        print("[PASS] dry run complete")
        return 0
    command = package_command(args)
    print(f"[RUN] package safe-surrogate BRAM summary: {' '.join(command)}", flush=True)
    result = subprocess.run(command, cwd=args.root)
    if result.returncode != 0:
        return result.returncode
    print("[PASS] safe-surrogate BRAM repetitions complete")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture repeated safe-surrogate BRAM marker windows on Genesys2/CVA6.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--runtime-root", default="/tmp/rvmt_p2")
    parser.add_argument("--sample", action="append", choices=SAMPLES)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--hw-server-url", default="localhost:3121")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--pre-read", type=float, default=0.1)
    parser.add_argument("--post-read", type=float, default=6.0)
    parser.add_argument("--arm-timeout", type=float, default=45.0)
    parser.add_argument("--process-wait-timeout", type=float, default=360.0)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    args.root = args.root.resolve()
    if args.repetitions < 1:
        parser.error("--repetitions must be >= 1")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
