from __future__ import annotations

import argparse
import json
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, TextIO


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260612-production-runtime-benchmark")
DEFAULT_OUT = Path("results/evaluation/genesys2-cva6/current/production_runtime_benchmark.json")
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx")
END_MARKER = "e0000a11"

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

MODES = [
    "trace_off",
    "event_only",
    "bram_ring",
    "pointer_snapshot_disabled",
]

START_RE = re.compile(r"RVMT_RUNTIME_BENCH_START\s+(.*)")
DONE_RE = re.compile(r"RVMT_RUNTIME_BENCH_DONE\s+(.*)")


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def parse_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in text.strip().replace("\r", "").split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    return fields


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def benchmark_shell_command(sample_id: str, mode: str, rep_name: str, runtime_root: str) -> str:
    runtime_path = f"{runtime_root.rstrip('/')}/{sample_id}"
    return f"""now_ns() {{
  ns=$(date +%s%N 2>/dev/null || true)
  case "$ns" in
    ""|*N*) s=$(date +%s 2>/dev/null || echo 0); printf '%s000000000\\n' "$s" ;;
    *) printf '%s\\n' "$ns" ;;
  esac
}}
sample_id={shell_quote(sample_id)}
mode={shell_quote(mode)}
rep={shell_quote(rep_name)}
runtime_path={shell_quote(runtime_path)}
start_ns=$(now_ns)
printf 'RVMT_RUNTIME_BENCH_START sample=%s mode=%s rep=%s ns=%s\\n' "$sample_id" "$mode" "$rep" "$start_ns"
"$runtime_path" >/tmp/rvmt_runtime_bench_stdout 2>/tmp/rvmt_runtime_bench_stderr
rc=$?
done_ns=$(now_ns)
printf 'RVMT_RUNTIME_BENCH_DONE sample=%s mode=%s rep=%s rc=%s ns=%s\\n' "$sample_id" "$mode" "$rep" "$rc" "$done_ns"
"""


def emit(handle: TextIO, text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()
    handle.write(text)
    handle.flush()


def read_until_done(ser, *, timeout_seconds: float, handle: TextIO, sample_id: str, mode: str, rep_name: str) -> str:
    deadline = time.time() + timeout_seconds
    chunks: list[str] = []
    done_token = f"RVMT_RUNTIME_BENCH_DONE sample={sample_id} mode={mode} rep={rep_name}"
    while time.time() < deadline:
        data = ser.read(4096)
        if not data:
            continue
        text = data.decode("utf-8", errors="replace")
        chunks.append(text)
        emit(handle, text)
        if done_token in "".join(chunks):
            return "".join(chunks)
    raise TimeoutError(f"timed out waiting for {done_token}")


def run_serial_command(
    *,
    port: str,
    baud: int,
    command: str,
    program_log: Path,
    pre_read: float,
    timeout_seconds: float,
    sample_id: str,
    mode: str,
    rep_name: str,
) -> None:
    try:
        import serial
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("pyserial is required for Genesys2 UART runtime benchmark") from exc

    program_log.parent.mkdir(parents=True, exist_ok=True)
    with serial.Serial(port, baud, timeout=0.1, write_timeout=5) as ser, program_log.open(
        "w", encoding="utf-8", newline="\n", errors="replace"
    ) as handle:
        handle.write(
            f"RVMT_GENESYS2_RUNTIME_BENCH_UART port={port} baud={baud} "
            f"sample={sample_id} mode={mode} rep={rep_name} start={now_iso()}\n"
        )
        handle.flush()
        deadline = time.time() + pre_read
        while time.time() < deadline:
            data = ser.read(4096)
            if data:
                emit(handle, data.decode("utf-8", errors="replace"))
        ser.write(command.encode("utf-8") + b"\r\n")
        ser.flush()
        emit(handle, f"\nRVMT_SEND_RUNTIME_BENCH sample={sample_id} mode={mode} rep={rep_name}\n")
        read_until_done(
            ser,
            timeout_seconds=timeout_seconds,
            handle=handle,
            sample_id=sample_id,
            mode=mode,
            rep_name=rep_name,
        )
        handle.write("\nRVMT_GENESYS2_RUNTIME_BENCH_UART_DONE\n")


def ila_capture_command(args: argparse.Namespace, sample_id: str, mode: str, rep: int, rep_dir: Path, command: str) -> list[str]:
    rep_name = f"rep_{rep:02d}"
    done_token = f"RVMT_RUNTIME_BENCH_DONE sample={sample_id} mode={mode} rep={rep_name}"
    cmd = [
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
        str(args.ila_timeout_seconds),
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
        str(args.process_wait_timeout),
        "--post-read-until",
        done_token,
        "--arm-timeout",
        str(args.arm_timeout),
        "--process-wait-timeout",
        str(args.process_wait_timeout),
    ]
    if mode == "event_only":
        cmd.append("--event-only-capture")
    if mode == "bram_ring":
        cmd.extend(
            [
                "--bram-out-jsonl",
                str(rep_dir / "bram_records.jsonl"),
                "--bram-summary",
                str(rep_dir / "bram_summary.json"),
                "--bram-trigger-primary",
                END_MARKER,
                "--sample-id",
                sample_id,
            ]
        )
    return cmd


def parse_program_log(path: Path) -> dict[str, Any]:
    starts: list[dict[str, str]] = []
    dones: list[dict[str, str]] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        start = START_RE.search(line)
        if start:
            fields = parse_fields(start.group(1))
            if str(fields.get("ns", "")).isdigit():
                starts.append(fields)
        done = DONE_RE.search(line)
        if done:
            fields = parse_fields(done.group(1))
            if str(fields.get("ns", "")).isdigit():
                dones.append(fields)
    if not starts or not dones:
        raise ValueError(f"{path}: missing runtime benchmark START/DONE markers")
    first = starts[0]
    last = dones[-1]
    start_ns = int(first.get("ns", "0"), 10)
    done_ns = int(last.get("ns", "0"), 10)
    return {
        "sample_id": last.get("sample") or first.get("sample"),
        "mode": last.get("mode") or first.get("mode"),
        "repetition_id": last.get("rep") or first.get("rep"),
        "rc": int(last.get("rc", "0"), 10),
        "start_ns": start_ns,
        "done_ns": done_ns,
        "duration_ns": max(done_ns - start_ns, 0),
        "program_log": repo_rel(path),
    }


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = (len(ordered) - 1) * pct
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = index - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def stats(values: list[int]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "median_ns": None, "p95_ns": None, "variance_ns2": None}
    return {
        "count": len(values),
        "median_ns": statistics.median(values),
        "p95_ns": percentile([float(value) for value in values], 0.95),
        "variance_ns2": statistics.pvariance(values) if len(values) > 1 else 0.0,
        "min_ns": min(values),
        "max_ns": max(values),
    }


def summarize(rows: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    by_sample_mode: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        by_sample_mode.setdefault((str(row["sample_id"]), str(row["mode"])), []).append(row)

    samples: list[dict[str, Any]] = []
    for sample_id in sorted({str(row["sample_id"]) for row in rows}):
        modes: dict[str, Any] = {}
        baseline_median = None
        baseline_p95 = None
        if (sample_id, "trace_off") in by_sample_mode:
            baseline_values = [int(row["duration_ns"]) for row in by_sample_mode[(sample_id, "trace_off")]]
            baseline = stats(baseline_values)
            baseline_median = baseline.get("median_ns")
            baseline_p95 = baseline.get("p95_ns")
        for mode in MODES:
            reps = by_sample_mode.get((sample_id, mode), [])
            values = [int(row["duration_ns"]) for row in reps]
            mode_stats = stats(values)
            median = mode_stats.get("median_ns")
            p95 = mode_stats.get("p95_ns")
            modes[mode] = {
                **mode_stats,
                "slowdown_vs_trace_off_median": (float(median) / float(baseline_median))
                if baseline_median and median is not None
                else None,
                "slowdown_vs_trace_off_p95": (float(p95) / float(baseline_p95))
                if baseline_p95 and p95 is not None
                else None,
                "repetitions": reps,
            }
        samples.append({"sample_id": sample_id, "modes": modes})

    all_mode_stats: dict[str, Any] = {}
    for mode in MODES:
        values = [int(row["duration_ns"]) for row in rows if row.get("mode") == mode]
        all_mode_stats[mode] = stats(values)

    status = "PASS" if rows and all(int(row.get("duration_ns", 0)) > 0 for row in rows) else "FAIL"
    return {
        "schema": "rvmt.genesys2.production_runtime_benchmark.v1",
        "status": status,
        "board": "Digilent Genesys2",
        "cpu": "CVA6 rv64gc sv39",
        "run_root": repo_rel(args.run_root),
        "runtime_root": args.runtime_root,
        "minimum_repetitions_per_mode_sample": args.repetitions,
        "modes": {
            "trace_off": "UART-only workload run; no ILA capture is armed for this benchmark mode.",
            "event_only": "ILA capture armed with event-only capture condition while workload runs.",
            "bram_ring": "BRAM ring capture/readout path armed around the workload marker window.",
            "pointer_snapshot_disabled": "Current production pointer snapshot setting disabled; workload run records disabled-mode overhead baseline.",
        },
        "metric": "wall_clock_ns_from_board_uart_date_markers",
        "mode_stats": all_mode_stats,
        "samples": samples,
        "raw_repetitions": rows,
        "non_claims": [
            "Wall-clock UART markers include shell scheduling and serial-observation noise; use medians/p95 over repetitions.",
            "The pointer_snapshot_disabled mode is a disabled-mode overhead measurement, not hardware pointer-payload capture evidence.",
        ],
    }


def run(args: argparse.Namespace) -> int:
    selected_samples = args.sample or SAMPLES
    selected_modes = args.mode or MODES
    rows: list[dict[str, Any]] = []
    args.run_root.mkdir(parents=True, exist_ok=True)
    for sample_id in selected_samples:
        for mode in selected_modes:
            for rep in range(1, args.repetitions + 1):
                rep_name = f"rep_{rep:02d}"
                rep_dir = args.run_root / sample_id / mode / rep_name
                program_log = rep_dir / "uart.log"
                if program_log.is_file() and not args.force:
                    try:
                        row = parse_program_log(program_log)
                        if int(row.get("duration_ns", 0)) > 0:
                            print(f"[SKIP] {sample_id}/{mode}/{rep_name}: existing benchmark repetition")
                            rows.append(row)
                            continue
                    except Exception:
                        pass
                rep_dir.mkdir(parents=True, exist_ok=True)
                command = benchmark_shell_command(sample_id, mode, rep_name, args.runtime_root)
                print(f"[RUN] {sample_id}/{mode}/{rep_name}", flush=True)
                if args.dry_run:
                    print(command)
                    continue
                if mode in {"event_only", "bram_ring"}:
                    cmd = ila_capture_command(args, sample_id, mode, rep, rep_dir, command)
                    result = subprocess.run(cmd, cwd=ROOT)
                    if result.returncode != 0:
                        return result.returncode
                else:
                    run_serial_command(
                        port=args.port,
                        baud=args.baud,
                        command=command,
                        program_log=program_log,
                        pre_read=args.pre_read,
                        timeout_seconds=args.process_wait_timeout,
                        sample_id=sample_id,
                        mode=mode,
                        rep_name=rep_name,
                    )
                rows.append(parse_program_log(program_log))
    if args.dry_run:
        print("[PASS] dry run complete")
        return 0
    summary = summarize(rows, args)
    write_json(args.out, summary)
    print(f"[{summary['status']}] wrote production runtime benchmark summary to {args.out}")
    return 0 if summary["status"] == "PASS" else 1


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        log = root / "uart.log"
        log.write_text(
            "\n".join(
                [
                    "RVMT_SEND \"printf 'RVMT_RUNTIME_BENCH_START sample=%s mode=%s rep=%s ns=%s\\n'\"",
                    "RVMT_RUNTIME_BENCH_START sample=file_scan mode=trace_off rep=rep_01 ns=1000",
                    "RVMT_SEND \"printf 'RVMT_RUNTIME_BENCH_DONE sample=%s mode=%s rep=%s rc=%s ns=%s\\n'\"",
                    "RVMT_RUNTIME_BENCH_DONE sample=file_scan mode=trace_off rep=rep_01 rc=0 ns=2500",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        row = parse_program_log(log)
        if row.get("duration_ns") != 1500:
            print("[FAIL] duration parse failed", file=sys.stderr)
            return 1
        args = argparse.Namespace(run_root=root, runtime_root="/tmp/rvmt_p2", repetitions=1)
        summary = summarize(
            [
                row,
                {
                    **row,
                    "mode": "bram_ring",
                    "duration_ns": 3000,
                    "program_log": "bram.log",
                },
            ],
            args,
        )
        sample = summary["samples"][0]
        if sample["modes"]["bram_ring"]["slowdown_vs_trace_off_median"] != 2.0:
            print("[FAIL] slowdown ratio failed", file=sys.stderr)
            return 1
        command = benchmark_shell_command("file_scan", "trace_off", "rep_01", "/tmp/rvmt_p2")
        if "RVMT_RUNTIME_BENCH_START" not in command or "date +%s%N" not in command:
            print("[FAIL] shell command missing benchmark markers", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 runtime benchmark helper self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Genesys2/CVA6 production runtime slowdown benchmarks.")
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--runtime-root", default="/tmp/rvmt_p2")
    parser.add_argument("--sample", action="append", choices=SAMPLES)
    parser.add_argument("--mode", action="append", choices=MODES)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--pre-read", type=float, default=0.1)
    parser.add_argument("--post-read", type=float, default=5.0)
    parser.add_argument("--arm-timeout", type=float, default=45.0)
    parser.add_argument("--process-wait-timeout", type=float, default=180.0)
    parser.add_argument("--ila-timeout-seconds", type=int, default=240)
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--hw-server-url", default="localhost:3121")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.repetitions < 1:
        parser.error("--repetitions must be >= 1")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
