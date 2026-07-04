from __future__ import annotations

import argparse
import base64
import json
import re
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import load_json, load_jsonl, repo_rel, sha256_file_if_present, write_json
from genesys2_experiment_common import transfer_binary


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260704-hardware-trace-cycle-window")
DEFAULT_OUT = Path("results/evaluation/genesys2-cva6/current/hardware_trace_cycle_window_summary.json")
DEFAULT_BUILD_ROOT = Path("build/board/genesys2_cva6_p0_marker")
DEFAULT_RUNTIME_ROOT = "/tmp/rvmt_p0"
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx")
DEFAULT_BITSTREAM = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit")
SCHEMA = "rvmt.genesys2.hardware_trace_cycle_window.v1"
RC_RE = re.compile(r"\bRVMT_HW_TRACE_CYCLE_RC=(-?\d+)\b")

SAMPLES = {
    "hello_write": ("0xb0000a01", "e0000a01"),
    "file_open_read_write": ("0xb0000a02", "e0000a02"),
    "fork_exec": ("0xb0000a03", "e0000a03"),
    "illegal_instruction": ("0xb0000a04", "e0000a04"),
}


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


def file_row(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": repo_rel(root, path),
        "sha256": sha256_file_if_present(path),
        "size_bytes": path.stat().st_size if path.is_file() else 0,
    }


def marker_records(records: list[dict[str, Any]], marker: str) -> list[dict[str, Any]]:
    target = parse_int(marker)
    if target is None:
        raise ValueError(f"invalid marker: {marker}")
    out: list[dict[str, Any]] = []
    for row in records:
        if row.get("evt") != "MARKER":
            continue
        value = parse_int(row.get("packed_primary") or row.get("value"))
        if value == target:
            out.append(row)
    return out


def sequence_gaps(records: list[dict[str, Any]]) -> list[dict[str, int]]:
    seqs = [parse_int(row.get("sequence_number")) for row in records]
    seqs = [seq for seq in seqs if seq is not None]
    gaps: list[dict[str, int]] = []
    for left, right in zip(seqs, seqs[1:]):
        if right != left + 1:
            gaps.append({"after": left, "before": right})
    return gaps


def cycle_delta(begin: int, end: int) -> tuple[int, bool]:
    if end >= begin:
        return end - begin, False
    return (1 << 32) - begin + end, True


def read_uart_rc(path: Path, token: str) -> int | None:
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if token not in line:
            continue
        match = RC_RE.search(line)
        return int(match.group(1), 10) if match else None
    return None


def summarize_repetition(
    *,
    root: Path,
    sample_id: str,
    rep_dir: Path,
    begin_marker: str,
    end_marker: str,
) -> dict[str, Any]:
    bram_summary_path = rep_dir / "bram_summary.json"
    bram_records_path = rep_dir / "bram_records.jsonl"
    bram_summary = load_json(bram_summary_path)
    records = load_jsonl(bram_records_path)
    ring = bram_summary.get("bram_ring", {}) if isinstance(bram_summary.get("bram_ring"), dict) else {}
    begin_rows = marker_records(records, begin_marker)
    end_rows = marker_records(records, "0x" + end_marker if not end_marker.startswith("0x") else end_marker)
    gaps = sequence_gaps(records)
    begin_cycle = parse_int(begin_rows[0].get("cycle")) if begin_rows else None
    end_cycle = parse_int(end_rows[-1].get("cycle")) if end_rows else None
    marker_delta = None
    marker_cycle_wrapped = False
    if begin_cycle is not None and end_cycle is not None:
        marker_delta, marker_cycle_wrapped = cycle_delta(begin_cycle, end_cycle)
    uart_rc = read_uart_rc(rep_dir / "uart.log", "RVMT_HW_TRACE_CYCLE_RC=")
    bram_marker_window_complete = (
        bram_summary.get("status") == "PASS"
        and len(begin_rows) == 1
        and len(end_rows) == 1
        and marker_delta is not None
        and marker_delta > 0
        and int(ring.get("dropped_count", 0) or 0) == 0
        and int(ring.get("wrap_count", 0) or 0) == 0
        and not bool(ring.get("full", False))
        and not gaps
    )
    uart_rc_consistent = uart_rc is None or uart_rc == 0 or sample_id == "illegal_instruction"
    accepted = bram_marker_window_complete and uart_rc_consistent
    acceptance_basis = []
    if bram_marker_window_complete:
        acceptance_basis.append("bram_marker_window_complete")
    if uart_rc is None:
        acceptance_basis.append("uart_rc_not_observed_auxiliary")
    elif uart_rc_consistent:
        acceptance_basis.append("uart_rc_consistent")
    return {
        "sample_id": sample_id,
        "repetition": rep_dir.name,
        "accepted": accepted,
        "acceptance_basis": acceptance_basis,
        "bram_marker_window_complete": bram_marker_window_complete,
        "uart_rc_observed": uart_rc is not None,
        "uart_rc_required_for_acceptance": False,
        "begin_marker": begin_marker,
        "end_marker": "0x" + end_marker if not end_marker.startswith("0x") else end_marker,
        "begin_marker_count": len(begin_rows),
        "end_marker_count": len(end_rows),
        "begin_sequence": begin_rows[0].get("sequence_number") if begin_rows else None,
        "end_sequence": end_rows[-1].get("sequence_number") if end_rows else None,
        "begin_cycle": begin_cycle,
        "end_cycle": end_cycle,
        "marker_cycle_delta": marker_delta,
        "marker_cycle_wrapped": marker_cycle_wrapped,
        "sequence_gaps": gaps,
        "uart_rc": uart_rc,
        "event_counts": bram_summary.get("event_counts", {}),
        "bram_ring": {
            "event_count": ring.get("event_count", 0),
            "captured_count": ring.get("captured_count", 0),
            "dropped_count": ring.get("dropped_count", 0),
            "wrap_count": ring.get("wrap_count", 0),
            "full": ring.get("full", False),
            "start_timestamp": ring.get("start_timestamp", 0),
            "end_timestamp": ring.get("end_timestamp", 0),
        },
        "artifacts": {
            "bram_summary": file_row(root, bram_summary_path),
            "bram_records": file_row(root, bram_records_path),
            "capture_csv": file_row(root, rep_dir / "capture.csv"),
            "capture_log": file_row(root, rep_dir / "capture.log"),
            "capture_err_log": file_row(root, rep_dir / "capture.err.log"),
            "uart_log": file_row(root, rep_dir / "uart.log"),
        },
    }


def stats(values: list[int]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "min": None, "median": None, "max": None, "mean": None}
    return {
        "count": len(values),
        "min": min(values),
        "median": statistics.median(values),
        "max": max(values),
        "mean": statistics.mean(values),
        "pstdev": statistics.pstdev(values) if len(values) > 1 else 0.0,
    }


def build_summary(args: argparse.Namespace, repetitions: list[dict[str, Any]]) -> dict[str, Any]:
    accepted = [row for row in repetitions if row.get("accepted") is True]
    deltas = [int(row["marker_cycle_delta"]) for row in accepted if row.get("marker_cycle_delta") is not None]
    status = "PASS" if len(accepted) >= args.minimum_repetitions and all(delta > 0 for delta in deltas) else "BLOCKED_HARDWARE_TRACE_CYCLE_WINDOW_INCOMPLETE"
    return {
        "schema": SCHEMA,
        "status": status,
        "board": "Digilent Genesys2",
        "cpu": "CVA6 rv64gc sv39",
        "run_root": repo_rel(ROOT, args.run_root),
        "samples": args.sample,
        "requested_repetitions": args.repetitions,
        "minimum_repetitions": args.minimum_repetitions,
        "accepted_repetitions": len(accepted),
        "cycle_source": "rv_maltrace_fpga_trace_cycle_field",
        "cycle_domain": "FPGA trace packet cycle field, decoded from BRAM marker-window records",
        "acceptance_policy": {
            "required": [
                "BRAM summary PASS",
                "exactly one begin MARKER and one end MARKER",
                "positive marker_cycle_delta from the FPGA trace packet cycle field",
                "no BRAM drops, wraps, full-ring condition, or sequence gaps",
            ],
            "auxiliary": [
                "UART process return code, when fully observed, must be consistent with the sample expectation.",
                "UART return-code text is not required because the ILA trigger and BRAM marker records are the primary hardware evidence.",
            ],
        },
        "marker_cycle_delta_stats": stats(deltas),
        "repetitions": repetitions,
        "bitstream": file_row(ROOT, args.bitstream) if args.bitstream else None,
        "ltx": file_row(ROOT, args.ltx) if args.ltx else None,
        "claim_boundary": {
            "hardware_trace_cycle_window_claimed": status == "PASS",
            "linux_perf_cycle_source_claimed": False,
            "user_rdcycle_source_claimed": False,
            "trace_off_slowdown_claimed": False,
            "production_runtime_slowdown_claimed": False,
        },
        "non_claims": [
            "The cycle source is the RV-MalTrace FPGA trace packet cycle field, not Linux perf_event_open.",
            "This summary measures marker-window cycle duration for controlled P0 workloads and does not by itself claim trace-off slowdown.",
            "The P0 workloads are repository-authored safe synthetic workloads, not real malware.",
        ],
    }


def transfer_samples(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    transferred: dict[str, dict[str, Any]] = {}
    for sample_id in args.sample:
        binary = args.build_root / sample_id / f"{sample_id}.riscv64"
        if not binary.is_file():
            raise FileNotFoundError(f"P0 binary missing: {binary}")
        target = f"{args.runtime_root.rstrip('/')}/{sample_id}"
        log = args.run_root / f"{sample_id}_transfer.log"
        transfer_binary(ROOT, port=args.port, baud=args.baud, binary=binary, target=target, transfer_log=log)
        transferred[sample_id] = {
            "binary": file_row(ROOT, binary),
            "target": target,
            "transfer_log": file_row(ROOT, log),
        }
    return transferred


def program_command(sample_id: str, rep_name: str, runtime_root: str) -> str:
    target = f"{runtime_root.rstrip('/')}/{sample_id}"
    return (
        f"printf 'RVMT_HW_TRACE_CYCLE_START sample={sample_id} rep={rep_name}\\n'; "
        f"{target}; "
        "rc=$?; "
        f"printf 'RVMT_HW_TRACE_CYCLE_RC=%s sample={sample_id} rep={rep_name}\\n' \"$rc\""
    )


def run_capture(args: argparse.Namespace, sample_id: str, rep: int, end_marker: str) -> None:
    rep_name = f"rep_{rep:02d}"
    rep_dir = args.run_root / sample_id / rep_name
    rep_dir.mkdir(parents=True, exist_ok=True)
    done_token = f"RVMT_HW_TRACE_CYCLE_RC=0 sample={sample_id} rep={rep_name}"
    command = [
        sys.executable,
        "tools/run_genesys2_ila_command_capture.py",
        "--root",
        ".",
        "--evt-hex",
        "c",
        "--primary",
        end_marker,
        "--csv",
        str(rep_dir / "capture.csv"),
        "--timeout-seconds",
        str(args.timeout_seconds),
        "--trigger-position",
        "0",
        "--event-only-capture",
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
        "--program-command-b64",
        base64.b64encode(program_command(sample_id, rep_name, args.runtime_root).encode("utf-8")).decode("ascii"),
        "--port",
        args.port,
        "--baud",
        str(args.baud),
        "--pre-read",
        str(args.pre_read),
        "--post-read",
        str(args.post_read),
        "--post-read-until",
        done_token,
        "--post-read-loose-required",
        "RVMT_HW_TRACE_CYCLE_RC=",
        "--post-read-loose-required",
        f"sample={sample_id}",
        "--post-read-loose-required",
        f"rep={rep_name}",
        "--arm-timeout",
        str(args.arm_timeout),
        "--process-wait-timeout",
        str(args.process_wait_timeout),
        "--bram-out-jsonl",
        str(rep_dir / "bram_records.jsonl"),
        "--bram-summary",
        str(rep_dir / "bram_summary.json"),
        "--bram-trigger-primary",
        end_marker,
        "--sample-id",
        sample_id,
    ]
    print(f"[RUN] {sample_id}/{rep_name}: hardware trace cycle window capture", flush=True)
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode != 0:
        raise RuntimeError(f"{sample_id}/{rep_name}: capture failed with {result.returncode}")


def run(args: argparse.Namespace) -> int:
    args.run_root.mkdir(parents=True, exist_ok=True)
    if not args.skip_transfer:
        transfer_samples(args)
    repetitions: list[dict[str, Any]] = []
    for sample_id in args.sample:
        begin_marker, end_marker = SAMPLES[sample_id]
        for rep in range(1, args.repetitions + 1):
            rep_dir = args.run_root / sample_id / f"rep_{rep:02d}"
            if not args.skip_capture:
                run_capture(args, sample_id, rep, end_marker)
            repetitions.append(
                summarize_repetition(
                    root=ROOT,
                    sample_id=sample_id,
                    rep_dir=rep_dir,
                    begin_marker=begin_marker,
                    end_marker=end_marker,
                )
            )
    summary = build_summary(args, repetitions)
    write_json(args.out, summary)
    print(f"[{summary['status']}] wrote hardware trace cycle-window summary to {args.out}")
    if summary["status"] != "PASS":
        return 2
    return 0


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        run_root = root / "run"
        rep_dir = run_root / "hello_write" / "rep_01"
        rep_dir.mkdir(parents=True)
        records = [
            {"evt": "MARKER", "packed_primary": "0xb0000a01", "sequence_number": 0, "cycle": 100},
            {"evt": "SYSCALL_ENTRY", "packed_primary": "0x00000040", "sequence_number": 1, "cycle": 120},
            {"evt": "SYSCALL_RET", "packed_primary": "0x00000001", "sequence_number": 2, "cycle": 140},
            {"evt": "MARKER", "packed_primary": "0xe0000a01", "sequence_number": 3, "cycle": 180},
        ]
        (rep_dir / "bram_records.jsonl").write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
        write_json(
            rep_dir / "bram_summary.json",
            {
                "status": "PASS",
                "event_counts": {"MARKER": 2, "SYSCALL_ENTRY": 1, "SYSCALL_RET": 1},
                "bram_ring": {
                    "event_count": 4,
                    "captured_count": 4,
                    "dropped_count": 0,
                    "wrap_count": 0,
                    "full": False,
                    "start_timestamp": 100,
                    "end_timestamp": 180,
                },
            },
        )
        for name in ("capture.csv", "capture.log", "capture.err.log"):
            (rep_dir / name).write_text("fixture\n", encoding="utf-8")
        (rep_dir / "uart.log").write_text("RVMT_HW_TRACE_CYCLE_RC=0 sample=hello_write rep=rep_01\n", encoding="utf-8")
        args = argparse.Namespace(
            run_root=run_root,
            sample=["hello_write"],
            repetitions=1,
            minimum_repetitions=1,
            bitstream=None,
            ltx=None,
        )
        rep = summarize_repetition(
            root=root,
            sample_id="hello_write",
            rep_dir=rep_dir,
            begin_marker="0xb0000a01",
            end_marker="e0000a01",
        )
        summary = build_summary(args, [rep])
    if summary["status"] != "PASS" or summary["marker_cycle_delta_stats"]["median"] != 80:
        print("[FAIL] hardware trace cycle-window self-test failed", file=sys.stderr)
        return 1
    print("[PASS] hardware trace cycle-window runner self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure controlled workload marker windows using RV-MalTrace hardware trace cycles.")
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--build-root", type=Path, default=DEFAULT_BUILD_ROOT)
    parser.add_argument("--runtime-root", default=DEFAULT_RUNTIME_ROOT)
    parser.add_argument("--sample", action="append", choices=sorted(SAMPLES), default=None)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--minimum-repetitions", type=int, default=5)
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--bitstream", type=Path, default=DEFAULT_BITSTREAM)
    parser.add_argument("--hw-server-url", default="localhost:3121")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--pre-read", type=float, default=0.1)
    parser.add_argument("--post-read", type=float, default=8.0)
    parser.add_argument("--arm-timeout", type=float, default=45.0)
    parser.add_argument("--process-wait-timeout", type=float, default=360.0)
    parser.add_argument("--skip-transfer", action="store_true")
    parser.add_argument("--skip-capture", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    args.sample = args.sample or ["hello_write"]
    if args.repetitions < 1 or args.minimum_repetitions < 1:
        parser.error("--repetitions and --minimum-repetitions must be >= 1")
    if args.minimum_repetitions > args.repetitions:
        parser.error("--minimum-repetitions cannot exceed --repetitions")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
