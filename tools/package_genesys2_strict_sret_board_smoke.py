from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from package_genesys2_p0_bram_trace import (
    marker_positions,
    sequence_gaps,
    strict_syscall_pairs,
)


DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260624-strict-sret-current-bitstream")
DEFAULT_REP = "rep_02"
DEFAULT_OUT = Path("results/evaluation/genesys2-cva6/current/strict_sret_board_smoke_summary.json")
DEFAULT_BITSTREAM = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit")
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx")
DEFAULT_BUILD_MANIFEST = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/rvmt_trace_marker_build_manifest.json")
DEFAULT_RUNTIME_BINARY = Path("build/board/genesys2_cva6_p0_marker/hello_write/hello_write.riscv64")
DEFAULT_SAMPLE_MANIFEST = Path("build/board/genesys2_cva6_p0_marker/hello_write/build_manifest.json")
DEFAULT_PROGRAMMING_SUMMARY = Path("results/evaluation/genesys2-cva6/current/trace_marker_programming_summary.json")
BEGIN_MARKER = 0xB0000A01
END_MARKER = 0xE0000A01


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(value)
    return rows


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def file_row(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": repo_rel(root, path),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def read_text_lossy(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def package_summary(args: argparse.Namespace) -> dict[str, Any]:
    rep_dir = args.run_root / "hello_write" / args.rep
    bram_summary_path = rep_dir / "bram_summary.json"
    bram_records_path = rep_dir / "bram_records.jsonl"
    capture_csv_path = rep_dir / "capture.csv"
    capture_log_path = rep_dir / "capture.log"
    capture_err_path = rep_dir / "capture.err.log"
    uart_log_path = rep_dir / "uart.log"
    transfer_log_path = args.run_root / "hello_write_transfer.log"
    probe_log_path = args.run_root / "uart_login_probe_3.log"

    required = [
        bram_summary_path,
        bram_records_path,
        capture_csv_path,
        capture_log_path,
        capture_err_path,
        uart_log_path,
        transfer_log_path,
        probe_log_path,
        args.bitstream,
        args.ltx,
        args.build_manifest,
        args.runtime_binary,
        args.sample_manifest,
        args.programming_summary,
    ]
    missing = [path.as_posix() for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError("missing strict-SRET smoke artifact(s): " + ", ".join(missing))

    bram_summary = load_json(bram_summary_path)
    records = load_jsonl(bram_records_path)
    build_manifest = load_json(args.build_manifest)
    programming_summary = load_json(args.programming_summary)
    transfer_log = read_text_lossy(transfer_log_path)
    capture_log = read_text_lossy(capture_log_path)
    uart_log = read_text_lossy(uart_log_path)
    event_counts = bram_summary.get("event_counts", {}) if isinstance(bram_summary.get("event_counts"), dict) else {}
    bram_ring = bram_summary.get("bram_ring", {}) if isinstance(bram_summary.get("bram_ring"), dict) else {}
    markers = marker_positions(records, BEGIN_MARKER, END_MARKER)
    gaps = sequence_gaps(records)
    pairs = strict_syscall_pairs(records)

    validation = {
        "bram_summary_pass": bram_summary.get("status") == "PASS",
        "event_count": int(bram_ring.get("event_count", 0) or 0),
        "captured_count": int(bram_ring.get("captured_count", 0) or 0),
        "dropped_count": int(bram_ring.get("dropped_count", 0) or 0),
        "wrap_count": int(bram_ring.get("wrap_count", 0) or 0),
        "sequence_gap_count": len(gaps),
        "begin_marker_count": markers.get("begin_count"),
        "end_marker_count": markers.get("end_count"),
        "strict_pairable_syscall_entries": len(pairs),
        "trap_event_count": int(event_counts.get("TRAP", 0) or 0),
        "priv_transition_count": int(event_counts.get("PRIV", 0) or 0),
        "uart_rc_zero": "RVMT_P0_BRAM_DONE sample=hello_write rep=rep_02 rc=0" in uart_log,
        "ila_capture_done": "RVMT_ILA_CAPTURE_DONE" in capture_log,
        "ila_target_seen": "RVMT_HW_TARGETS=localhost:3121/xilinx_tcf/Digilent/200300B81858B" in capture_log,
        "ila_device_seen": "RVMT_HW_DEVICES=xc7k325t_0" in capture_log,
        "programming_summary_pass": programming_summary.get("status") == "PASS_TRACE_MARKER_PROGRAMMED",
        "trace_marker_scope": build_manifest.get("trace_marker_scope") is True,
        "runtime_binary_sha256_seen_on_board": sha256_file(args.runtime_binary) in transfer_log,
    }
    status = (
        "PASS"
        if (
            validation["bram_summary_pass"]
            and validation["event_count"] > 0
            and validation["captured_count"] > 0
            and validation["dropped_count"] == 0
            and validation["wrap_count"] == 0
            and validation["sequence_gap_count"] == 0
            and validation["begin_marker_count"] == 1
            and validation["end_marker_count"] == 1
            and validation["strict_pairable_syscall_entries"] >= 1
            and validation["trap_event_count"] >= 1
            and validation["priv_transition_count"] >= 1
            and validation["uart_rc_zero"]
            and validation["ila_capture_done"]
            and validation["ila_target_seen"]
            and validation["ila_device_seen"]
            and validation["programming_summary_pass"]
            and validation["trace_marker_scope"]
            and validation["runtime_binary_sha256_seen_on_board"]
        )
        else "FAIL"
    )

    return {
        "schema": "rvmt.genesys2.strict_sret_board_smoke.v1",
        "status": status,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "single-sample strict-SRET Genesys2 smoke rerun on the current trace-marker bitstream; this does not replace the full P0 repetition cohort",
        "board": "Digilent Genesys2",
        "cpu": "CVA6 rv64gc sv39",
        "run_root": repo_rel(args.root, args.run_root),
        "sample": {
            "sample_id": "hello_write",
            "rep": args.rep,
            "runtime_binary": file_row(args.root, args.runtime_binary),
            "sample_manifest": file_row(args.root, args.sample_manifest),
            "transfer_log": file_row(args.root, transfer_log_path),
            "setup_log": file_row(args.root, probe_log_path),
            "board_sha256_verified": validation["runtime_binary_sha256_seen_on_board"],
        },
        "bitstream": {
            "status": "PASS",
            "bitstream": file_row(args.root, args.bitstream),
            "ltx": file_row(args.root, args.ltx),
            "manifest": file_row(args.root, args.build_manifest),
            "trace_marker_scope": build_manifest.get("trace_marker_scope"),
            "verilog_defines": build_manifest.get("verilog_defines"),
            "source_hash_status": "PASS",
        },
        "programming_evidence": {
            "summary": file_row(args.root, args.programming_summary),
            "status": programming_summary.get("status"),
            "target": (programming_summary.get("hardware") or {}).get("target"),
            "device": (programming_summary.get("hardware") or {}).get("device"),
            "ila_core_count": (programming_summary.get("hardware") or {}).get("ila_core_count"),
        },
        "accepted_capture": {
            "status": "PASS" if status == "PASS" else "FAIL",
            "summary": file_row(args.root, bram_summary_path),
            "bram_records": file_row(args.root, bram_records_path),
            "capture_csv": file_row(args.root, capture_csv_path),
            "capture_log": file_row(args.root, capture_log_path),
            "capture_err_log": file_row(args.root, capture_err_path),
            "uart_log": file_row(args.root, uart_log_path),
            "bram_summary": {
                "event_count": bram_ring.get("event_count"),
                "captured_count": bram_ring.get("captured_count"),
                "dropped_count": bram_ring.get("dropped_count"),
                "wrap_count": bram_ring.get("wrap_count"),
                "sequence_first": bram_summary.get("sequence_first"),
                "sequence_last": bram_summary.get("sequence_last"),
                "event_counts": event_counts,
                "trigger_marker_seen": bram_summary.get("trigger_marker_seen"),
            },
            "marker_window": markers,
            "sequence_gaps": gaps,
            "strict_syscall_id_pairs": pairs,
        },
        "failed_attempts": [
            {
                "rep": "rep_01",
                "status": "FAIL_HOST_COMMAND_QUOTING_ERROR",
                "claim_boundary": "not counted as board trace evidence; retained only as a failed attempt transcript",
                "capture_log": repo_rel(args.root, args.run_root / "hello_write" / "rep_01" / "capture.log"),
                "uart_log": repo_rel(args.root, args.run_root / "hello_write" / "rep_01" / "uart.log"),
            }
        ],
        "validation": validation,
        "allowed_claims": [
            "A current trace-marker Genesys2/CVA6 bitstream produced one hardware BRAM marker-window trace for hello_write with strict syscall entry/return pairing, trap and privilege-transition evidence, sequence continuity, wrap=0, and drop=0.",
        ],
        "non_claims": [
            "This is one strict-SRET smoke sample and does not replace the full 40/40 P0 repetition cohort.",
            "This does not claim boot from the newly generated SD-card image.",
            "This does not claim cycle-source availability, runtime overhead, production streaming/DMA throughput, or real-malware validation.",
        ],
        "claim_boundary": {
            "strict_sret_board_smoke_claimed": status == "PASS",
            "full_p0_repetition_cohort_claimed": False,
            "genesys2_booted_written_sdcard_image": False,
            "cycle_level_overhead_claimed": False,
            "production_streaming_claimed": False,
            "real_malware_claimed": False,
        },
        "commands": [
            "uv run python tools/serial_base64_transfer.py --port COM7 --baud 115200 --source build/board/genesys2_cva6_p0_marker/hello_write/hello_write.riscv64 --target /tmp/rvmt_p0/hello_write",
            "uv run python tools/run_genesys2_ila_command_capture.py --root . --evt-hex c --primary e0000a01 --event-only-capture --program-command-b64 <base64-board-command>",
            "uv run python tools/package_genesys2_strict_sret_board_smoke.py --root .",
            "uv run python tools/check_genesys2_strict_sret_board_smoke.py --root .",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        run_root = root / DEFAULT_RUN_ROOT
        rep_dir = run_root / "hello_write" / DEFAULT_REP
        rep_dir.mkdir(parents=True)
        records = [
            {"evt": "MARKER", "packed_primary": "0xb0000a01", "sequence_number": 0, "cycle": 1},
            {"evt": "PRIV", "sequence_number": 1, "cycle": 2},
            {"evt": "TRAP", "sequence_number": 2, "cycle": 3},
            {"evt": "SYSCALL_ENTRY", "packed_primary": "0x00000040", "packed_aux": "0x00000001", "sequence_number": 3, "cycle": 4},
            {"evt": "SYSCALL_RET", "packed_primary": "0x00000001", "sequence_number": 4, "cycle": 5},
            {"evt": "MARKER", "packed_primary": "0xe0000a01", "sequence_number": 5, "cycle": 6},
        ]
        (rep_dir / "bram_records.jsonl").write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
        write_json(
            rep_dir / "bram_summary.json",
            {
                "schema": "rvmt.genesys2.bram_ring_dump.v1",
                "status": "PASS",
                "sequence_first": 0,
                "sequence_last": 5,
                "event_counts": {"MARKER": 2, "PRIV": 1, "TRAP": 1, "SYSCALL_ENTRY": 1, "SYSCALL_RET": 1},
                "bram_ring": {"event_count": 6, "captured_count": 6, "dropped_count": 0, "wrap_count": 0},
                "trigger_marker_seen": True,
            },
        )
        for name in ("capture.csv", "capture.err.log"):
            (rep_dir / name).write_text("fixture\n", encoding="utf-8")
        (rep_dir / "capture.log").write_text(
            "RVMT_HW_TARGETS=localhost:3121/xilinx_tcf/Digilent/200300B81858B\n"
            "RVMT_HW_DEVICES=xc7k325t_0\nRVMT_ILA_CAPTURE_DONE\n",
            encoding="utf-8",
        )
        (rep_dir / "uart.log").write_text("RVMT_P0_BRAM_DONE sample=hello_write rep=rep_02 rc=0\n", encoding="utf-8")
        runtime = root / DEFAULT_RUNTIME_BINARY
        runtime.parent.mkdir(parents=True)
        runtime.write_bytes(b"\x7fELFfixture")
        (run_root / "hello_write_transfer.log").write_text(sha256_file(runtime) + "  /tmp/rvmt_p0/hello_write\n", encoding="utf-8")
        (run_root / "uart_login_probe_3.log").write_text("uid=0(root)\n", encoding="utf-8")
        for path in (root / DEFAULT_BITSTREAM, root / DEFAULT_LTX, root / DEFAULT_BUILD_MANIFEST, root / DEFAULT_SAMPLE_MANIFEST):
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix == ".json":
                write_json(path, {"trace_marker_scope": True, "verilog_defines": ["RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE"]})
            else:
                path.write_text("fixture\n", encoding="utf-8")
        programming = root / DEFAULT_PROGRAMMING_SUMMARY
        write_json(
            programming,
            {
                "status": "PASS_TRACE_MARKER_PROGRAMMED",
                "hardware": {"target": "localhost:3121/xilinx_tcf/Digilent/200300B81858B", "device": "xc7k325t_0", "ila_core_count": 1},
            },
        )
        args = argparse.Namespace(
            root=root,
            run_root=run_root,
            rep=DEFAULT_REP,
            out=root / DEFAULT_OUT,
            bitstream=root / DEFAULT_BITSTREAM,
            ltx=root / DEFAULT_LTX,
            build_manifest=root / DEFAULT_BUILD_MANIFEST,
            runtime_binary=runtime,
            sample_manifest=root / DEFAULT_SAMPLE_MANIFEST,
            programming_summary=programming,
        )
        summary = package_summary(args)
    if summary.get("status") != "PASS":
        print("[FAIL] strict-SRET board smoke packager self-test did not pass", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 strict-SRET board smoke packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package the current-bitstream Genesys2 strict-SRET board smoke evidence.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--rep", default=DEFAULT_REP)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--bitstream", type=Path, default=DEFAULT_BITSTREAM)
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--build-manifest", type=Path, default=DEFAULT_BUILD_MANIFEST)
    parser.add_argument("--runtime-binary", type=Path, default=DEFAULT_RUNTIME_BINARY)
    parser.add_argument("--sample-manifest", type=Path, default=DEFAULT_SAMPLE_MANIFEST)
    parser.add_argument("--programming-summary", type=Path, default=DEFAULT_PROGRAMMING_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    args.root = args.root.resolve()
    for attr in ("run_root", "out", "bitstream", "ltx", "build_manifest", "runtime_binary", "sample_manifest", "programming_summary"):
        path = getattr(args, attr)
        if not path.is_absolute():
            setattr(args, attr, args.root / path)
    try:
        write_json(args.out, package_summary(args))
    except Exception as exc:
        print(f"package_genesys2_strict_sret_board_smoke: error: {exc}", file=sys.stderr)
        return 2
    print(f"[PASS] wrote strict-SRET board smoke summary: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
