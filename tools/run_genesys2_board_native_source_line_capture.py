from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    load_jsonl,
    repo_path,
    repo_rel,
    write_json,
)

from ccfa_gate_common import ALL_CCFA_SAMPLES, P0_BRAM_MARKERS, P0_SAMPLES


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEBUG_READINESS = Path("results/evaluation/genesys2-cva6/current/debug_elf_readiness_summary.json")
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260613-board-native-dwarf-source-lines")
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-source-lines/work-fpga/ariane_xilinx.ltx")
DEFAULT_RUNTIME_ROOT = "/tmp/rvmt_debug"
DEFAULT_WRAPPER_ROOT = "/tmp/rvmt_debug_wrappers"
SAFE_BEGIN_MARKER = "0xb0000a11"
SAFE_END_MARKER = "0xe0000a11"


def readiness_rows(root: Path, readiness_path: Path) -> dict[str, dict[str, Any]]:
    data = load_json(repo_path(root, readiness_path))
    rows = data.get("samples")
    if not isinstance(rows, list):
        raise ValueError(f"{readiness_path}: missing samples list")
    mapped = {str(row.get("id")): row for row in rows if isinstance(row, dict) and row.get("id")}
    missing = [sample for sample in ALL_CCFA_SAMPLES if sample not in mapped]
    if missing:
        raise ValueError("debug readiness missing sample(s): " + ", ".join(missing))
    return mapped


def marker_pair(sample_id: str) -> tuple[str, str]:
    if sample_id in P0_SAMPLES:
        return P0_BRAM_MARKERS[sample_id]
    return SAFE_BEGIN_MARKER, SAFE_END_MARKER


def run_command(command: list[str], *, cwd: Path, dry_run: bool = False) -> int:
    print(f"[RUN] {' '.join(command)}", flush=True)
    if dry_run:
        return 0
    return subprocess.run(command, cwd=cwd).returncode


def build_wrapper(root: Path, sample_dir: Path, sample_id: str, runtime_path: str, begin_marker: str, end_marker: str, dry_run: bool) -> Path:
    wrapper = sample_dir / "00_marker_wrapper" / f"{sample_id}_marker_wrap.riscv64"
    command = [
        sys.executable,
        "tools/build_genesys2_marker_wrapper_elf.py",
        "--out",
        str(wrapper),
        "--sample-id",
        sample_id,
        "--exec-path",
        runtime_path,
        "--arg",
        runtime_path,
        "--begin-marker",
        begin_marker,
        "--end-marker",
        end_marker,
    ]
    rc = run_command(command, cwd=root, dry_run=dry_run)
    if rc != 0:
        raise RuntimeError(f"{sample_id}: marker wrapper build failed with {rc}")
    return wrapper


def transfer_file(
    root: Path,
    source: Path,
    target: str,
    log: Path,
    args: argparse.Namespace,
) -> int:
    command = [
        sys.executable,
        "tools/serial_base64_transfer.py",
        "--port",
        args.port,
        "--baud",
        str(args.baud),
        "--source",
        str(source),
        "--target",
        target,
        "--log",
        str(log),
        "--chunk-lines",
        str(args.transfer_chunk_lines),
        "--chunk-read",
        str(args.transfer_chunk_read),
        "--final-read",
        str(args.transfer_final_read),
        "--line-delay",
        str(args.transfer_line_delay),
        "--prompt-token",
        args.prompt_token,
        "--disable-echo",
    ]
    return run_command(command, cwd=root, dry_run=args.dry_run)


def transfer_inputs(root: Path, sample_dir: Path, sample_id: str, ready: dict[str, Any], wrapper: Path, args: argparse.Namespace) -> None:
    runtime_path = str(ready.get("runtime_path") or f"{args.runtime_root.rstrip('/')}/{sample_id}")
    wrapper_runtime = f"{args.wrapper_root.rstrip('/')}/{sample_id}_marker_wrap"
    if args.no_transfer:
        return
    mkdir_log = sample_dir / "01_board_transfer" / "mkdir.log"
    mkdir_cmd = [
        sys.executable,
        "tools/serial_direct_command_capture.py",
        "--port",
        args.port,
        "--baud",
        str(args.baud),
        "--out",
        str(mkdir_log),
        "--pre-read",
        "0.1",
        "--post-read",
        "3",
        f"mkdir -p {args.runtime_root} {args.wrapper_root}; echo RVMT_DEBUG_DIR_READY",
    ]
    rc = run_command(mkdir_cmd, cwd=root, dry_run=args.dry_run)
    if rc != 0:
        raise RuntimeError(f"{sample_id}: board mkdir failed with {rc}")
    elf = repo_path(root, str(ready.get("debug_elf_path") or ""))
    if not args.skip_debug_transfer:
        rc = transfer_file(root, elf, runtime_path, sample_dir / "01_board_transfer" / "debug_elf_transfer.log", args)
        if rc != 0:
            raise RuntimeError(f"{sample_id}: debug ELF transfer failed with {rc}")
    rc = transfer_file(root, wrapper, wrapper_runtime, sample_dir / "01_board_transfer" / "wrapper_transfer.log", args)
    if rc != 0:
        raise RuntimeError(f"{sample_id}: wrapper transfer failed with {rc}")


def rep_is_capture_pass(rep_dir: Path) -> bool:
    summary_path = rep_dir / "bram_summary.json"
    records_path = rep_dir / "bram_records.jsonl"
    if not summary_path.is_file() or not records_path.is_file():
        return False
    try:
        summary = load_json(summary_path)
    except Exception:
        return False
    bram = summary.get("bram_ring") if isinstance(summary.get("bram_ring"), dict) else {}
    return (
        summary.get("status") == "PASS"
        and int(bram.get("event_count", 0) or 0) > 0
        and int(bram.get("dropped_count", 0) or 0) == 0
        and int(bram.get("wrap_count", 0) or 0) == 0
    )


def capture_attempt(root: Path, sample_dir: Path, sample_id: str, end_marker: str, args: argparse.Namespace, attempt: int) -> Path | None:
    rep_name = f"attempt_{attempt:02d}"
    rep_dir = sample_dir / rep_name
    if rep_is_capture_pass(rep_dir) and not args.force:
        print(f"[SKIP] {sample_id}/{rep_name}: existing PASS capture")
        return rep_dir
    rep_dir.mkdir(parents=True, exist_ok=True)
    wrapper_runtime = f"{args.wrapper_root.rstrip('/')}/{sample_id}_marker_wrap"
    done_token = f"RVMT_DWARF_BRAM_DONE sample={sample_id} attempt={rep_name}"
    program_command = (
        f"printf 'RVMT_DWARF_BRAM_START sample={sample_id} attempt={rep_name}\\n'; "
        f"{wrapper_runtime}; "
        "rc=$?; "
        f"printf 'RVMT_DWARF_BRAM_DONE sample={sample_id} attempt={rep_name} rc=%s\\n' \"$rc\""
    )
    command = [
        sys.executable,
        "tools/run_genesys2_ila_command_capture.py",
        "--root",
        ".",
        "--evt-hex",
        "c",
        "--primary",
        end_marker.removeprefix("0x"),
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
        program_command,
        "--post-read-until",
        done_token,
        "--post-read-loose-required",
        "RVMT_DWARF_BRAM_DONE",
        "--post-read-loose-required",
        "rc=0",
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
        end_marker.removeprefix("0x"),
        "--sample-id",
        sample_id,
    ]
    rc = run_command(command, cwd=root, dry_run=args.dry_run)
    if rc == 0 and (args.dry_run or rep_is_capture_pass(rep_dir)):
        return rep_dir
    print(f"[WARN] {sample_id}/{rep_name}: capture failed rc={rc}", file=sys.stderr)
    return None


def source_line_metrics(joined_events: list[dict[str, Any]]) -> dict[str, Any]:
    target_events = [
        row
        for row in joined_events
        if row.get("pc_owner_static") == "target_sample"
        and row.get("evt") not in {"MARKER", "PRIV", "CSR", "SATP", "DROP", "NONE"}
    ]
    with_source = [row for row in target_events if row.get("source_file") and row.get("source_line") is not None]
    unknown = [
        row
        for row in target_events
        if not (row.get("source_file") and row.get("source_line") is not None)
    ]
    return {
        "key_event_count": len(target_events),
        "source_line_event_count": len(with_source),
        "source_line_rate": (len(with_source) / len(target_events)) if target_events else 0.0,
        "unknown_key_events": len(unknown),
    }


def join_and_manifest(
    root: Path,
    sample_dir: Path,
    sample_id: str,
    ready: dict[str, Any],
    accepted_dir: Path,
    begin_marker: str,
    end_marker: str,
    wrapper_root: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    joined_path = sample_dir / "joined_trace_code_map.jsonl"
    joined_summary_path = sample_dir / "joined_trace_code_map_summary.json"
    command = [
        sys.executable,
        "tools/join_trace_code_map.py",
        "--trace",
        str(accepted_dir / "bram_records.jsonl"),
        "--code-map",
        str(repo_path(root, str(ready.get("code_map_path") or ""))),
        "--out",
        str(joined_path),
        "--summary-out",
        str(joined_summary_path),
    ]
    rc = run_command(command, cwd=root)
    if rc != 0:
        raise RuntimeError(f"{sample_id}: trace/code-map join failed with {rc}")
    joined_summary = load_json(joined_summary_path)
    joined_events = load_jsonl(joined_path)
    metrics = source_line_metrics(joined_events)
    bram_summary = load_json(accepted_dir / "bram_summary.json")
    bram_ring = bram_summary.get("bram_ring") if isinstance(bram_summary.get("bram_ring"), dict) else {}
    marker_scope = joined_summary.get("marker_scope") if isinstance(joined_summary.get("marker_scope"), dict) else {}
    capture_manifest = {
        "id": sample_id,
        "schema": "rvmt.genesys2.board_native_dwarf_capture.v1",
        "genesys2_cva6_board_trace_claimed": True,
        "board_trace_claimed": True,
        "transport": "bram_jtag_marker_window",
        "accepted_attempt": accepted_dir.name,
        "debug_elf_path": ready.get("debug_elf_path"),
        "debug_elf_sha256": ready.get("debug_elf_sha256"),
        "captured_elf_sha256": ready.get("debug_elf_sha256"),
        "runtime_path": ready.get("runtime_path"),
        "wrapper_runtime_path": f"{wrapper_root.rstrip('/')}/{sample_id}_marker_wrap",
        "marker_begin": begin_marker,
        "marker_end": end_marker,
        "marker_window_passed": marker_scope.get("status") == "PASS",
        "bram_summary": repo_rel(root, accepted_dir / "bram_summary.json"),
        "bram_records": repo_rel(root, accepted_dir / "bram_records.jsonl"),
        "capture_csv": repo_rel(root, accepted_dir / "capture.csv"),
        "dropped_count": int(bram_ring.get("dropped_count", 0) or 0),
        "wrap_count": int(bram_ring.get("wrap_count", 0) or 0),
        "event_count": int(bram_ring.get("event_count", 0) or 0),
    }
    joined_manifest = {
        "id": sample_id,
        "schema": "rvmt.genesys2.joined_trace_code_map_manifest.v1",
        "joined_trace_code_map": repo_rel(root, joined_path),
        "joined_trace_code_map_summary": repo_rel(root, joined_summary_path),
        "source_line_rate": metrics["source_line_rate"],
        "source_line_event_count": metrics["source_line_event_count"],
        "key_event_count": metrics["key_event_count"],
        "unknown_key_events": metrics["unknown_key_events"],
        "unaccounted_drop": int(capture_manifest["dropped_count"]) + int(capture_manifest["wrap_count"]),
        "marker_window_passed": capture_manifest["marker_window_passed"],
        "marker_scope": marker_scope,
        "source_line_basis": "board BRAM marker-window trace joined to exact debug/no-PIE ELF code map",
    }
    write_json(sample_dir / "board_capture_manifest.json", capture_manifest)
    write_json(sample_dir / "joined_trace_code_map_manifest.json", joined_manifest)
    return capture_manifest, joined_manifest


def run(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    rows = readiness_rows(root, args.debug_readiness)
    selected = args.sample or ALL_CCFA_SAMPLES
    args.run_root.mkdir(parents=True, exist_ok=True)
    board_rows: list[dict[str, Any]] = []
    joined_rows: list[dict[str, Any]] = []
    for sample_id in selected:
        ready = rows[sample_id]
        sample_dir = args.run_root / sample_id
        sample_dir.mkdir(parents=True, exist_ok=True)
        begin_marker, end_marker = marker_pair(sample_id)
        runtime_path = str(ready.get("runtime_path") or f"{args.runtime_root.rstrip('/')}/{sample_id}")
        wrapper = build_wrapper(root, sample_dir, sample_id, runtime_path, begin_marker, end_marker, args.dry_run)
        transfer_inputs(root, sample_dir, sample_id, ready, wrapper, args)
        if args.dry_run:
            continue
        accepted_dir: Path | None = None
        for attempt in range(1, args.retries + 1):
            accepted_dir = capture_attempt(root, sample_dir, sample_id, end_marker, args, attempt)
            if accepted_dir is not None:
                break
        if accepted_dir is None:
            print(f"[FAIL] {sample_id}: no accepted board capture after {args.retries} attempt(s)", file=sys.stderr)
            return 1
        capture_manifest, joined_manifest = join_and_manifest(
            root,
            sample_dir,
            sample_id,
            ready,
            accepted_dir,
            begin_marker,
            end_marker,
            args.wrapper_root,
        )
        board_rows.append(capture_manifest)
        joined_rows.append(joined_manifest)
        if joined_manifest["source_line_rate"] < 0.95 or joined_manifest["unknown_key_events"] != 0 or joined_manifest["unaccounted_drop"] != 0 or not joined_manifest["marker_window_passed"]:
            print(f"[FAIL] {sample_id}: joined source-line metrics did not pass", file=sys.stderr)
            print(json.dumps(joined_manifest, indent=2, sort_keys=True), file=sys.stderr)
            return 1
    if args.dry_run:
        print("[PASS] dry run complete")
        return 0
    write_json(args.run_root / "board_capture_manifest.json", {"schema": "rvmt.genesys2.board_native_dwarf_capture_set.v1", "samples": board_rows})
    write_json(args.run_root / "joined_trace_code_map_manifest.json", {"schema": "rvmt.genesys2.joined_trace_code_map_set.v1", "samples": joined_rows})
    if args.no_package:
        print("[PASS] board-native DWARF source-line captures complete without packaging")
        return 0
    package_cmd = [
        sys.executable,
        "tools/package_genesys2_board_native_source_lines.py",
        "--root",
        str(root),
        "--run-root",
        str(args.run_root),
        "--generate-readelf-decodedline",
    ]
    rc = run_command(package_cmd, cwd=root)
    if rc != 0:
        return rc
    check_cmd = [sys.executable, "tools/check_genesys2_board_native_source_lines.py", "--root", str(root)]
    rc = run_command(check_cmd, cwd=root)
    if rc != 0:
        return rc
    print("[PASS] board-native DWARF source-line captures packaged")
    return 0


def self_test() -> int:
    rows = [
        {"evt": "SYSCALL_ENTRY", "pc_owner_static": "target_sample", "source_file": "a.c", "source_line": 1},
        {"evt": "ARG_MEM", "pc_owner_static": "target_sample", "source_file": "a.c", "source_line": 1},
        {"evt": "MARKER", "pc_owner_static": "unknown"},
        {"evt": "SYSCALL_ENTRY", "pc_owner_static": "unknown"},
    ]
    metrics = source_line_metrics(rows)
    if metrics["source_line_rate"] != 1.0 or metrics["unknown_key_events"] != 0 or metrics["key_event_count"] != 2:
        print("[FAIL] source-line metric PASS fixture rejected", file=sys.stderr)
        print(metrics, file=sys.stderr)
        return 1
    rows.append({"evt": "TRAP", "pc_owner_static": "target_sample"})
    bad = source_line_metrics(rows)
    if bad["source_line_rate"] >= 1.0 or bad["unknown_key_events"] != 1:
        print("[FAIL] source-line metric missing-source fixture accepted", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 board-native source-line capture helper self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture board-native DWARF source-line evidence on Genesys2/CVA6.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--debug-readiness", type=Path, default=DEFAULT_DEBUG_READINESS)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--runtime-root", default=DEFAULT_RUNTIME_ROOT)
    parser.add_argument("--wrapper-root", default=DEFAULT_WRAPPER_ROOT)
    parser.add_argument("--sample", action="append", choices=ALL_CCFA_SAMPLES)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--hw-server-url", default="localhost:3121")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--prompt-token", default="# ")
    parser.add_argument("--transfer-chunk-lines", type=int, default=64)
    parser.add_argument("--transfer-chunk-read", type=float, default=5.0)
    parser.add_argument("--transfer-final-read", type=float, default=20.0)
    parser.add_argument("--transfer-line-delay", type=float, default=0.005)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--pre-read", type=float, default=2.0)
    parser.add_argument("--post-read", type=float, default=60.0)
    parser.add_argument("--arm-timeout", type=float, default=60.0)
    parser.add_argument("--process-wait-timeout", type=float, default=300.0)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--no-transfer", action="store_true")
    parser.add_argument("--skip-debug-transfer", action="store_true")
    parser.add_argument("--no-package", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.retries < 1:
        parser.error("--retries must be >= 1")
    args.run_root = args.run_root if args.run_root.is_absolute() else args.root / args.run_root
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
