from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260613-board-benign-control")
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx")
DEFAULT_BINARY_ROOT = "/tmp/rvmt_benign_syscall"
DEFAULT_MANIFEST = Path("experiments/linux_behavior/benign/manifest.json")

BENIGN_SAMPLES = {
    "hello": "direct_syscall_write_stdout",
    "ls": "direct_syscall_openat_getdents64_write_close",
    "cat": "direct_syscall_openat_read_write_close",
    "cp": "direct_syscall_openat_read_openat_write_close",
    "sha256sum": "direct_syscall_openat_read_close_write_digest",
}


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def repo_rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def run_command(command: list[str], *, cwd: Path, dry_run: bool = False) -> int:
    print(f"[RUN] {' '.join(command)}", flush=True)
    if dry_run:
        return 0
    return subprocess.run(command, cwd=cwd).returncode


def marker_pair(index: int) -> tuple[str, str]:
    payload = 0xB10 + index
    return f"0xb000{payload:04x}", f"0xe000{payload:04x}"


def build_benign_elf(root: Path, sample_dir: Path, sample_id: str, begin_marker: str, end_marker: str, dry_run: bool) -> tuple[Path, Path]:
    binary = sample_dir / "00_benign_syscall_elf" / f"{sample_id}.riscv64"
    code_map_dir = sample_dir / "00_benign_syscall_elf" / "code_map"
    command = [
        sys.executable,
        "tools/build_genesys2_benign_syscall_elf.py",
        "--out",
        str(binary),
        "--sample-id",
        sample_id,
        "--code-map",
        "--begin-marker",
        begin_marker,
        "--end-marker",
        end_marker,
    ]
    rc = run_command(command, cwd=root, dry_run=dry_run)
    if rc != 0:
        raise RuntimeError(f"{sample_id}: benign syscall ELF build failed with {rc}")
    return binary, code_map_dir / "code_map.json"


def board_setup(root: Path, args: argparse.Namespace) -> None:
    if args.no_transfer:
        return
    setup_cmd = (
        f"mkdir -p {args.binary_root}; "
        "printf 'rvmt benign fixture\\n' > /tmp/rvmt_benign_input.txt; "
        "rm -f /tmp/rvmt_benign_copy.txt; "
        "echo RVMT_BENIGN_SETUP_READY"
    )
    command = [
        sys.executable,
        "tools/serial_direct_command_capture.py",
        "--port",
        args.port,
        "--baud",
        str(args.baud),
        "--out",
        str(args.run_root / "board_setup.log"),
        "--pre-read",
        "0.1",
        "--post-read",
        "5",
        setup_cmd,
    ]
    rc = run_command(command, cwd=root, dry_run=args.dry_run)
    if rc != 0:
        raise RuntimeError(f"board setup failed with {rc}")


def transfer_binary(root: Path, binary: Path, target: str, log: Path, args: argparse.Namespace) -> None:
    if args.no_transfer:
        return
    command = [
        sys.executable,
        "tools/serial_base64_transfer.py",
        "--port",
        args.port,
        "--baud",
        str(args.baud),
        "--source",
        str(binary),
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
    rc = run_command(command, cwd=root, dry_run=args.dry_run)
    if rc != 0:
        raise RuntimeError(f"{binary}: transfer failed with {rc}")


def rep_is_pass(rep_dir: Path) -> bool:
    summary_path = rep_dir / "bram_summary.json"
    if not summary_path.is_file() or not (rep_dir / "bram_records.jsonl").is_file():
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


def capture_sample(root: Path, sample_dir: Path, sample_id: str, end_marker: str, args: argparse.Namespace) -> Path:
    rep_dir = sample_dir / "rep_01"
    if rep_is_pass(rep_dir) and not args.force:
        print(f"[SKIP] {sample_id}/rep_01: existing PASS capture")
        return rep_dir
    rep_dir.mkdir(parents=True, exist_ok=True)
    runtime = f"{args.binary_root.rstrip('/')}/{sample_id}"
    done_token = f"RVMT_BENIGN_DONE sample={sample_id}"
    program_command = (
        f"printf 'RVMT_BENIGN_START sample={sample_id}\\n'; "
        f"{runtime}; "
        "rc=$?; "
        f"printf 'RVMT_BENIGN_DONE sample={sample_id} rc=%s\\n' \"$rc\""
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
        "--program-command",
        program_command,
        "--post-read-until",
        done_token,
        "--post-read-loose-required",
        "RVMT_BENIGN_DONE",
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
    if rc != 0 or (not args.dry_run and not rep_is_pass(rep_dir)):
        raise RuntimeError(f"{sample_id}: board capture failed with {rc}")
    return rep_dir


def annotate_sample_class(path: Path, sample_id: str) -> None:
    data = load_json(path)
    data["sample_id"] = sample_id
    data["sample_class"] = "benign"
    data["network_required"] = False
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def recover_and_audit(root: Path, sample_dir: Path, sample_id: str, rep_dir: Path, code_map: Path, args: argparse.Namespace) -> None:
    recover_dir = sample_dir / "behavior"
    recover_cmd = [
        sys.executable,
        "tools/recover_behavior.py",
        "--trace",
        str(rep_dir / "bram_records.jsonl"),
        "--out-dir",
        str(recover_dir),
        "--code-map",
        str(code_map),
    ]
    rc = run_command(recover_cmd, cwd=root, dry_run=args.dry_run)
    if rc != 0:
        raise RuntimeError(f"{sample_id}: recover_behavior failed with {rc}")
    if not args.dry_run:
        annotate_sample_class(recover_dir / "semantic_events.json", sample_id)
        annotate_sample_class(recover_dir / "behavior_graph.json", sample_id)
    audit_dir = sample_dir / "audit"
    rc = run_command(
        [
            sys.executable,
            "tools/audit_behavior.py",
            "--semantic",
            str(recover_dir / "semantic_events.json"),
            "--graph",
            str(recover_dir / "behavior_graph.json"),
            "--manifest",
            str(args.manifest),
            "--sample-id",
            sample_id,
            "--out-dir",
            str(audit_dir),
        ],
        cwd=root,
        dry_run=args.dry_run,
    )
    if rc != 0:
        raise RuntimeError(f"{sample_id}: audit_behavior failed with {rc}")
    if not args.dry_run:
        annotate_sample_class(audit_dir / "behavior_audit.json", sample_id)
        # Packager looks in the sample directory recursively, but keep stable top-level copies.
        for source, target_name in (
            (recover_dir / "semantic_events.json", "semantic_events.json"),
            (recover_dir / "behavior_graph.json", "behavior_graph.json"),
            (audit_dir / "behavior_audit.json", "behavior_audit.json"),
        ):
            (sample_dir / target_name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")


def write_capture_manifest(root: Path, sample_dir: Path, sample_id: str, command_text: str, rep_dir: Path, begin_marker: str, end_marker: str, binary: Path, code_map: Path) -> None:
    summary = load_json(rep_dir / "bram_summary.json")
    bram = summary.get("bram_ring") if isinstance(summary.get("bram_ring"), dict) else {}
    write_json(
        sample_dir / "board_capture_manifest.json",
        {
            "schema": "rvmt.genesys2.board_benign_capture.v1",
            "id": sample_id,
            "genesys2_cva6_board_trace_claimed": True,
            "board_trace_claimed": True,
            "non_network": True,
            "network_required": False,
            "command": command_text,
            "binary": repo_rel(root, binary),
            "code_map": repo_rel(root, code_map),
            "marker_begin": begin_marker,
            "marker_end": end_marker,
            "marker_window_passed": summary.get("trigger_marker_seen") is True,
            "bram_summary": repo_rel(root, rep_dir / "bram_summary.json"),
            "bram_records": repo_rel(root, rep_dir / "bram_records.jsonl"),
            "event_count": int(bram.get("event_count", 0) or 0),
            "dropped_count": int(bram.get("dropped_count", 0) or 0),
            "wrap_count": int(bram.get("wrap_count", 0) or 0),
        },
    )


def run(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    args.run_root.mkdir(parents=True, exist_ok=True)
    selected = args.sample or list(BENIGN_SAMPLES)
    board_setup(root, args)
    for index, sample_id in enumerate(selected, start=1):
        sample_dir = args.run_root / sample_id
        sample_dir.mkdir(parents=True, exist_ok=True)
        begin_marker, end_marker = marker_pair(index)
        binary, code_map = build_benign_elf(root, sample_dir, sample_id, begin_marker, end_marker, args.dry_run)
        transfer_binary(
            root,
            binary,
            f"{args.binary_root.rstrip('/')}/{sample_id}",
            sample_dir / "01_board_transfer" / "binary_transfer.log",
            args,
        )
        if args.dry_run:
            continue
        rep_dir = capture_sample(root, sample_dir, sample_id, end_marker, args)
        recover_and_audit(root, sample_dir, sample_id, rep_dir, code_map, args)
        write_capture_manifest(root, sample_dir, sample_id, BENIGN_SAMPLES[sample_id], rep_dir, begin_marker, end_marker, binary, code_map)
    if args.dry_run:
        print("[PASS] dry run complete")
        return 0
    package = [sys.executable, "tools/package_genesys2_board_benign_control.py", "--root", str(root), "--run-root", str(args.run_root)]
    rc = run_command(package, cwd=root)
    if rc != 0:
        return rc
    check = [sys.executable, "tools/check_genesys2_board_benign_control.py", "--root", str(root)]
    rc = run_command(check, cwd=root)
    if rc != 0:
        return rc
    print("[PASS] Genesys2 board benign control packaged")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture Genesys2 board benign-control marker-window evidence.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--binary-root", default=DEFAULT_BINARY_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--sample", action="append", choices=list(BENIGN_SAMPLES))
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--hw-server-url", default="localhost:3121")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--prompt-token", default="# ")
    parser.add_argument("--transfer-chunk-lines", type=int, default=64)
    parser.add_argument("--transfer-chunk-read", type=float, default=5.0)
    parser.add_argument("--transfer-final-read", type=float, default=15.0)
    parser.add_argument("--transfer-line-delay", type=float, default=0.005)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--pre-read", type=float, default=0.1)
    parser.add_argument("--post-read", type=float, default=60.0)
    parser.add_argument("--arm-timeout", type=float, default=60.0)
    parser.add_argument("--process-wait-timeout", type=float, default=300.0)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--no-transfer", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    args.run_root = args.run_root if args.run_root.is_absolute() else args.root / args.run_root
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
