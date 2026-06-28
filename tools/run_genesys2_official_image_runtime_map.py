from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import official_image_evidence_common as common


ROOT = common.ROOT
SCHEMA = "rvmt.genesys2.official_image_runtime_map.v1"
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260625-official-image-runtime-map")
DEFAULT_OUT = common.CURRENT_ROOT / "official_image_runtime_map_summary.json"
DEFAULT_LTX = common.DEFAULT_LTX
BEGIN = "0xb0000c01"
END = "0xe0000c01"


def run(command: list[str], *, cwd: Path, dry_run: bool, allowed: set[int] | None = None) -> None:
    print("+ " + " ".join(command), flush=True)
    if dry_run:
        return
    completed = subprocess.run(command, cwd=cwd)
    if completed.returncode not in (allowed or {0}):
        raise subprocess.CalledProcessError(completed.returncode, command)


def runtime_commands(target: str) -> list[str]:
    quoted = common.shell_quote(target)
    return [
        "rm -f /tmp/rvmt-map-ready-* /tmp/rvmt-map-continue-*; "
        f"{quoted} runtime-map {BEGIN} {END} static_exec & rvmt_pid=$!; "
        "for i in $(seq 1 80); do [ -e /tmp/rvmt-map-ready-$rvmt_pid ] && break; sleep 0.05; done; "
        "echo RVMT_RUNTIME_MAP_HOST_PID=$rvmt_pid",
        "echo RVMT_PROC_SECTION_BEGIN maps; cat /proc/$rvmt_pid/maps 2>&1; echo RVMT_PROC_SECTION_END maps",
        "echo RVMT_PROC_SECTION_BEGIN status; cat /proc/$rvmt_pid/status 2>&1; echo RVMT_PROC_SECTION_END status",
        "echo RVMT_PROC_SECTION_BEGIN stat; cat /proc/$rvmt_pid/stat 2>&1; echo RVMT_PROC_SECTION_END stat",
        "echo RVMT_PROC_SECTION_BEGIN cmdline; cat /proc/$rvmt_pid/cmdline 2>&1 | tr '\\000' ' '; echo; echo RVMT_PROC_SECTION_END cmdline",
        "echo RVMT_PROC_SECTION_BEGIN exe_readlink; readlink /proc/$rvmt_pid/exe 2>&1; echo RVMT_PROC_SECTION_END exe_readlink",
        "echo RVMT_PROC_SECTION_BEGIN exe_sha256; sha256sum /proc/$rvmt_pid/exe 2>&1; echo RVMT_PROC_SECTION_END exe_sha256",
        "touch /tmp/rvmt-map-continue-$rvmt_pid; wait $rvmt_pid; rc=$?; "
        "printf 'RVMT_RUNTIME_MAP_HOST_%s pid=%s rc=%s ready=1\n' DONE \"$rvmt_pid\" \"$rc\"",
    ]


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
            str(args.run_root / "runtime_map_transfer.log"),
            "--chunk-read",
            "0.25",
            "--final-read",
            "3.0",
            "--disable-echo",
        ],
        cwd=ROOT,
        dry_run=args.dry_run,
    )


def capture(args: argparse.Namespace) -> None:
    command = [
            sys.executable,
            "tools/run_genesys2_ila_command_capture.py",
            "--root",
            ".",
            "--evt-hex",
            "c",
            "--primary",
            END[2:],
            "--csv",
            str(args.run_root / "capture.csv"),
            "--timeout-seconds",
            str(args.timeout_seconds),
            "--trigger-position",
            "0",
            "--ltx",
            str(args.ltx),
            "--hw-server-url",
            args.hw_server_url,
            "--capture-log",
            str(args.run_root / "capture.log"),
            "--capture-err",
            str(args.run_root / "capture.err.log"),
            "--program-log",
            str(args.run_root / "uart.log"),
    ]
    if not args.no_event_only_capture:
        command.append("--event-only-capture")
    for item in runtime_commands(args.target):
        command.extend(["--program-command", item])
    command.extend(
        [
            "--port",
            args.port,
            "--baud",
            str(args.baud),
            "--pre-read",
            str(args.pre_read),
            "--between-read",
            "1.5",
            "--post-read",
            str(args.post_read),
            "--post-read-until",
            "RVMT_RUNTIME_MAP_HOST_DONE",
            "--arm-timeout",
            str(args.arm_timeout),
            "--process-wait-timeout",
            str(args.process_wait_timeout),
            "--bram-out-jsonl",
            str(args.run_root / "bram_records.jsonl"),
            "--bram-summary",
            str(args.run_root / "bram_summary.json"),
            "--bram-trigger-primary",
            END[2:],
            "--sample-id",
            "official_image_runtime_map",
        ],
    )
    run(
        command,
        cwd=ROOT,
        dry_run=args.dry_run,
    )


def package_summary(run_root: Path, out: Path, build_manifest: Path, target: str) -> dict[str, Any]:
    uart = run_root / "uart.log"
    uart_text = uart.read_text(encoding="utf-8", errors="replace") if uart.is_file() else ""
    sections = common.extract_sections(uart_text)
    pid_info = common.parse_pid_kv(uart_text, "RVMT_RUNTIME_MAP_HOST_DONE")
    host_pid = common.parse_pid_kv(uart_text, "RVMT_RUNTIME_MAP_HOST_PID").get("PID")
    if host_pid is None:
        for line in uart_text.splitlines():
            if line.strip().startswith("RVMT_RUNTIME_MAP_HOST_PID="):
                host_pid = common.int_value(line.strip().split("=", 1)[1])
                break
    proc_artifacts = common.write_section_files(run_root, run_root / "proc_snapshots" / str(host_pid or "unknown"), sections)
    maps = common.parse_maps(sections.get("maps", ""))
    records = common.load_jsonl(run_root / "bram_records.jsonl")
    bram_summary = common.load_json(run_root / "bram_summary.json") if (run_root / "bram_summary.json").is_file() else {}
    ring = common.bram_ring(bram_summary)
    attributions = common.pc_attributions(records, maps)
    variant = common.variant_row(build_manifest, "static_exec")
    board_sha = common.parse_sha256_line(sections.get("exe_sha256", ""))
    expected_sha = str(variant.get("binary_sha256") or "")
    exact_hash_match = bool(board_sha and expected_sha and board_sha == expected_sha)
    runtime_path_match = target in sections.get("exe_readlink", "") or "official_image_probe" in sections.get("exe_readlink", "")
    status = "PASS"
    blocked_reason = None
    if (
        pid_info.get("rc") != 0
        or not maps
        or ring["event_count"] <= 0
        or ring["dropped_count"] != 0
        or ring["wrap_count"] != 0
        or not attributions
        or not exact_hash_match
        or not runtime_path_match
    ):
        status = "BLOCKED_RUNTIME_MAP_PC_ATTRIBUTION_INCOMPLETE"
        blocked_reason = "runtime /proc maps, exact ELF hash, or drop-free hardware PC attribution was incomplete"
    summary = {
        "schema": SCHEMA,
        "status": status,
        "run_root": common.repo_rel(run_root),
        "board": "Digilent Genesys2",
        "cpu": "CVA6 rv64gc sv39",
        "marker_window": {"begin": BEGIN, "end": END},
        "target": target,
        "pid": host_pid,
        "uart_done": pid_info,
        "bram_ring": ring,
        "sequence_gap_count": common.sequence_gap_count(records),
        "runtime_maps": {"entry_count": len(maps), "executable_entry_count": sum(1 for row in maps if "x" in str(row.get("perms"))), "entries": maps[:64]},
        "pc_attributions": attributions,
        "exact_elf": {
            "build_manifest": common.file_row(build_manifest),
            "variant": "static_exec",
            "expected_sha256": expected_sha,
            "board_proc_exe_sha256": board_sha,
            "hash_match": exact_hash_match,
            "exe_readlink": sections.get("exe_readlink", "").strip(),
        },
        "artifacts": {
            "uart_log": common.file_row(uart),
            "capture_csv": common.file_row(run_root / "capture.csv"),
            "capture_log": common.file_row(run_root / "capture.log"),
            "capture_err_log": common.file_row(run_root / "capture.err.log"),
            "bram_records": common.file_row(run_root / "bram_records.jsonl"),
            "bram_summary": common.file_row(run_root / "bram_summary.json"),
            "transfer_log": common.file_row(run_root / "runtime_map_transfer.log"),
            "proc_snapshots": proc_artifacts,
            "bitstream": common.file_row(common.DEFAULT_BITSTREAM),
            "ltx": common.file_row(common.DEFAULT_LTX),
        },
        "blocked_reason": blocked_reason,
        "claim_boundary": {
            "board_runtime_pc_to_proc_map_attribution_claimed": status == "PASS",
            "provenance_exact_elf_hash_required": True,
            "runtime_proc_maps_are_board_observed": bool(maps),
            "qemu_or_strace_substitution_used": False,
            "cycle_level_overhead_claimed": False,
            "real_malware_validation_claimed": False,
        },
        "non_claims": [
            "This runtime-map evidence binds hardware PCs to live /proc maps for a benign official-image probe only.",
            "It does not claim DWARF source-line attribution or real-malware validation.",
            "QEMU/strace outputs are not used as a substitute for the board runtime map.",
        ],
    }
    common.write_json(out, summary)
    return summary


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-runtime-map-") as tmp:
        root = Path(tmp)
        old_root = common.ROOT
        try:
            common.ROOT = root
            run_root = root / "run"
            run_root.mkdir(parents=True)
            build = root / "build/manifest.json"
            common.write_json(build, {"variants": {"static_exec": {"binary_sha256": "a" * 64}}})
            (run_root / "uart.log").write_text(
                "RVMT_RUNTIME_MAP_HOST_PID=7\n"
                "RVMT_PROC_SECTION_BEGIN maps\n00010000-00020000 r-xp 00000000 00:01 1 /tmp/rvmt_official/official_image_probe\nRVMT_PROC_SECTION_END maps\n"
                "RVMT_PROC_SECTION_BEGIN exe_readlink\n/tmp/rvmt_official/official_image_probe\nRVMT_PROC_SECTION_END exe_readlink\n"
                "RVMT_PROC_SECTION_BEGIN exe_sha256\n" + ("a" * 64) + "  /proc/7/exe\nRVMT_PROC_SECTION_END exe_sha256\n"
                "RVMT_RUNTIME_MAP_HOST_DONE pid=7 rc=0 ready=1\n",
                encoding="utf-8",
            )
            common.write_json(run_root / "bram_summary.json", {"bram_ring": {"event_count": 2, "dropped_count": 0, "wrap_count": 0}})
            (run_root / "bram_records.jsonl").write_text('{"evt":"MARKER","pc":"0x00010100","sequence_number":0}\n', encoding="utf-8")
            out = root / "summary.json"
            summary = package_summary(run_root, out, build, "/tmp/rvmt_official/official_image_probe")
        finally:
            common.ROOT = old_root
    if summary.get("status") != "PASS":
        print("[FAIL] runtime-map fixture did not pass", file=sys.stderr)
        return 1
    print("[PASS] official-image runtime-map packager self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture and package official-image runtime /proc map attribution evidence.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--build-manifest", type=Path, default=common.DEFAULT_BUILD_MANIFEST)
    parser.add_argument("--target", default=common.DEFAULT_TARGET)
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--hw-server-url", default="localhost:3121")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--pre-read", type=float, default=0.2)
    parser.add_argument("--post-read", type=float, default=12.0)
    parser.add_argument("--arm-timeout", type=float, default=60.0)
    parser.add_argument("--process-wait-timeout", type=float, default=180.0)
    parser.add_argument(
        "--no-event-only-capture",
        action="store_true",
        help="Capture the full ILA window instead of filtering to event records; useful when repeated trigger marks exceed event-only limits.",
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-transfer", action="store_true")
    parser.add_argument("--skip-capture", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    args.run_root.mkdir(parents=True, exist_ok=True)
    if not args.skip_build:
        run([sys.executable, "tools/build_genesys2_official_image_probe.py"], cwd=ROOT, dry_run=args.dry_run)
    if not args.skip_transfer:
        transfer_probe(args, common.static_binary_from_manifest(args.build_manifest))
    if not args.skip_capture:
        capture(args)
    if args.dry_run:
        return 0
    summary = package_summary(args.run_root, args.out, args.build_manifest, args.target)
    print(f"[{summary['status']}] wrote {args.out}")
    return 0 if summary["status"] == "PASS" or str(summary["status"]).startswith("BLOCKED_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
