from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import official_image_evidence_common as common


ROOT = common.ROOT
SCHEMA = "rvmt.genesys2.official_image_fork_exec_ownership.v1"
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260625-official-image-fork-exec-ownership")
DEFAULT_OUT = common.CURRENT_ROOT / "official_image_fork_exec_ownership_summary.json"
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker-syscall/work-fpga/ariane_xilinx.ltx")
BEGIN = "0xb0000c02"
END = "0xe0000c02"
PID_MARKER_KIND_NAMES = {
    1: "parent_pid",
    2: "parent_tgid",
    3: "child_pid",
    4: "child_tgid",
    5: "child_pre_exec_pid",
    6: "child_pre_exec_tgid",
}
PID_MARKER_LINE_RE = re.compile(r"\bRVMT_PID_MARKER\s+label=(\S+)\s+kind=(\d+)\s+value=(-?\d+)(?:\s+marker=(0x[0-9a-fA-F]+))?")


def run(command: list[str], *, cwd: Path, dry_run: bool, allowed: set[int] | None = None) -> None:
    print("+ " + " ".join(command), flush=True)
    if dry_run:
        return
    completed = subprocess.run(command, cwd=cwd)
    if completed.returncode not in (allowed or {0}):
        raise subprocess.CalledProcessError(completed.returncode, command)


def fork_commands(target: str) -> list[str]:
    quoted = common.shell_quote(target)
    return [
        "rm -f /tmp/rvmt-fork-*; "
        f"{quoted} fork-ownership {BEGIN} {END} & rvmt_ppid=$!; "
        "rvmt_cf=/tmp/rvmt-fork-child-$rvmt_ppid; "
        "for i in $(seq 1 80); do [ -e $rvmt_cf ] && break; sleep 0.05; done; "
        "rvmt_cpid=$(cat $rvmt_cf 2>/dev/null); "
        "for i in $(seq 1 80); do [ -n \"$rvmt_cpid\" ] && [ -e /tmp/rvmt-fork-pre-ready-$rvmt_cpid ] && break; sleep 0.05; done; "
        "echo RVMT_FORK_HOST_PIDS parent=$rvmt_ppid child=$rvmt_cpid",
        "echo RVMT_PROC_SECTION_BEGIN parent_status_pre; cat /proc/$rvmt_ppid/status 2>&1; echo RVMT_PROC_SECTION_END parent_status_pre",
        "echo RVMT_PROC_SECTION_BEGIN parent_maps_pre; cat /proc/$rvmt_ppid/maps 2>&1; echo RVMT_PROC_SECTION_END parent_maps_pre",
        "echo RVMT_PROC_SECTION_BEGIN child_status_pre; cat /proc/$rvmt_cpid/status 2>&1; echo RVMT_PROC_SECTION_END child_status_pre",
        "echo RVMT_PROC_SECTION_BEGIN child_maps_pre; cat /proc/$rvmt_cpid/maps 2>&1; echo RVMT_PROC_SECTION_END child_maps_pre",
        "echo RVMT_PROC_SECTION_BEGIN child_exe_pre; readlink /proc/$rvmt_cpid/exe 2>&1; echo; sha256sum /proc/$rvmt_cpid/exe 2>&1; echo RVMT_PROC_SECTION_END child_exe_pre",
        "touch /tmp/rvmt-fork-continue-$rvmt_cpid; sleep 0.4",
        "echo RVMT_PROC_SECTION_BEGIN child_status_post; cat /proc/$rvmt_cpid/status 2>&1; echo RVMT_PROC_SECTION_END child_status_post",
        "echo RVMT_PROC_SECTION_BEGIN child_maps_post; cat /proc/$rvmt_cpid/maps 2>&1; echo RVMT_PROC_SECTION_END child_maps_post",
        "echo RVMT_PROC_SECTION_BEGIN child_exe_post; readlink /proc/$rvmt_cpid/exe 2>&1; echo; echo RVMT_PROC_SECTION_END child_exe_post",
        "wait $rvmt_ppid; rc=$?; printf 'RVMT_FORK_OWNERSHIP_%s parent=%s child=%s rc=%s\\n' HOST_DONE \"$rvmt_ppid\" \"$rvmt_cpid\" \"$rc\"",
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
            str(args.run_root / "fork_exec_transfer.log"),
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
    for item in fork_commands(args.target):
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
            "RVMT_FORK_OWNERSHIP_HOST_DONE",
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
            "official_image_fork_exec_ownership",
        ],
    )
    if not args.no_event_only_capture:
        command.insert(command.index("--ltx"), "--event-only-capture")
    run(
        command,
        cwd=ROOT,
        dry_run=args.dry_run,
    )


def pid_fields_present(records: list[dict[str, Any]]) -> bool:
    keys = {"pid", "tgid", "hart_pid", "process_id", "thread_id"}
    return any(keys & set(row) for row in records)


def arg_mem_text_payloads(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int, int], list[tuple[int, bytes]]] = {}
    for record in records:
        if record.get("evt") != "ARG_MEM":
            continue
        arg_index = common.int_value(record.get("arg_index_full") if record.get("arg_index_full") is not None else record.get("arg_index"))
        if arg_index != 1:
            continue
        syscall_id = str(record.get("syscall_id_full") or record.get("syscall_id") or "")
        base = common.int_value(record.get("mem_base_full") if record.get("mem_base_full") is not None else record.get("mem_base"))
        addr = common.int_value(record.get("mem_addr_full") if record.get("mem_addr_full") is not None else record.get("mem_addr"))
        data = common.int_value(record.get("mem_data_full") if record.get("mem_data_full") is not None else record.get("mem_data"))
        size = common.int_value(record.get("mem_size_full") if record.get("mem_size_full") is not None else record.get("mem_size"))
        if not syscall_id or base is None or addr is None or data is None:
            continue
        chunk_size = max(0, min(int(size or 8), 8))
        if chunk_size == 0:
            continue
        groups.setdefault((syscall_id, arg_index, base), []).append(
            (addr - base, int(data).to_bytes(8, "little", signed=False)[:chunk_size])
        )
    rows: list[dict[str, Any]] = []
    for (syscall_id, arg_index, base), chunks in groups.items():
        payload = b"".join(chunk for _, chunk in sorted(chunks))
        rows.append(
            {
                "syscall_id": syscall_id,
                "arg_index": arg_index,
                "mem_base": f"0x{base:016x}",
                "text": payload.decode("utf-8", errors="replace"),
                "source": "bram_arg_mem_stdout",
            }
        )
    return rows


def pid_marker_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        if record.get("evt") != "MARKER":
            continue
        value = common.int_value(record.get("packed_primary"))
        if value is None or ((value >> 28) & 0xF) != 0xD:
            continue
        kind = (value >> 24) & 0xF
        rows.append(
            {
                "sequence_number": record.get("sequence_number"),
                "kind": kind,
                "name": PID_MARKER_KIND_NAMES.get(kind, f"unknown_{kind}"),
                "value": value & 0x00FFFFFF,
                "marker": f"0x{value:08x}",
                "source": "bram_marker_event",
            }
        )
    for payload in arg_mem_text_payloads(records):
        for match in PID_MARKER_LINE_RE.finditer(str(payload.get("text") or "")):
            kind = int(match.group(2))
            row = {
                "sequence_number": None,
                "kind": kind,
                "name": PID_MARKER_KIND_NAMES.get(kind, f"unknown_{kind}"),
                "raw_label": match.group(1),
                "value": int(match.group(3)),
                "marker": match.group(4),
                "source": payload.get("source"),
                "syscall_id": payload.get("syscall_id"),
            }
            rows.append(row)
    return rows


def pid_marker_values(markers: list[dict[str, Any]]) -> dict[str, set[int]]:
    values: dict[str, set[int]] = {}
    for marker in markers:
        name = str(marker.get("name") or "")
        if not name or name.startswith("unknown_"):
            continue
        values.setdefault(name, set()).add(int(marker.get("value") or 0))
    return values


def marker_pid_pairing_ok(markers: list[dict[str, Any]], parent: int | None, child: int | None) -> bool:
    if parent is None or child is None:
        return False
    values = pid_marker_values(markers)
    return (
        parent in values.get("parent_pid", set())
        and parent in values.get("parent_tgid", set())
        and child in values.get("child_pid", set())
        and child in values.get("child_tgid", set())
        and child in values.get("child_pre_exec_pid", set())
        and child in values.get("child_pre_exec_tgid", set())
    )


def package_summary(run_root: Path, out: Path, build_manifest: Path, target: str) -> dict[str, Any]:
    uart = run_root / "uart.log"
    text = uart.read_text(encoding="utf-8", errors="replace") if uart.is_file() else ""
    sections = common.extract_sections(text)
    proc_artifacts = common.write_section_files(run_root, run_root / "proc_snapshots" / "fork_exec", sections)
    host_done = common.parse_pid_kv(text, "RVMT_FORK_OWNERSHIP_HOST_DONE")
    probe_done = common.parse_pid_kv(text, "RVMT_FORK_OWNERSHIP_DONE")
    host_pids = common.parse_pid_kv(text, "RVMT_FORK_HOST_PIDS")
    parent_pid = host_pids.get("parent") or host_done.get("parent") or probe_done.get("parent_pid")
    child_pid = host_pids.get("child") or host_done.get("child") or probe_done.get("child_pid")
    records = common.load_jsonl(run_root / "bram_records.jsonl")
    bram_summary = common.load_json(run_root / "bram_summary.json") if (run_root / "bram_summary.json").is_file() else {}
    ring = common.bram_ring(bram_summary)
    pre_child_maps = common.parse_maps(sections.get("child_maps_pre", ""))
    post_child_maps = common.parse_maps(sections.get("child_maps_post", ""))
    parent_maps = common.parse_maps(sections.get("parent_maps_pre", ""))
    has_pid = pid_fields_present(records)
    pid_markers = pid_marker_records(records)
    marker_pid_ok = marker_pid_pairing_ok(pid_markers, parent_pid, child_pid)
    child_pre_probe = "official_image_probe" in sections.get("child_exe_pre", "")
    child_post_busybox = "/bin/busybox" in sections.get("child_exe_post", "")
    completion_rc = host_done.get("rc") if host_done.get("rc") is not None else probe_done.get("rc")
    base_ok = completion_rc == 0 and ring["event_count"] > 0 and ring["dropped_count"] == 0 and ring["wrap_count"] == 0
    if base_ok and (has_pid or marker_pid_ok) and child_pre_probe and child_post_busybox:
        status = "PASS"
        blocked_reason = None
    elif base_ok and not has_pid:
        status = "BLOCKED_TRACE_PID_TGID_NOT_EXPOSED_IN_BRAM_RECORDS"
        blocked_reason = "current BRAM payload records hardware events and PCs but does not expose PID/TGID and did not capture the marker-assisted PID/TGID boundary records"
    else:
        status = "BLOCKED_FORK_EXEC_RUNTIME_CAPTURE_INCOMPLETE"
        blocked_reason = "fork/exec runtime snapshots or drop-free hardware marker-window capture were incomplete"
    summary = {
        "schema": SCHEMA,
        "status": status,
        "run_root": common.repo_rel(run_root),
        "target": target,
        "marker_window": {"begin": BEGIN, "end": END},
        "pids": {
            "parent": parent_pid,
            "child": child_pid,
        },
        "host_done": host_done,
        "probe_done": probe_done,
        "bram_ring": ring,
        "sequence_gap_count": common.sequence_gap_count(records),
        "trace_pid_tgid_fields_present": has_pid,
        "trace_pid_tgid_marker_fields_present": marker_pid_ok,
        "pid_tgid_markers": pid_markers,
        "runtime_snapshots": {
            "parent_map_entry_count": len(parent_maps),
            "child_pre_exec_map_entry_count": len(pre_child_maps),
            "child_post_exec_map_entry_count": len(post_child_maps),
            "child_pre_exec_exe_matches_probe": child_pre_probe,
            "child_post_exec_exe_matches_busybox": child_post_busybox,
        },
        "artifacts": {
            "uart_log": common.file_row(uart),
            "capture_csv": common.file_row(run_root / "capture.csv"),
            "capture_log": common.file_row(run_root / "capture.log"),
            "capture_err_log": common.file_row(run_root / "capture.err.log"),
            "bram_records": common.file_row(run_root / "bram_records.jsonl"),
            "bram_summary": common.file_row(run_root / "bram_summary.json"),
            "transfer_log": common.file_row(run_root / "fork_exec_transfer.log"),
            "build_manifest": common.file_row(build_manifest),
            "proc_snapshots": proc_artifacts,
        },
        "blocked_reason": blocked_reason,
        "claim_boundary": {
            "fork_exec_process_ownership_claimed": status == "PASS",
            "runtime_proc_snapshots_captured": bool(sections),
            "hardware_pid_tgid_required_for_strict_pairing": status != "PASS" and not marker_pid_ok,
            "marker_assisted_pid_tgid_pairing": marker_pid_ok,
            "runtime_map_inference_not_promoted_to_pid_pairing": status != "PASS",
            "qemu_or_strace_substitution_used": False,
            "cycle_level_overhead_claimed": False,
            "real_malware_validation_claimed": False,
        },
        "non_claims": [
            "Marker-assisted PID/TGID pairing is scoped to this controlled probe and is not a claim that the hardware independently recovers Linux scheduler task IDs for arbitrary workloads.",
            "This benign fork/exec probe is not real-malware validation.",
        ],
    }
    common.write_json(out, summary)
    return summary


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-fork-owner-") as tmp:
        root = Path(tmp)
        old_root = common.ROOT
        try:
            common.ROOT = root
            run_root = root / "run"
            run_root.mkdir()
            build = root / "build.json"
            common.write_json(build, {})
            (run_root / "uart.log").write_text(
                "RVMT_FORK_HOST_PIDS parent=10 child=11\n"
                "RVMT_PROC_SECTION_BEGIN child_exe_pre\n/tmp/rvmt_official/official_image_probe\nRVMT_PROC_SECTION_END child_exe_pre\n"
                "RVMT_PROC_SECTION_BEGIN child_exe_post\n/bin/busybox\nRVMT_PROC_SECTION_END child_exe_post\n"
                "RVMT_PROC_SECTION_BEGIN parent_maps_pre\n00010000-00020000 r-xp 0 00:01 1 /tmp/rvmt_official/official_image_probe\nRVMT_PROC_SECTION_END parent_maps_pre\n"
                "RVMT_PROC_SECTION_BEGIN child_maps_pre\n00010000-00020000 r-xp 0 00:01 1 /tmp/rvmt_official/official_image_probe\nRVMT_PROC_SECTION_END child_maps_pre\n"
                "RVMT_PROC_SECTION_BEGIN child_maps_post\n00030000-00040000 r-xp 0 00:01 2 /bin/busybox\nRVMT_PROC_SECTION_END child_maps_post\n"
                "RVMT_FORK_OWNERSHIP_HOST_DONE parent=10 child=11 rc=0\n",
                encoding="utf-8",
            )
            common.write_json(run_root / "bram_summary.json", {"bram_ring": {"event_count": 3, "dropped_count": 0, "wrap_count": 0}})
            (run_root / "bram_records.jsonl").write_text('{"evt":"SYSCALL_ENTRY","sequence_number":1}\n', encoding="utf-8")
            out = root / "summary.json"
            summary = package_summary(run_root, out, build, "/tmp/rvmt_official/official_image_probe")
            if summary.get("status") != "BLOCKED_TRACE_PID_TGID_NOT_EXPOSED_IN_BRAM_RECORDS":
                print("[FAIL] fork/exec fixture should block on missing PID/TGID fields", file=sys.stderr)
                return 1
            marker_records = []
            marker_lines = [
                "RVMT_PID_MARKER label=fork_parent_pid kind=1 value=10 marker=0xd100000a\n",
                "RVMT_PID_MARKER label=fork_parent_tgid kind=2 value=10 marker=0xd200000a\n",
                "RVMT_PID_MARKER label=fork_child_pid kind=3 value=11 marker=0xd300000b\n",
                "RVMT_PID_MARKER label=fork_child_tgid kind=4 value=11 marker=0xd400000b\n",
                "RVMT_PID_MARKER label=fork_child_pre_exec_pid kind=5 value=11 marker=0xd500000b\n",
                "RVMT_PID_MARKER label=fork_child_pre_exec_tgid kind=6 value=11 marker=0xd600000b\n",
            ]
            sequence = 1
            for syscall_index, line in enumerate(marker_lines, start=1):
                base = 0x1000 + syscall_index * 0x100
                payload = line.encode("utf-8")
                for offset in range(0, len(payload), 8):
                    chunk = payload[offset:offset + 8]
                    marker_records.append(
                        {
                            "evt": "ARG_MEM",
                            "arg_index_full": 1,
                            "syscall_id_full": f"0x{syscall_index:08x}",
                            "mem_base_full": f"0x{base:016x}",
                            "mem_addr_full": f"0x{base + offset:016x}",
                            "mem_data_full": f"0x{int.from_bytes(chunk.ljust(8, b'\0'), 'little'):016x}",
                            "mem_size_full": len(chunk),
                            "sequence_number": sequence,
                        }
                    )
                    sequence += 1
            (run_root / "bram_records.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in marker_records),
                encoding="utf-8",
            )
            summary = package_summary(run_root, root / "summary-pass.json", build, "/tmp/rvmt_official/official_image_probe")
        finally:
            common.ROOT = old_root
    if summary.get("status") != "PASS" or summary.get("trace_pid_tgid_marker_fields_present") is not True:
        print("[FAIL] fork/exec fixture should pass with marker-assisted PID/TGID fields", file=sys.stderr)
        return 1
    print("[PASS] official-image fork/exec ownership packager self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture and package official-image fork/exec ownership evidence.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--build-manifest", type=Path, default=common.DEFAULT_BUILD_MANIFEST)
    parser.add_argument("--target", default=common.DEFAULT_TARGET)
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--hw-server-url", default="localhost:3121")
    parser.add_argument("--timeout-seconds", type=int, default=160)
    parser.add_argument("--pre-read", type=float, default=0.2)
    parser.add_argument("--post-read", type=float, default=16.0)
    parser.add_argument("--arm-timeout", type=float, default=60.0)
    parser.add_argument("--process-wait-timeout", type=float, default=220.0)
    parser.add_argument(
        "--no-event-only-capture",
        action="store_true",
        help="Use a normal ILA capture window instead of BASIC event-only capture.",
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
