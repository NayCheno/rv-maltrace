from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import official_image_evidence_common as common


ROOT = common.ROOT
SCHEMA = "rvmt.genesys2.hardware_oracle_differential.v1"
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260625-official-image-hardware-oracle-differential")
DEFAULT_OUT = common.CURRENT_ROOT / "official_image_hardware_oracle_differential_summary.json"
DEFAULT_P0_SUMMARY = common.CURRENT_ROOT / "p0_bram_trace_summary.json"
DEFAULT_BINARY = Path("build/board/genesys2_cva6_p0_marker/hello_write/hello_write.riscv64")
SYSCALL_NAMES = {
    56: "openat",
    57: "close",
    62: "lseek",
    63: "read",
    64: "write",
    80: "fstat",
    93: "exit",
    94: "exit_group",
    1023: "rvmt_marker",
}


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def run_qemu(run_root: Path, binary: Path, *, service: str, dry_run: bool) -> int:
    qemu = run_root / "qemu"
    qemu.mkdir(parents=True, exist_ok=True)
    stdout = (qemu / "stdout.txt").as_posix()
    stderr = (qemu / "strace.txt").as_posix()
    rc = (qemu / "returncode.txt").as_posix()
    version = (qemu / "qemu.version.txt").as_posix()
    script = (
        f"qemu-riscv64 --version | head -n 1 > {shell_quote(version)} 2>&1 || true; "
        f"qemu-riscv64 -strace {shell_quote(binary.as_posix())} > {shell_quote(stdout)} 2> {shell_quote(stderr)}; "
        f"printf '%s\\n' \"$?\" > {shell_quote(rc)}"
    )
    command = ["docker", "compose", "-f", "docker-compose.toolchain.yml", "run", "--rm", service, "bash", "-lc", script]
    (qemu / "command.txt").write_text(" ".join(command) + "\n", encoding="utf-8")
    print("+ " + " ".join(command), flush=True)
    if dry_run:
        return 0
    completed = subprocess.run(command, cwd=ROOT)
    return completed.returncode


def parse_strace_names(path: Path) -> list[str]:
    names: list[str] = []
    if not path.is_file():
        return names
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        text = line.strip()
        match = re.match(r"^(?:\d+\s+)?([A-Za-z_][A-Za-z0-9_]*|\d+)\(", text)
        if not match:
            continue
        names.append(match.group(1))
    return names


def hardware_hello_row(p0: dict[str, Any]) -> dict[str, Any]:
    for sample in p0.get("samples", []):
        if isinstance(sample, dict) and sample.get("sample_id") == "hello_write":
            return sample
    return {}


def hardware_syscalls(records_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in common.load_jsonl(records_path):
        if record.get("evt") != "SYSCALL_ENTRY":
            continue
        number = common.int_value(record.get("packed_primary"))
        rows.append(
            {
                "sequence_number": record.get("sequence_number"),
                "pc": record.get("pc"),
                "number": number,
                "name": SYSCALL_NAMES.get(number or -1, f"sys_{number}" if number is not None else None),
                "provenance": "genesys2_bram_hardware_trace",
            }
        )
    return rows


def package_summary(run_root: Path, out: Path, p0_summary: Path, binary: Path) -> dict[str, Any]:
    p0 = common.load_json(p0_summary)
    hello = hardware_hello_row(p0)
    records_path = common.repo_path(ROOT, str((hello.get("artifacts") or {}).get("bram_records") or ""))
    binary_sha = common.sha256_file(binary)
    hardware_binary_sha = (hello.get("artifacts") or {}).get("binary_sha256")
    hw_syscalls = hardware_syscalls(records_path)
    qemu_dir = run_root / "qemu"
    qemu_strace = qemu_dir / "strace.txt"
    qemu_rc_path = qemu_dir / "returncode.txt"
    qemu_rc = None
    if qemu_rc_path.is_file():
        qemu_rc = common.int_value(qemu_rc_path.read_text(encoding="utf-8", errors="replace").strip())
    oracle_names = parse_strace_names(qemu_strace)
    hardware_names = [row["name"] for row in hw_syscalls if row.get("name")]
    common_names = sorted(set(hardware_names) & set(oracle_names))
    write_aligned = "write" in common_names
    exact_elf_match = bool(binary_sha and hardware_binary_sha and binary_sha == hardware_binary_sha)
    if qemu_rc == 0 and write_aligned and exact_elf_match:
        status = "PASS"
        blocked_reason = None
    elif qemu_rc is None:
        status = "BLOCKED_QEMU_ORACLE_UNAVAILABLE"
        blocked_reason = "qemu-riscv64 -strace oracle output is missing"
    else:
        status = "BLOCKED_HARDWARE_ORACLE_ALIGNMENT_INCOMPLETE"
        blocked_reason = "same-ELF hardware/QEMU oracle alignment did not meet the write-syscall baseline"
    summary = {
        "schema": SCHEMA,
        "status": status,
        "run_root": common.repo_rel(run_root),
        "sample_id": "hello_write",
        "hardware": {
            "p0_summary": common.file_row(p0_summary),
            "bram_records": common.file_row(records_path),
            "binary": common.file_row(binary),
            "binary_sha256": binary_sha,
            "summary_binary_sha256": hardware_binary_sha,
            "exact_elf_match": exact_elf_match,
            "syscalls": hw_syscalls,
        },
        "oracle": {
            "kind": "qemu-riscv64 -strace",
            "returncode": qemu_rc,
            "syscall_names": oracle_names,
            "artifacts": {
                "stdout": common.file_row(qemu_dir / "stdout.txt"),
                "strace": common.file_row(qemu_strace),
                "returncode": common.file_row(qemu_rc_path),
                "qemu_version": common.file_row(qemu_dir / "qemu.version.txt"),
                "command": common.file_row(qemu_dir / "command.txt"),
            },
        },
        "alignment": {
            "common_syscall_names": common_names,
            "write_syscall_aligned": write_aligned,
            "hardware_syscall_count": len(hw_syscalls),
            "oracle_syscall_count": len(oracle_names),
        },
        "blocked_reason": blocked_reason,
        "claim_boundary": {
            "hardware_oracle_alignment_claimed": status == "PASS",
            "qemu_strace_is_validation_oracle_only": True,
            "qemu_or_strace_substitutes_for_hardware_trace": False,
            "same_elf_required": True,
            "cycle_level_overhead_claimed": False,
            "real_malware_validation_claimed": False,
        },
        "non_claims": [
            "QEMU -strace is a validation oracle for the same benign ELF; it is not hardware evidence.",
            "The comparison checks syscall-name overlap and exact ELF identity, not cycle-level overhead or malware detection.",
        ],
    }
    common.write_json(out, summary)
    return summary


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-hw-oracle-") as tmp:
        root = Path(tmp)
        old_root = common.ROOT
        old_module_root = globals()["ROOT"]
        try:
            common.ROOT = root
            globals()["ROOT"] = root
            run_root = root / "run"
            qemu = run_root / "qemu"
            qemu.mkdir(parents=True)
            (qemu / "strace.txt").write_text("123 write(1,0x100,4) = 4\n", encoding="utf-8")
            (qemu / "stdout.txt").write_text("hi\n", encoding="utf-8")
            (qemu / "returncode.txt").write_text("0\n", encoding="utf-8")
            (qemu / "qemu.version.txt").write_text("qemu fixture\n", encoding="utf-8")
            (qemu / "command.txt").write_text("qemu\n", encoding="utf-8")
            binary = root / "hello.riscv64"
            binary.write_text("binary", encoding="utf-8")
            records = root / "records.jsonl"
            records.write_text('{"evt":"SYSCALL_ENTRY","packed_primary":"0x00000040","sequence_number":1,"pc":"0x10140"}\n', encoding="utf-8")
            p0 = root / "p0.json"
            common.write_json(p0, {"samples": [{"sample_id": "hello_write", "artifacts": {"bram_records": common.repo_rel(records, root), "binary_sha256": common.sha256_file(binary)}}]})
            summary = package_summary(run_root, root / "summary.json", p0, binary)
        finally:
            common.ROOT = old_root
            globals()["ROOT"] = old_module_root
    if summary.get("status") != "PASS":
        print("[FAIL] hardware/oracle fixture did not pass", file=sys.stderr)
        return 1
    print("[PASS] hardware/oracle differential packager self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run QEMU oracle and package same-ELF hardware/oracle differential evidence.")
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--p0-summary", type=Path, default=DEFAULT_P0_SUMMARY)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--service", default="linux-behavior")
    parser.add_argument("--skip-qemu", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    args.run_root.mkdir(parents=True, exist_ok=True)
    if not args.skip_qemu:
        run_qemu(args.run_root, args.binary, service=args.service, dry_run=args.dry_run)
    if args.dry_run:
        return 0
    summary = package_summary(args.run_root, args.out, args.p0_summary, args.binary)
    print(f"[{summary['status']}] wrote {args.out}")
    return 0 if summary["status"] == "PASS" or str(summary["status"]).startswith("BLOCKED_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
