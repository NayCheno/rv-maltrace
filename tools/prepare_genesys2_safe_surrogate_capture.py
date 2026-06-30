from __future__ import annotations

import argparse
import base64
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    resolve,
    write_json,
)


DEFAULT_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
DEFAULT_RUN_ROOT = Path("results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610")
DEFAULT_COVERAGE = DEFAULT_RUN_ROOT / "safe_surrogate_manifest_coverage.json"
DEFAULT_OUT = DEFAULT_RUN_ROOT / "safe_surrogate_capture_plan.json"
DEFAULT_RUNTIME_ROOT = "/tmp/rvmt_p2"
TRACE_MARKER_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx")
SAFE_SAMPLE_CLASS = "malware_like_synthetic"
BOARD = "Digilent Genesys2"
CPU = "CVA6"
SYSCALL_NUMBERS = {
    "read": 63,
    "write": 64,
    "openat": 56,
    "close": 57,
    "clone": 220,
    "execve": 221,
    "waitid": 95,
    "mmap": 222,
    "mprotect": 226,
    "munmap": 215,
    "getdents64": 61,
    "ptrace": 117,
    "clock_gettime": 113,
    "rt_sigaction": 134,
    "exit": 93,
}


def display(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def samples_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest.get("samples")
    if not isinstance(rows, list):
        return {}
    return {row["id"]: row for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)}


def complete_samples_from_coverage(coverage: dict[str, Any]) -> set[str]:
    rows = coverage.get("samples")
    if not isinstance(rows, list):
        return set()
    return {
        str(row.get("sample_id"))
        for row in rows
        if isinstance(row, dict) and row.get("status") == "PASS_SAFE_SURROGATE_EVIDENCE_CHAIN"
    }


def shell_command_b64(command: str) -> str:
    return base64.b64encode(command.encode("utf-8")).decode("ascii")


def unique_syscalls(row: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for name in row.get("expected_syscalls", []):
        if isinstance(name, str) and name not in result:
            result.append(name)
    return result


def safe_manifest_errors(root: Path, sample_id: str, row: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if row.get("class") != SAFE_SAMPLE_CLASS:
        errors.append(f"{sample_id}: class must be {SAFE_SAMPLE_CLASS}")
    if row.get("real_malware") is not False:
        errors.append(f"{sample_id}: real_malware must be false")
    if row.get("destructive") is not False:
        errors.append(f"{sample_id}: destructive must be false")
    if row.get("network_required") is not False:
        errors.append(f"{sample_id}: network_required must be false")
    if row.get("provenance") != "repository_source":
        errors.append(f"{sample_id}: provenance must be repository_source")
    source = row.get("source")
    if not isinstance(source, str) or not resolve(root, Path(source)).is_file():
        errors.append(f"{sample_id}: source file missing")
    if "35t" in json.dumps(row, sort_keys=True).lower():
        errors.append(f"{sample_id}: current Genesys2 plan must not reference legacy board evidence")
    return errors


def command_join_trace(sample_dir: Path, root: Path) -> list[str]:
    return [
        "uv",
        "run",
        "python",
        "tools/join_trace_code_map.py",
        "--trace",
        display(sample_dir / "hardware_trace/trace.jsonl", root),
        "--code-map",
        display(sample_dir / "local_code_analysis/code_map.json", root),
        "--out",
        display(sample_dir / "local_code_analysis/source_attribution.json", root),
        "--summary-out",
        display(sample_dir / "local_code_analysis/source_attribution_summary.json", root),
    ]


def command_recover_behavior(sample_dir: Path, root: Path) -> list[str]:
    return [
        "uv",
        "run",
        "python",
        "tools/recover_behavior.py",
        "--trace",
        display(sample_dir / "hardware_trace/trace.jsonl", root),
        "--code-map",
        display(sample_dir / "local_code_analysis/code_map.json", root),
        "--out-dir",
        display(sample_dir / "behavior", root),
    ]


def command_audit_behavior(sample_dir: Path, sample_id: str, root: Path) -> list[str]:
    return [
        "uv",
        "run",
        "python",
        "tools/audit_behavior.py",
        "--semantic",
        display(sample_dir / "behavior/semantic_events.json", root),
        "--graph",
        display(sample_dir / "behavior/behavior_graph.json", root),
        "--manifest",
        display(root / DEFAULT_MANIFEST, root),
        "--sample-id",
        sample_id,
        "--out-dir",
        display(sample_dir / "malware_analysis/audit", root),
    ]


def command_package(
    *,
    sample_dir: Path,
    sample_id: str,
    source: str,
    runtime_path: str,
    binary: Path,
    root: Path,
    captures: list[dict[str, Any]] | None = None,
) -> list[str]:
    command = [
        "uv",
        "run",
        "python",
        "tools/package_genesys2_safe_surrogate_evidence.py",
        "--sample-dir",
        display(sample_dir, root),
        "--sample-id",
        sample_id,
        "--source",
        source,
        "--runtime-path",
        runtime_path,
        "--binary",
        display(binary, root),
    ]
    for capture in captures or []:
        command.extend(
            [
                "--capture",
                ",".join(
                    [
                        f"id={capture['id']}",
                        f"csv={capture['csv']}",
                        f"trace={capture['trace']}",
                        f"program={capture['program_log']}",
                        f"log={capture['capture_log']}",
                        f"trigger={capture['trigger']}",
                        f"validity={capture['validity']}",
                    ]
                ),
            ]
        )
    command.append("--update-run-summary")
    return command


def board_program_command(sample_id: str, capture_id: str, runtime_path: str) -> str:
    return (
        f"printf 'RVMT_P2_RUN_START sample={sample_id} capture={capture_id}\\n'; "
        f"{runtime_path}; "
        "rc=$?; "
        f"printf 'RVMT_P2_RUN_DONE sample={sample_id} capture={capture_id} rc=%s\\n' \"$rc\""
    )


def capture_plan(sample_dir: Path, sample_id: str, row: dict[str, Any], runtime_path: str, root: Path) -> list[dict[str, Any]]:
    raw_dir = sample_dir / "03_hardware_trace/raw_captures_warmup80m"
    captures: list[dict[str, Any]] = []
    for syscall_name in unique_syscalls(row):
        number = SYSCALL_NUMBERS.get(syscall_name)
        if number is None:
            continue
        capture_id = f"{syscall_name}_entry"
        csv = raw_dir / f"{capture_id}.csv"
        trace = raw_dir / f"{capture_id}.trace.jsonl"
        capture_log = raw_dir / f"{capture_id}_capture.log"
        capture_err = raw_dir / f"{capture_id}_capture.err.log"
        program_log = raw_dir / f"{capture_id}_program.log"
        command = board_program_command(sample_id, capture_id, runtime_path)
        captures.append(
            {
                "id": capture_id,
                "syscall": syscall_name,
                "syscall_number": number,
                "evt_hex": "4",
                "primary": f"{number:x}",
                "trigger": f"SYSCALL_ENTRY_a7_0x{number:x}",
                "validity": f"{sample_id}_{syscall_name}_entry_window",
                "csv": display(csv, root),
                "trace": display(trace, root),
                "capture_log": display(capture_log, root),
                "capture_err": display(capture_err, root),
                "program_log": display(program_log, root),
                "program_command": command,
                "program_command_b64": shell_command_b64(command),
                "ltx": display(root / TRACE_MARKER_LTX, root),
                "event_only_capture": True,
                "marker_scope_required": True,
                "command": [
                    "uv",
                    "run",
                    "python",
                    "tools/run_genesys2_ila_command_capture.py",
                    "--evt-hex",
                    "4",
                    "--primary",
                    f"{number:x}",
                    "--csv",
                    display(csv, root),
                    "--capture-log",
                    display(capture_log, root),
                    "--capture-err",
                    display(capture_err, root),
                    "--program-log",
                    display(program_log, root),
                    "--program-command-b64",
                    shell_command_b64(command),
                    "--event-only-capture",
                    "--ltx",
                    display(root / TRACE_MARKER_LTX, root),
                    "--decode-out",
                    display(trace, root),
                ],
            }
        )
    capture_id = "ret_any"
    csv = raw_dir / f"{capture_id}.csv"
    trace = raw_dir / f"{capture_id}.trace.jsonl"
    capture_log = raw_dir / f"{capture_id}_capture.log"
    capture_err = raw_dir / f"{capture_id}_capture.err.log"
    program_log = raw_dir / f"{capture_id}_program.log"
    command = board_program_command(sample_id, capture_id, runtime_path)
    captures.append(
        {
            "id": capture_id,
            "evt_hex": "5",
            "primary": "X",
            "trigger": "SYSCALL_RET_any",
            "validity": "return_event_unattributed_window_probe",
            "csv": display(csv, root),
            "trace": display(trace, root),
            "capture_log": display(capture_log, root),
            "capture_err": display(capture_err, root),
            "program_log": display(program_log, root),
            "program_command": command,
            "program_command_b64": shell_command_b64(command),
            "ltx": display(root / TRACE_MARKER_LTX, root),
            "event_only_capture": True,
            "marker_scope_required": True,
            "command": [
                "uv",
                "run",
                "python",
                "tools/run_genesys2_ila_command_capture.py",
                "--evt-hex",
                "5",
                "--primary",
                "X",
                "--csv",
                display(csv, root),
                "--capture-log",
                display(capture_log, root),
                "--capture-err",
                display(capture_err, root),
                "--program-log",
                display(program_log, root),
                "--program-command-b64",
                shell_command_b64(command),
                "--event-only-capture",
                "--ltx",
                display(root / TRACE_MARKER_LTX, root),
                "--decode-out",
                display(trace, root),
            ],
        }
    )
    return captures


def build_sample_plan(root: Path, run_root: Path, sample_id: str, row: dict[str, Any], compiler: str, readelf: str) -> dict[str, Any]:
    sample_dir = run_root / sample_id
    build_dir = sample_dir / "00_build_syscall_only"
    binary = build_dir / f"{sample_id}.riscv64"
    source = str(row["source"])
    runtime_path = f"{DEFAULT_RUNTIME_ROOT}/{sample_id}"
    captures = capture_plan(sample_dir, sample_id, row, runtime_path, root)
    build_command = [
        compiler,
        "-O2",
        "-static",
        "-o",
        display(binary, root),
        source,
    ]
    readelf_command = [readelf, "-h", display(binary, root)]
    deterministic_build_command = [
        "uv",
        "run",
        "python",
        "tools/build_genesys2_safe_syscall_elf.py",
        "--sample-id",
        sample_id,
        "--out-root",
        display(run_root, root),
        "--code-map",
    ]
    code_map_command = [
        "uv",
        "run",
        "python",
        "tools/build_code_map.py",
        "--elf",
        display(binary, root),
        "--sample-id",
        sample_id,
        "--source",
        source,
        "--binary-role",
        "linux_user_malware_like_synthetic",
        "--runtime-path",
        runtime_path,
        "--out-dir",
        display(sample_dir / "local_code_analysis", root),
    ]
    transfer_command = [
        "uv",
        "run",
        "python",
        "tools/serial_base64_transfer.py",
        "--port",
        "COM7",
        "--baud",
        "115200",
        "--source",
        display(binary, root),
        "--target",
        runtime_path,
        "--log",
        display(sample_dir / "02_board_transfer/serial_base64_transfer.log", root),
    ]
    return {
        "sample_id": sample_id,
        "status": "PLANNED_NOT_EVIDENCE",
        "sample_class": row.get("class"),
        "real_malware": False,
        "source": source,
        "sample_dir": display(sample_dir, root),
        "runtime_path": runtime_path,
        "binary": display(binary, root),
        "expected_syscalls": row.get("expected_syscalls", []),
        "expected_behavior": row.get("expected_behavior", []),
        "commands": {
            "build_syscall_only_binary": deterministic_build_command,
            "build_c_source_binary_if_toolchain_available": build_command,
            "record_compiler_if_available": [compiler, "--version"],
            "record_readelf_if_available": readelf_command,
            "build_code_map_if_external_binary_used": code_map_command,
            "transfer_to_board_com7": transfer_command,
            "capture_windows": [capture["command"] for capture in captures],
            "package_hardware_and_static": command_package(
                sample_dir=sample_dir,
                sample_id=sample_id,
                source=source,
                runtime_path=runtime_path,
                binary=binary,
                root=root,
                captures=captures,
            ),
            "join_trace_code_map": command_join_trace(sample_dir, root),
            "recover_behavior": command_recover_behavior(sample_dir, root),
            "audit_behavior": command_audit_behavior(sample_dir, sample_id, root),
            "finalize_integrated_validation": command_package(
                sample_dir=sample_dir,
                sample_id=sample_id,
                source=source,
                runtime_path=runtime_path,
                binary=binary,
                root=root,
            ),
        },
        "captures": captures,
        "required_final_artifacts": [
            "hardware_trace/trace.jsonl",
            "hardware_trace/trace_summary.json",
            "local_code_analysis/code_map.json",
            "local_code_analysis/static_analysis.json",
            "local_code_analysis/source_attribution.json",
            "malware_analysis/behavior_mapping.json or malware_analysis/behavior_report.md",
            "integrated_validation.json",
        ],
        "limitations": [
            "This plan is not hardware evidence.",
            "The deterministic build command creates syscall-shape safe surrogate ELFs; it does not compile or execute real malware.",
            "Each capture command must be run against the current Digilent Genesys2/CVA6 board over onboard JTAG and COM7 UART.",
            "The strict coverage gate must remain incomplete until decoded hardware traces and integrated validation are generated.",
        ],
    }


def build_plan(root: Path, manifest_path: Path, coverage_path: Path | None, run_root: Path, compiler: str, readelf: str, include_complete: bool) -> dict[str, Any]:
    manifest = load_json(resolve(root, manifest_path))
    rows = samples_by_id(manifest)
    complete: set[str] = set()
    coverage_rel = None
    if coverage_path is not None and resolve(root, coverage_path).is_file():
        coverage = load_json(resolve(root, coverage_path))
        complete = complete_samples_from_coverage(coverage)
        coverage_rel = display(resolve(root, coverage_path), root)
    toolchain = {
        "deterministic_syscall_builder": "tools/build_genesys2_safe_syscall_elf.py",
        "deterministic_syscall_builder_available": (root / "tools/build_genesys2_safe_syscall_elf.py").is_file(),
        "compiler": compiler,
        "compiler_available_on_path": shutil.which(compiler) is not None,
        "readelf": readelf,
        "readelf_available_on_path": shutil.which(readelf) is not None,
    }
    errors: list[str] = []
    sample_plans: list[dict[str, Any]] = []
    for sample_id in sorted(rows):
        row = rows[sample_id]
        errors.extend(safe_manifest_errors(root, sample_id, row))
        if not include_complete and sample_id in complete:
            continue
        sample_plans.append(build_sample_plan(root, run_root, sample_id, row, compiler, readelf))
    return {
        "schema": "rvmt.genesys2.safe_surrogate.capture_plan.v1",
        "status": "PLAN_NOT_EVIDENCE",
        "board": BOARD,
        "cpu": CPU,
        "manifest": display(resolve(root, manifest_path), root),
        "coverage": coverage_rel,
        "run_root": display(run_root, root),
        "planned_samples": [row["sample_id"] for row in sample_plans],
        "already_complete_samples": sorted(complete),
        "toolchain": toolchain,
        "errors": errors,
        "samples": sample_plans,
        "allowed_claims": [
            "This artifact is a reproducible Genesys2/CVA6 safe-surrogate capture plan for repository-authored synthetic samples.",
        ],
        "non_claims": [
            "No real malware validation is demonstrated.",
            "No real malware detection quality or efficacy is claimed.",
            "No real malware payload, source, or binary is introduced by this plan.",
            "Planned samples are not hardware evidence until decoded ILA traces and integrated validation artifacts exist.",
        ],
    }


def write_fixture(root: Path) -> tuple[Path, Path]:
    manifest = root / "manifest.json"
    coverage = root / "coverage.json"
    source_dir = root / "experiments/linux_behavior/malware_like/programs"
    source_dir.mkdir(parents=True)
    (source_dir / "alpha.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (source_dir / "beta.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    write_json(
        manifest,
        {
            "sample_class": SAFE_SAMPLE_CLASS,
            "samples": [
                {
                    "id": "alpha",
                    "class": SAFE_SAMPLE_CLASS,
                    "provenance": "repository_source",
                    "real_malware": False,
                    "destructive": False,
                    "network_required": False,
                    "source": "experiments/linux_behavior/malware_like/programs/alpha.c",
                    "expected_syscalls": ["write"],
                    "expected_behavior": ["alpha"],
                },
                {
                    "id": "beta",
                    "class": SAFE_SAMPLE_CLASS,
                    "provenance": "repository_source",
                    "real_malware": False,
                    "destructive": False,
                    "network_required": False,
                    "source": "experiments/linux_behavior/malware_like/programs/beta.c",
                    "expected_syscalls": ["openat", "read", "close"],
                    "expected_behavior": ["beta"],
                },
            ],
        },
    )
    write_json(
        coverage,
        {
            "schema": "fixture",
            "samples": [
                {"sample_id": "alpha", "status": "PASS_SAFE_SURROGATE_EVIDENCE_CHAIN"},
                {"sample_id": "beta", "status": "NOT_RUN"},
            ],
        },
    )
    return manifest, coverage


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest, coverage = write_fixture(root)
        plan = build_plan(root, manifest, coverage, root / "run", "riscv64-linux-gnu-gcc", "riscv64-linux-gnu-readelf", False)
        if plan["planned_samples"] != ["beta"]:
            print(f"[FAIL] self-test planned wrong samples: {plan['planned_samples']}", file=sys.stderr)
            return 1
        beta = plan["samples"][0]
        captures = beta["captures"]
        if [capture["id"] for capture in captures] != ["openat_entry", "read_entry", "close_entry", "ret_any"]:
            print("[FAIL] self-test generated wrong capture windows", file=sys.stderr)
            return 1
        for capture in captures:
            command = capture.get("command", [])
            if capture.get("event_only_capture") is not True or "--event-only-capture" not in command:
                print("[FAIL] self-test missed event-only capture requirement", file=sys.stderr)
                return 1
            if capture.get("marker_scope_required") is not True or "--ltx" not in command or "trace-marker" not in " ".join(command):
                print("[FAIL] self-test missed marker-scope LTX requirement", file=sys.stderr)
                return 1
        if "package_hardware_and_static" not in beta["commands"]:
            print("[FAIL] self-test missed package command", file=sys.stderr)
            return 1
        if plan["status"] != "PLAN_NOT_EVIDENCE":
            print("[FAIL] self-test overclaimed plan status", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 safe surrogate capture plan self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare a Genesys2/CVA6 safe-surrogate capture plan for incomplete P2 samples.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--coverage", type=Path, default=DEFAULT_COVERAGE)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--compiler", default="riscv64-linux-gnu-gcc")
    parser.add_argument("--readelf", default="riscv64-linux-gnu-readelf")
    parser.add_argument("--include-complete", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    try:
        root = args.root.resolve()
        plan = build_plan(root, args.manifest, args.coverage, resolve(root, args.run_root), args.compiler, args.readelf, args.include_complete)
        write_json(resolve(root, args.out), plan)
    except Exception as exc:
        print(f"prepare_genesys2_safe_surrogate_capture: error: {exc}", file=sys.stderr)
        return 2
    if plan["errors"]:
        for error in plan["errors"]:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print(f"[PASS] Genesys2/CVA6 safe surrogate capture plan written: {resolve(root, args.out)}")
    if not plan["toolchain"]["compiler_available_on_path"]:
        print(f"[WARN] compiler not on PATH: {args.compiler}")
    if not plan["toolchain"]["readelf_available_on_path"]:
        print(f"[WARN] readelf not on PATH: {args.readelf}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
