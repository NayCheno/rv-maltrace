from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    repo_path,
    require,
    sha256_file,
    write_json,
)


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/jtag_ram_boot_probe_summary.json")
SCHEMA = "rvmt.genesys2.jtag_ram_boot_probe.v1"
PASS_STATUS = "PASS_JTAG_RAM_BOOT_CONTROL_PATH_OBSERVED"
BLOCKED_NO_MEMORY_CONTROL = "BLOCKED_JTAG_RAM_BOOT_NO_MEMORY_CONTROL"
BLOCKED_STATUSES = {
    "BLOCKED_HOST_VIVADO_NOT_FOUND",
    "BLOCKED_JTAG_HW_SERVER_UNAVAILABLE",
    "BLOCKED_JTAG_TARGET_UNAVAILABLE",
    "BLOCKED_JTAG_DEVICE_UNAVAILABLE",
    "BLOCKED_JTAG_REFRESH_FAILED",
    BLOCKED_NO_MEMORY_CONTROL,
}
ACCEPTED_STATUSES = {PASS_STATUS, *BLOCKED_STATUSES}


def check_artifact_hash(errors: list[str], root: Path, row: dict[str, Any], label: str, *, required: bool = True) -> None:
    path_value = row.get("path")
    require(errors, isinstance(path_value, str) and bool(path_value), f"{label}.path missing")
    if not isinstance(path_value, str) or not path_value:
        return
    path = repo_path(root, path_value)
    if required:
        require(errors, path.is_file(), f"{label} missing: {path_value}")
    if not path.is_file():
        return
    expected_hash = row.get("sha256")
    require(errors, isinstance(expected_hash, str) and len(expected_hash) == 64, f"{label}.sha256 missing")
    require(errors, expected_hash == sha256_file(path), f"{label}.sha256 mismatch")
    if "size_bytes" in row:
        require(errors, int(row.get("size_bytes") or -1) == path.stat().st_size, f"{label}.size_bytes mismatch")


def check_manifest(data: dict[str, Any], root: Path, *, require_ram_control: bool = False) -> list[str]:
    errors: list[str] = []
    status = data.get("status")
    require(errors, data.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    require(errors, status in ACCEPTED_STATUSES, "status must be PASS or an accepted BLOCKED JTAG RAM-boot status")
    if require_ram_control:
        require(errors, status == PASS_STATUS, f"status must be {PASS_STATUS} when --require-ram-control is used")
    require(errors, data.get("command") == "uv run rvmt ndss:jtag-ram-boot-probe", "command must record rvmt entrypoint")
    require(
        errors,
        data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current",
        "canonical evaluation root mismatch",
    )

    vivado = as_dict(data.get("vivado"))
    require(errors, isinstance(vivado.get("path"), str) and bool(vivado.get("path")), "vivado.path missing")
    if status != "BLOCKED_HOST_VIVADO_NOT_FOUND":
        require(errors, vivado.get("exists") is True, "vivado.exists must be true unless Vivado is the blocker")
    check_artifact_hash(errors, root, as_dict(data.get("tcl_script")), "tcl_script")
    ltx = as_dict(data.get("ltx_file"))
    require(errors, isinstance(ltx.get("path"), str) and bool(ltx.get("path")), "ltx_file.path missing")
    if ltx.get("exists") is True:
        check_artifact_hash(errors, root, ltx, "ltx_file", required=True)
    check_artifact_hash(errors, root, as_dict(data.get("log")), "log")

    markers = as_dict(data.get("markers"))
    discovery = as_dict(data.get("discovery"))
    boundary = as_dict(data.get("claim_boundary"))
    ram = as_dict(data.get("ram_boot_feasibility"))
    target_seen = bool(as_list(discovery.get("targets")))
    device_seen = bool(as_list(discovery.get("devices")))
    memory_control = discovery.get("memory_control_object_observed") is True
    axis_objects = as_list(discovery.get("hw_axis_objects"))
    axi_objects = as_list(discovery.get("hw_axi_objects"))
    mem_objects = as_list(discovery.get("hw_mem_objects"))

    require(errors, isinstance(markers, dict), "markers missing")
    if status not in {"BLOCKED_HOST_VIVADO_NOT_FOUND", "BLOCKED_JTAG_HW_SERVER_UNAVAILABLE"}:
        require(errors, discovery.get("read_only_marker_observed") is True, "read-only marker missing")
        require(
            errors,
            discovery.get("no_program_reset_or_memory_write_marker_observed") is True,
            "no-program/reset/write marker missing",
        )
    require(errors, discovery.get("jtag_target_observed") is target_seen, "jtag target observation mismatch")
    require(errors, discovery.get("fpga_device_observed") is device_seen, "FPGA device observation mismatch")
    require(errors, memory_control == bool(axis_objects or axi_objects or mem_objects), "memory-control object mismatch")

    if status == PASS_STATUS:
        require(errors, data.get("returncode") == 0, "PASS requires Vivado returncode 0")
        require(errors, target_seen, "PASS requires JTAG target")
        require(errors, device_seen, "PASS requires FPGA device")
        require(errors, memory_control, "PASS requires a hw_axis/hw_axi/hw_mem object")
        require(errors, ram.get("ram_boot_feasible_now") is True, "PASS must mark ram_boot_feasible_now true")
        require(errors, ram.get("can_program_memory_without_sdcard") is True, "PASS must mark can_program_memory_without_sdcard true")
        require(errors, data.get("blocked_reason") is None, "PASS must not carry blocked_reason")
    elif status == BLOCKED_NO_MEMORY_CONTROL:
        require(errors, data.get("returncode") == 0, "no-memory-control blocker requires successful read-only Vivado probe")
        require(errors, target_seen, "no-memory-control blocker requires target visibility")
        require(errors, device_seen, "no-memory-control blocker requires FPGA device visibility")
        require(errors, not memory_control, "no-memory-control blocker must not list memory-control objects")
        require(errors, ram.get("ram_boot_feasible_now") is False, "blocked summary must mark ram_boot_feasible_now false")
        require(errors, isinstance(data.get("blocked_reason"), str) and bool(data.get("blocked_reason")), "blocked reason missing")
    elif status == "BLOCKED_JTAG_TARGET_UNAVAILABLE":
        require(errors, not target_seen, "target-unavailable status must not claim target visibility")
    elif status == "BLOCKED_JTAG_DEVICE_UNAVAILABLE":
        require(errors, target_seen, "device-unavailable status requires target visibility")
        require(errors, not device_seen, "device-unavailable status must not claim device visibility")

    require(errors, boundary.get("read_only_inventory") is True, "read_only_inventory boundary missing")
    require(errors, boundary.get("fpga_programmed") is False, "must not claim FPGA programming")
    require(errors, boundary.get("fpga_reset") is False, "must not claim FPGA reset")
    require(errors, boundary.get("memory_write_performed") is False, "must not claim memory write")
    require(errors, boundary.get("hart_control_performed") is False, "must not claim hart control")
    require(errors, boundary.get("ram_boot_attempted") is False, "must not claim RAM boot attempt")
    require(errors, boundary.get("ram_boot_succeeded") is False, "must not claim RAM boot success")
    require(errors, boundary.get("sdcard_modified") is False, "must not claim SD-card modification")
    require(errors, boundary.get("genesys2_board_boot_claimed") is False, "must not claim board boot")
    require(errors, boundary.get("new_kernel_or_image_booted") is False, "must not claim new kernel/image boot")

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "read-only" in non_claims, "non_claims must state read-only scope")
    require(errors, "not a ram-load" in non_claims or "not a ram" in non_claims, "non_claims must reject RAM-load evidence")
    require(errors, "not evidence" in non_claims and "boot" in non_claims, "non_claims must reject boot evidence")
    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "rvmt ndss:jtag-ram-boot-probe" in commands, "validation command missing rvmt probe")
    require(errors, "check_genesys2_jtag_ram_boot_probe.py --root ." in commands, "validation command missing checker")
    require(errors, "--require-ram-control" in commands, "validation command missing RAM-control requirement")
    return errors


def fixture_summary(root: Path, *, status: str) -> dict[str, Any]:
    tcl = root / "tools/probe_genesys2_jtag_ram_boot.tcl"
    ltx = root / "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx"
    log = root / "results/evaluation/genesys2-cva6/current/jtag_ram_boot_probe.log"
    tcl.parent.mkdir(parents=True, exist_ok=True)
    ltx.parent.mkdir(parents=True, exist_ok=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    tcl.write_text("puts RVMT_READ_ONLY=1\n", encoding="utf-8")
    ltx.write_text("RVMT-LTX\n", encoding="utf-8")
    log.write_text(
        "RVMT_READ_ONLY=1\n"
        "RVMT_NO_PROGRAM_RESET_OR_MEMORY_WRITE=1\n"
        "RVMT_HW_TARGETS=localhost:3121/xilinx_tcf/Digilent/210251A12345\n"
        "RVMT_HW_DEVICES=xc7k325t_0\n",
        encoding="utf-8",
    )
    memory_control = status == PASS_STATUS
    return {
        "schema": SCHEMA,
        "status": status,
        "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
        "command": "uv run rvmt ndss:jtag-ram-boot-probe",
        "vivado": {"path": "D:/Application/vivado/2025.2/Vivado/bin/vivado.bat", "exists": True},
        "tcl_script": {
            "path": "tools/probe_genesys2_jtag_ram_boot.tcl",
            "sha256": sha256_file(tcl),
        },
        "ltx_file": {
            "path": "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx",
            "exists": True,
            "sha256": sha256_file(ltx),
        },
        "hw_server_url": "localhost:3121",
        "returncode": 0,
        "blocked_reason": None if memory_control else "fixture no memory control",
        "log": {
            "path": "results/evaluation/genesys2-cva6/current/jtag_ram_boot_probe.log",
            "sha256": sha256_file(log),
            "size_bytes": log.stat().st_size,
        },
        "markers": {
            "RVMT_READ_ONLY": "1",
            "RVMT_NO_PROGRAM_RESET_OR_MEMORY_WRITE": "1",
            "RVMT_HW_TARGETS": "localhost:3121/xilinx_tcf/Digilent/210251A12345",
            "RVMT_HW_DEVICES": "xc7k325t_0",
            "RVMT_HW_AXIS": "hw_axi_1" if memory_control else "",
        },
        "discovery": {
            "read_only_marker_observed": True,
            "no_program_reset_or_memory_write_marker_observed": True,
            "targets": ["localhost:3121/xilinx_tcf/Digilent/210251A12345"],
            "devices": ["xc7k325t_0"],
            "genesys2_xc7k325t_devices": ["xc7k325t_0"],
            "ilas": ["hw_ila_1"],
            "vios": [],
            "debug_cores": [],
            "hw_axis_objects": ["hw_axi_1"] if memory_control else [],
            "hw_axi_objects": [],
            "hw_mem_objects": [],
            "hw_axi_commands": [],
            "hw_axis_commands": ["get_hw_axis"],
            "hw_mem_commands": [],
            "jtag_target_observed": True,
            "fpga_device_observed": True,
            "genesys2_xc7k325t_observed": True,
            "ila_observed": True,
            "memory_control_object_observed": memory_control,
        },
        "ram_boot_feasibility": {
            "ram_boot_feasible_now": memory_control,
            "can_program_memory_without_sdcard": memory_control,
            "hart_control_path_observed": False,
            "requires_new_bitstream": not memory_control,
            "required_next_actions": ["fixture"],
        },
        "claim_boundary": {
            "vivado_hardware_manager_probe_executed": True,
            "read_only_inventory": True,
            "fpga_programmed": False,
            "fpga_reset": False,
            "memory_write_performed": False,
            "hart_control_performed": False,
            "ram_boot_attempted": False,
            "ram_boot_succeeded": False,
            "sdcard_modified": False,
            "genesys2_board_boot_claimed": False,
            "new_kernel_or_image_booted": False,
        },
        "non_claims": [
            "This is a read-only Vivado hardware-manager inventory, not a RAM-load or board-boot experiment.",
            "JTAG target visibility is not evidence that a kernel can boot without the SD card.",
        ],
        "validation_commands": [
            "uv run rvmt ndss:jtag-ram-boot-probe",
            "uv run python tools/check_genesys2_jtag_ram_boot_probe.py --root .",
            "uv run python tools/check_genesys2_jtag_ram_boot_probe.py --root . --require-ram-control",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-jtag-ram-boot-check-") as tmp:
        root = Path(tmp)
        blocked = fixture_summary(root, status=BLOCKED_NO_MEMORY_CONTROL)
        errors = check_manifest(blocked, root)
        if errors:
            print("[FAIL] blocked JTAG RAM boot fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        if not check_manifest(blocked, root, require_ram_control=True):
            print("[FAIL] blocked fixture accepted with --require-ram-control", file=sys.stderr)
            return 1
        passed = fixture_summary(root, status=PASS_STATUS)
        errors = check_manifest(passed, root, require_ram_control=True)
        if errors:
            print("[FAIL] RAM-control fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        passed["claim_boundary"]["memory_write_performed"] = True
        if not check_manifest(passed, root):
            print("[FAIL] memory-write overclaim fixture accepted", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 JTAG RAM boot probe checker self-test")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check Genesys2/CVA6 read-only JTAG RAM-boot feasibility evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--require-ram-control", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = repo_path(root, args.summary)
    if not summary.is_file():
        print(f"[FAIL] missing JTAG RAM boot probe summary: {summary}", file=sys.stderr)
        return 1
    try:
        errors = check_manifest(load_json(summary), root, require_ram_control=args.require_ram_control)
    except Exception as exc:
        print(f"[FAIL] JTAG RAM boot probe checker error: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("[FAIL] JTAG RAM boot probe summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] JTAG RAM boot probe summary accepted: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
