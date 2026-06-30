from __future__ import annotations

import argparse
import datetime as dt
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

from experiment_common import (
    repo_path,
    repo_rel,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/jtag_ram_boot_probe_summary.json")
DEFAULT_LOG = Path("results/evaluation/genesys2-cva6/current/jtag_ram_boot_probe.log")
DEFAULT_TCL = Path("tools/probe_genesys2_jtag_ram_boot.tcl")
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx")
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


def as_posix_path(path: Path) -> str:
    return str(path).replace("\\", "/")


def load_config(root: Path) -> dict[str, Any]:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return {}
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    tool = data.get("tool", {}) if isinstance(data, dict) else {}
    config = tool.get("rv-maltrace", {}) if isinstance(tool, dict) else {}
    return config if isinstance(config, dict) else {}


def resolve_path(root: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def vivado_command(config: dict[str, Any], root: Path, vivado_override: Path | None) -> Path:
    if vivado_override is not None:
        return resolve_path(root, vivado_override)
    return resolve_path(root, config.get("vivado", "vivado"))


def marker_map(output: str) -> dict[str, str]:
    markers: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("RVMT_") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        markers[key] = value
    return markers


def split_object_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [token for token in value.strip().split() if token]


def marker_bool(markers: dict[str, str], key: str) -> bool:
    return markers.get(key, "").strip().lower() in {"1", "true", "yes", "y"}


def marker_int(markers: dict[str, str], key: str) -> int | None:
    value = markers.get(key)
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def classify_status(returncode: int | None, markers: dict[str, str]) -> tuple[str, str | None]:
    if returncode is None:
        return "BLOCKED_JTAG_HW_SERVER_UNAVAILABLE", "Vivado did not complete the JTAG probe"
    if marker_int(markers, "RVMT_CONNECT_HW_SERVER_RC") not in (None, 0):
        return "BLOCKED_JTAG_HW_SERVER_UNAVAILABLE", markers.get("RVMT_CONNECT_HW_SERVER_ERR")
    if returncode == 22 or marker_int(markers, "RVMT_HW_TARGET_COUNT") == 0:
        return "BLOCKED_JTAG_TARGET_UNAVAILABLE", "Vivado hardware manager did not enumerate a JTAG target"
    if returncode == 24 or marker_int(markers, "RVMT_HW_DEVICE_COUNT") == 0:
        return "BLOCKED_JTAG_DEVICE_UNAVAILABLE", "Vivado hardware manager did not enumerate an FPGA device"
    if returncode == 25 or marker_int(markers, "RVMT_REFRESH_HW_DEVICE_RC") not in (None, 0):
        return "BLOCKED_JTAG_REFRESH_FAILED", markers.get("RVMT_REFRESH_HW_DEVICE_ERR")
    if returncode not in (0, None):
        return "BLOCKED_JTAG_HW_SERVER_UNAVAILABLE", f"Vivado JTAG probe exited {returncode}"
    axis = split_object_list(markers.get("RVMT_HW_AXIS"))
    axi = split_object_list(markers.get("RVMT_HW_AXI"))
    mems = split_object_list(markers.get("RVMT_HW_MEMS"))
    if axis or axi or mems:
        return PASS_STATUS, None
    return (
        BLOCKED_NO_MEMORY_CONTROL,
        "JTAG target/device are visible, but no Vivado hw_axis/hw_axi/hw_mem object was discovered for RAM writes or hart control",
    )


def build_summary(
    *,
    root: Path,
    vivado: Path,
    tcl: Path,
    ltx: Path,
    log: Path,
    hw_server_url: str,
    returncode: int | None,
    markers: dict[str, str],
    blocked_reason: str | None,
    status: str,
) -> dict[str, Any]:
    targets = split_object_list(markers.get("RVMT_HW_TARGETS"))
    devices = split_object_list(markers.get("RVMT_HW_DEVICES"))
    genesys_devices = split_object_list(markers.get("RVMT_XC7K325T_DEVICES"))
    ilas = split_object_list(markers.get("RVMT_HW_ILAS"))
    vios = split_object_list(markers.get("RVMT_HW_VIOS"))
    debug_cores = split_object_list(markers.get("RVMT_HW_DEBUG_CORES"))
    axis_objects = split_object_list(markers.get("RVMT_HW_AXIS"))
    axi_objects = split_object_list(markers.get("RVMT_HW_AXI"))
    mem_objects = split_object_list(markers.get("RVMT_HW_MEMS"))
    memory_control = bool(axis_objects or axi_objects or mem_objects)
    summary: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "generated_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
        "command": "uv run rvmt ndss:jtag-ram-boot-probe",
        "scope": "read-only Vivado hardware-manager inventory for remote JTAG RAM-boot feasibility",
        "vivado": {
            "path": as_posix_path(vivado),
            "exists": vivado.is_file() if vivado.suffix else None,
        },
        "tcl_script": {
            "path": repo_rel(root, tcl),
            "sha256": sha256_file(tcl) if tcl.is_file() else None,
        },
        "ltx_file": {
            "path": repo_rel(root, ltx),
            "exists": ltx.is_file(),
            "sha256": sha256_file(ltx) if ltx.is_file() else None,
        },
        "hw_server_url": hw_server_url,
        "returncode": returncode,
        "blocked_reason": blocked_reason,
        "log": {
            "path": repo_rel(root, log),
            "sha256": sha256_file(log) if log.is_file() else None,
            "size_bytes": log.stat().st_size if log.is_file() else None,
        },
        "markers": markers,
        "discovery": {
            "read_only_marker_observed": marker_bool(markers, "RVMT_READ_ONLY"),
            "no_program_reset_or_memory_write_marker_observed": marker_bool(
                markers, "RVMT_NO_PROGRAM_RESET_OR_MEMORY_WRITE"
            ),
            "targets": targets,
            "devices": devices,
            "genesys2_xc7k325t_devices": genesys_devices,
            "ilas": ilas,
            "vios": vios,
            "debug_cores": debug_cores,
            "hw_axis_objects": axis_objects,
            "hw_axi_objects": axi_objects,
            "hw_mem_objects": mem_objects,
            "hw_axi_commands": split_object_list(markers.get("RVMT_HW_AXI_COMMANDS")),
            "hw_axis_commands": split_object_list(markers.get("RVMT_HW_AXIS_COMMANDS")),
            "hw_mem_commands": split_object_list(markers.get("RVMT_HW_MEM_COMMANDS")),
            "jtag_target_observed": bool(targets),
            "fpga_device_observed": bool(devices),
            "genesys2_xc7k325t_observed": bool(genesys_devices),
            "ila_observed": bool(ilas),
            "memory_control_object_observed": memory_control,
        },
        "ram_boot_feasibility": {
            "ram_boot_feasible_now": status == PASS_STATUS,
            "can_program_memory_without_sdcard": status == PASS_STATUS,
            "hart_control_path_observed": bool(debug_cores),
            "requires_new_bitstream": not memory_control,
            "required_next_actions": [
                "Add or expose a Vivado-accessible JTAG-to-AXI or equivalent debug memory access path if no hw_axis/hw_axi/hw_mem object is present.",
                "Only after a memory-control object is observed, run a separate non-read-only RAM-load experiment with explicit reset/hart-control logging.",
                "Keep SD-card boot/kernel replacement claims blocked until the board actually boots the new payload and UART/JTAG artifacts are captured.",
            ],
        },
        "claim_boundary": {
            "vivado_hardware_manager_probe_executed": returncode is not None,
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
            "JTAG target, FPGA, or ILA visibility alone is not evidence that a kernel can be updated or booted without the SD card.",
            "A PASS status here only means a Vivado memory-control object was observed; it still does not claim a successful RAM boot.",
            "A BLOCKED status is an evidence-backed non-claim and must not be reported as a board or kernel PASS.",
        ],
        "validation_commands": [
            "uv run rvmt ndss:jtag-ram-boot-probe",
            "uv run python tools/check_genesys2_jtag_ram_boot_probe.py --root .",
            "uv run python tools/check_genesys2_jtag_ram_boot_probe.py --root . --require-ram-control",
        ],
    }
    return summary


def run_probe(root: Path, args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(root)
    vivado = vivado_command(config, root, args.vivado)
    tcl = repo_path(root, args.tcl)
    ltx = repo_path(root, args.ltx)
    log = repo_path(root, args.log)
    if not vivado.is_file():
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(f"Vivado executable not found: {vivado}\n", encoding="utf-8", newline="\n")
        markers: dict[str, str] = {}
        return build_summary(
            root=root,
            vivado=vivado,
            tcl=tcl,
            ltx=ltx,
            log=log,
            hw_server_url=args.hw_server_url,
            returncode=None,
            markers=markers,
            blocked_reason=f"Vivado executable not found: {vivado}",
            status="BLOCKED_HOST_VIVADO_NOT_FOUND",
        )
    if not tcl.is_file():
        raise FileNotFoundError(f"JTAG RAM boot probe Tcl not found: {tcl}")
    cmd = [
        str(vivado),
        "-mode",
        "batch",
        "-nojournal",
        "-nolog",
        "-notrace",
        "-source",
        str(tcl),
        "-tclargs",
        as_posix_path(ltx),
        args.hw_server_url,
    ]
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([str(vivado.parent), env.get("PATH", "")])
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(root),
            env=env,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=args.timeout_sec,
        )
        output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
        returncode = completed.returncode
    except subprocess.TimeoutExpired as exc:
        parts = [f"Vivado JTAG RAM boot probe timed out after {args.timeout_sec} seconds."]
        if exc.stdout:
            parts.append(str(exc.stdout))
        if exc.stderr:
            parts.append(str(exc.stderr))
        output = "\n".join(parts) + "\n"
        returncode = None
    except OSError as exc:
        output = f"failed to start Vivado: {exc}\n"
        returncode = None
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(output, encoding="utf-8", newline="\n")
    markers = marker_map(output)
    status, blocked_reason = classify_status(returncode, markers)
    return build_summary(
        root=root,
        vivado=vivado,
        tcl=tcl,
        ltx=ltx,
        log=log,
        hw_server_url=args.hw_server_url,
        returncode=returncode,
        markers=markers,
        blocked_reason=blocked_reason,
        status=status,
    )


def self_test() -> int:
    output = "\n".join(
        [
            "RVMT_READ_ONLY=1",
            "RVMT_NO_PROGRAM_RESET_OR_MEMORY_WRITE=1",
            "RVMT_HW_TARGETS=localhost:3121/xilinx_tcf/Digilent/210251A12345",
            "RVMT_HW_TARGET_COUNT=1",
            "RVMT_HW_DEVICES=xc7k325t_0",
            "RVMT_XC7K325T_DEVICES=xc7k325t_0",
            "RVMT_HW_DEVICE_COUNT=1",
            "RVMT_REFRESH_HW_DEVICE_RC=0",
            "RVMT_HW_ILAS=hw_ila_1",
            "RVMT_HW_AXIS=",
            "RVMT_HW_AXI=",
            "RVMT_HW_MEMS=",
        ]
    )
    markers = marker_map(output)
    status, reason = classify_status(0, markers)
    if status != BLOCKED_NO_MEMORY_CONTROL or not reason:
        print("[FAIL] expected no-memory-control fixture to block", file=sys.stderr)
        return 1
    markers["RVMT_HW_AXIS"] = "hw_axi_1"
    status, reason = classify_status(0, markers)
    if status != PASS_STATUS or reason is not None:
        print("[FAIL] expected hw_axis fixture to pass control-path discovery", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 JTAG RAM boot probe runner self-test")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a read-only Vivado/JTAG RAM-boot feasibility probe for Genesys2/CVA6.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--tcl", type=Path, default=DEFAULT_TCL)
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--vivado", type=Path, help="Override Vivado batch executable.")
    parser.add_argument("--hw-server-url", default="localhost:3121")
    parser.add_argument("--timeout-sec", type=int, default=300)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = repo_path(root, args.summary)
    data = run_probe(root, args)
    write_json(summary, data)
    print(f"[{data['status']}] wrote {summary}")
    if data.get("blocked_reason"):
        print(f"[BLOCKED] {data['blocked_reason']}")
    return 0 if data.get("status") == PASS_STATUS else 2


if __name__ == "__main__":
    raise SystemExit(main())
