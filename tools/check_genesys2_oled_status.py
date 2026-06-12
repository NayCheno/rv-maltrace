from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


OLED_RTL = Path("rtl/trace/rvmt_genesys2_oled_status.sv")
TRACE_RTL_F = Path("sim/vivado/trace_rtl.f")
FPGA_TOP = Path("rtl/cva6/corev_apu/fpga/src/ariane_xilinx.sv")
GENESYS2_XDC = Path("rtl/cva6/corev_apu/fpga/constraints/genesys-2.xdc")
CLI = Path("src/rv_maltrace/cli.py")


def read(root: Path, path: Path) -> str:
    full = root / path
    if not full.is_file():
        raise FileNotFoundError(path.as_posix())
    return full.read_text(encoding="utf-8", errors="replace")


def compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def check_oled_rtl(root: Path) -> list[str]:
    text = read(root, OLED_RTL)
    errors: list[str] = []
    for needle in (
        "module rvmt_genesys2_oled_status",
        "module rvmt_oled_spi_byte",
        "PHASE_RESET_TEXT",
        "PHASE_BOOTING_TEXT",
        "PHASE_LINUX_BOOT_TEXT",
        "PHASE_UART_XFER_TEXT",
        "PHASE_TESTING_TEXT",
        "PHASE_TRACE_CAP_TEXT",
        "PHASE_PTR_SNAP_TEXT",
        "PHASE_DONE_IDLE_TEXT",
        "AUTO HW STATUS",
        "MANUAL SW2:0",
        "function automatic [7:0] font5x7",
        "init_cmd = 8'hae",
        "spi_data <= 8'haf",
    ):
        require(errors, needle in text, f"{OLED_RTL}: missing {needle}")
    return errors


def check_top(root: Path) -> list[str]:
    text = read(root, FPGA_TOP)
    ctext = compact(text)
    errors: list[str] = []
    for port in ("oled_dc", "oled_res", "oled_sclk", "oled_sdin", "oled_vbat", "oled_vdd"):
        require(errors, port in text, f"{FPGA_TOP}: missing OLED port {port}")
    for needle in (
        "RVMT_OLED_PHASE_RESET",
        "RVMT_OLED_PHASE_BOOTING",
        "RVMT_OLED_PHASE_LINUX_BOOT",
        "RVMT_OLED_PHASE_UART_XFER",
        "RVMT_OLED_PHASE_TESTING",
        "RVMT_OLED_PHASE_TRACE_CAP",
        "RVMT_OLED_PHASE_PTR_SNAP",
        "RVMT_OLED_PHASE_DONE_IDLE",
        "rvmt_oled_manual_mode = sw[7]",
        "rvmt_genesys2_oled_status",
        ".CLK_HZ(50_000_000)",
    ):
        require(errors, needle in text, f"{FPGA_TOP}: missing OLED integration {needle}")
    for needle in (
        "assignrvmt_oled_rx_activity=rvmt_oled_rx_q^rx;",
        "assignrvmt_oled_tx_activity=rvmt_oled_tx_q^tx;",
        "rvmt_trace_packet.value[31:28]==4'hb",
        "rvmt_trace_packet.value[31:28]==4'he",
        "rvmt_trace_packet.evt==trace_pkg::EVT_ARG_MEM",
        "rvmt_oled_auto_phase<=RVMT_OLED_PHASE_UART_XFER;",
        "rvmt_oled_auto_phase<=RVMT_OLED_PHASE_LINUX_BOOT;",
        "rvmt_oled_auto_phase<=RVMT_OLED_PHASE_TESTING;",
        "rvmt_oled_auto_phase<=RVMT_OLED_PHASE_PTR_SNAP;",
    ):
        require(errors, needle in ctext, f"{FPGA_TOP}: missing OLED stage inference path {needle}")
    return errors


def check_constraints(root: Path) -> list[str]:
    text = read(root, GENESYS2_XDC)
    errors: list[str] = []
    expected = {
        "oled_dc": "AC17",
        "oled_res": "AB17",
        "oled_sclk": "AF17",
        "oled_sdin": "Y15",
        "oled_vbat": "AB22",
        "oled_vdd": "AG17",
    }
    for port, pin in expected.items():
        require(errors, f"PACKAGE_PIN {pin}" in text and f"get_ports {port}" in text, f"{GENESYS2_XDC}: missing {port} on {pin}")
    require(errors, "oled_vbat" in text and "LVCMOS33" in text, f"{GENESYS2_XDC}: OLED VBAT 3.3V constraint missing")
    return errors


def check_build_paths(root: Path) -> list[str]:
    trace_rtl = read(root, TRACE_RTL_F)
    cli = read(root, CLI)
    errors: list[str] = []
    require(errors, OLED_RTL.as_posix() in trace_rtl, f"{TRACE_RTL_F}: OLED RTL missing from Vivado trace filelist")
    require(errors, '"rtl/trace/rvmt_genesys2_oled_status.sv"' in cli, f"{CLI}: trace-marker source hash manifest must include OLED RTL")
    require(errors, "R:/rtl/trace/rvmt_genesys2_oled_status.sv" in cli, f"{CLI}: Vivado wrapper must inject OLED RTL into generated add_sources.tcl")
    return errors


def run_checks(root: Path) -> list[str]:
    errors: list[str] = []
    for check in (check_oled_rtl, check_top, check_constraints, check_build_paths):
        try:
            errors.extend(check(root))
        except Exception as exc:
            errors.append(str(exc))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2/CVA6 OLED progress status integration.")
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()

    root = args.root.resolve()
    errors = run_checks(root)
    if errors:
        print("[FAIL] Genesys2/CVA6 OLED progress status readiness", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("[PASS] Genesys2/CVA6 OLED progress status readiness")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
