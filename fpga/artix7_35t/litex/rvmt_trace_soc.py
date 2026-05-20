#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    raise RuntimeError("could not find repository root")


ROOT = repo_root()
LOLV = ROOT / "vendor" / "litex" / "linux-on-litex-vexriscv"
CPU_NETLIST = (
    ROOT
    / "vendor"
    / "litex"
    / "pythondata-cpu-vexriscv_smp"
    / "pythondata_cpu_vexriscv_smp"
    / "verilog"
    / "VexRiscvLitexSmpCluster_Cc1_Iw32Is4096Iy1_Dw32Ds4096Dy1_ITs4DTs4_Ood_Wm.v"
)

for path in (
    ROOT / "fpga" / "artix7_35t" / "litex",
    LOLV,
    ROOT / "vendor" / "litex" / "migen",
    ROOT / "vendor" / "litex" / "litex",
    ROOT / "vendor" / "litex" / "litex-boards",
    ROOT / "vendor" / "litex" / "litedram",
    ROOT / "vendor" / "litex" / "pythondata-cpu-vexriscv_smp",
):
    sys.path.insert(0, str(path))

from litex.soc.cores.cpu.vexriscv_smp import VexRiscvSMP
from litex.soc.integration.builder import Builder
from litex_boards.targets import embedfire_rise_pro
from rvmt_trace import RVMTTraceRing
from rvmt_trace_patch import patch_trace_gateware
from soc_linux import SoCLinux


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RV-MalTrace minimal trace SoC for EmbedFire A35T.")
    parser.add_argument("--variant", default="a7-35")
    parser.add_argument("--sys-clk-freq", default=50e6, type=float)
    parser.add_argument("--uart-baudrate", default=115200, type=float)
    parser.add_argument("--rootfs", choices=("ram0", "mmcblk0p2"), default="ram0")
    parser.add_argument("--trace-depth", default=256, type=int)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--load", action="store_true")
    parser.add_argument("--no-compile-software", action="store_true")
    parser.add_argument("--integrated-rom-init")
    parser.add_argument("--skip-dts", action="store_true")
    parser.add_argument("--vivado", default=os.environ.get("RVMT_VIVADO", "vivado"))
    VexRiscvSMP.args_fill(parser)
    return parser.parse_args()


def run_vivado(vivado: str, gateware_dir: Path) -> None:
    subprocess.check_call(
        [vivado, "-mode", "batch", "-source", "embedfire_rise_pro.rvmt_trace.tcl"],
        cwd=gateware_dir,
    )


def main() -> int:
    args = parse_args()
    os.chdir(LOLV)
    VexRiscvSMP.args_read(args)
    VexRiscvSMP.wishbone_memory = True
    VexRiscvSMP.hardware_breakpoints = 0

    soc_kwargs = {
        "variant": args.variant,
        "sys_clk_freq": int(args.sys_clk_freq),
        "uart_baudrate": int(args.uart_baudrate),
        "uart_name": "serial",
        "integrated_rom_size": 0x10000,
        "integrated_sram_size": 0x1800,
        "l2_size": 2048,
        "with_led_chaser": False,
        "with_beeper": False,
    }
    if args.integrated_rom_init:
        soc_kwargs["integrated_rom_init"] = args.integrated_rom_init

    soc = SoCLinux(embedfire_rise_pro.BaseSoC, **soc_kwargs)
    soc.submodules.rvmt_trace = RVMTTraceRing(depth=args.trace_depth)
    soc.csr.add("rvmt_trace", n=8)
    soc.add_constant("RVMT_TRACE_ENTRY_WORDS", 16)
    soc.add_constant("RVMT_TRACE_DEPTH", args.trace_depth)
    builder = Builder(
        soc,
        output_dir="build/embedfire_rise_pro_trace",
        bios_console="lite",
        csr_json="build/embedfire_rise_pro_trace/csr.json",
        csr_csv="build/embedfire_rise_pro_trace/csr.csv",
        compile_gateware=False,
        compile_software=not args.no_compile_software,
    )
    builder.build(run=False, build_name="embedfire_rise_pro")
    patched_cpu = patch_trace_gateware(Path(builder.gateware_dir), CPU_NETLIST)
    print(f"RVMT_TRACE_PATCHED_CPU={patched_cpu}")

    if not args.skip_dts:
        soc.generate_dts("embedfire_rise_pro", args.rootfs)
        soc.compile_dts("embedfire_rise_pro")
        soc.combine_dtb("embedfire_rise_pro")
        shutil.copyfile(f"images/boot_{args.rootfs}.json", "images/boot.json")

    if args.build:
        run_vivado(args.vivado, Path(builder.gateware_dir))
    if args.load:
        soc.platform.create_programmer().load_bitstream(builder.get_bitstream_filename(mode="sram"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
