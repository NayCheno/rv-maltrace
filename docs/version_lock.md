# Version Lock

This file captures the baseline versions used by the first commit-level
hardware behavior tracing MVP.

## CVA6

- Repository: `openhwgroup/cva6`
- Local path: `rtl/cva6`
- Upstream baseline commit: `e12d59f6f4a749dc70cc4d08938181ca40b3f343`
- Local submodule commit: `63a1417ad675b588f1a8ec02d315d27f4c4ab517`
- Local commit date: `2026-05-08T15:37:19+08:00`
- Local commit subject: `Add RV maltrace RVFI trace hook`

## Vivado

- Configured executable: `E:/vivado/2025.2/Vivado/bin/vivado.bat`
- Version: `Vivado v2025.2 (64-bit)`
- SW build: `6299465`
- IP build: `6300035`
- Simulator: `xsim`
- Board repository: `vendor/vivado-boards/new/board_files`
- Target board: `genesys2`
- Xilinx part: `xc7k325tffg900-2`
- Xilinx board part: `digilentinc.com:genesys2:part0:1.1`

## RISC-V Toolchain

- Expected compiler: `riscv-none-elf-gcc`
- Expected objdump: `riscv-none-elf-objdump`
- Expected objcopy: `riscv-none-elf-objcopy`
- Bare-metal build prefix: `riscv-none-elf-`
- Docker toolchain config: `gcc-13.1.0-baremetal`
- Docker build script: `docker/toolchain/build-cva6-toolchain.sh`
- Docker service: `cva6-toolchain`
- Binutils source: `https://sourceware.org/git/binutils-gdb.git`, ref `binutils-2_40`.
- GCC source: `https://github.com/gcc-mirror/gcc.git`, ref `releases/gcc-13.1.0`.
- Newlib source: `https://sourceware.org/git/newlib-cygwin.git`, ref `newlib-4.3.0`.
- Local Windows PATH check: `riscv-none-elf-gcc`, `riscv-none-elf-objdump`, and `riscv-none-elf-objcopy` are not visible from the Windows shell PATH on 2026-05-08; use Docker or prepend the installed toolchain `bin` directory.

## Bare-metal Runtime

- Runtime source: `sim/programs/common/crt0.S`, `sim/programs/common/finish.S`, and `sim/programs/common/trap_vector.S`.
- Linker script: `sim/programs/common/linker.ld`.
- End-of-test ABI: MMIO tohost write at `0x10000000`.

## Testbench

- Repository: this repository.
- Latest locked implementation commit: `cb31781c33107098b582dc32b51f46f3ba98b5ce`.
- Trace unit testbench: `sim/tb/tb_trace_top_unit.sv`.
- CVA6 RVFI adapter testbench: `sim/tb/tb_cva6_rvfi_trace_adapter.sv`.
- CVA6 direct-core xsim trace/no-trace testbench: `sim/tb/tb_cva6_direct_xsim_smoke.sv`.
- CVA6 direct-core DRAM images: `sim/programs/cva6_*/cva6_*.mem`.
- CVA6 full testharness xsim smoke testbench: `sim/tb/tb_cva6_xsim_smoke.sv`.
- Trace sink: `sim/tb/tb_trace_sink.sv`.
- Scoreboard: `sim/tb/tb_trace_scoreboard.sv`.

## Project Tools

- Python package: `rv-maltrace`
- Python package version: `0.1.0`
- Task entrypoint: `uv run rvmt`
- Checker version source: `tools/compare_trace.py`.
