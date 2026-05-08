# Version Lock

This file captures the baseline versions used by the first commit-level
hardware behavior tracing MVP.

## CVA6

- Repository: `openhwgroup/cva6`
- Local path: `rtl/cva6`
- Commit: `e12d59f6f4a749dc70cc4d08938181ca40b3f343`
- Commit date: `2026-05-08T11:24:46+08:00`
- Commit subject: `Make FPGA wrapper compatible with Vivado 2025.2`

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

- Expected compiler: `riscv64-unknown-elf-gcc`
- Expected objdump: `riscv64-unknown-elf-objdump`
- Local compiler version: TODO, `riscv64-unknown-elf-gcc` is not currently visible from the Windows shell PATH.
- Local objdump version: TODO, `riscv64-unknown-elf-objdump` is not currently visible from the Windows shell PATH.
- Docker toolchain config: `gcc-13.1.0-baremetal`
- Docker service: `cva6-toolchain`

## Bare-metal Runtime

- Runtime source: TODO, MVP runtime/crt0 will live under `sim/programs/common/`.
- Linker script: TODO, MVP linker script will live under `sim/programs/common/linker.ld`.
- End-of-test ABI: MMIO tohost write at `0x10000000`.

## Testbench

- Repository: this repository.
- Commit: TODO until the first MVP implementation commit is created.
- Trace unit testbench: `sim/tb/tb_trace_top_unit.sv`.
- Future CVA6 execution testbench: TODO, planned path `sim/tb/tb_cva6_trace_top.sv`.
- Trace sink: `sim/tb/tb_trace_sink.sv`.
- Scoreboard: `sim/tb/tb_trace_scoreboard.sv`.

## Project Tools

- Python package: `rv-maltrace`
- Python package version: `0.1.0`
- Task entrypoint: `uv run rvmt`
- Checker version source: `tools/compare_trace.py`.
