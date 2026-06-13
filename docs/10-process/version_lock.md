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
- Linux userland compiler: `riscv64-linux-gnu-gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0` from Docker service `linux-behavior`.
- Linux userland binutils/source-line tools: `riscv64-linux-gnu-addr2line` and `riscv64-linux-gnu-readelf`, GNU Binutils for Ubuntu 2.42.
- Linux behavior runtime tools: `qemu-riscv64 version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.16)` and `strace -- version 6.8`.
- Docker toolchain config: `gcc-13.1.0-baremetal`
- Docker build script: `docker/toolchain/build-cva6-toolchain.sh`
- Docker service: `cva6-toolchain`
- Docker Linux behavior service: `linux-behavior` in `docker-compose.toolchain.yml`.
- Binutils source: `https://sourceware.org/git/binutils-gdb.git`, ref `binutils-2_40`.
- GCC source: `https://github.com/gcc-mirror/gcc.git`, ref `releases/gcc-13.1.0`.
- Newlib source: `https://sourceware.org/git/newlib-cygwin.git`, ref `newlib-4.3.0`.
- Local Windows PATH check: `riscv-none-elf-gcc`, `riscv-none-elf-objdump`, and `riscv-none-elf-objcopy` are not visible from the Windows shell PATH on 2026-05-08; use Docker or prepend the installed toolchain `bin` directory.

## Linux and Buildroot

- Status: Linux behavior container locked for the current controlled P0 and
  safe-surrogate workload claims; Buildroot Linux boot remains not claimed.
- Linux behavior container: Docker service `linux-behavior` from
  `docker/linux-behavior/Dockerfile`.
- Linux userland toolchain: `riscv64-linux-gnu-gcc` 13.3.0, GNU Binutils 2.42,
  `qemu-riscv64` 8.2.2, and `strace` 6.8 as listed above.
- Source-line probe: `results/evaluation/genesys2-cva6/current/source_line_toolchain_probe.json`
  records the debug/no-PIE `addr2line` path and separately records that current
  board ELFs lack DWARF debug sections.
- Buildroot version/commit: not locked for the current evidence package.
- Rootfs manifest: not present for a Buildroot boot claim.
- Gate: Buildroot kernel/rootfs anchors must still be fixed before claiming
  Buildroot Linux boot or a Buildroot-based paper evaluation. Current Linux
  syscall trace, semantic reconstruction, and source-line sidecar claims are
  scoped to controlled workloads and the locked `linux-behavior` toolchain.

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
- Fresh-clone current evidence reproduction entrypoint:
  `uv run python tools/reproduce_genesys2_current.py --quick` or `--full`.
- Lightweight artifact package manifest:
  `results/evaluation/genesys2-cva6/current/artifact_package_manifest.json`,
  checked by `uv run python tools/check_genesys2_artifact_package.py --root .`.
- CCF-A case-study manifest:
  `results/evaluation/genesys2-cva6/current/case_study_manifest.json`,
  checked by `uv run python tools/check_ccfa_case_study_manifest.py --root .`.
- External closure readiness contract:
  `results/evaluation/genesys2-cva6/current/external_closure_readiness.json`,
  checked by `uv run python tools/check_genesys2_external_closure_readiness.py --root .`.
- External closure intake gate:
  `results/evaluation/genesys2-cva6/current/external_closure_intake.json`,
  checked by `uv run python tools/check_genesys2_external_closure_intake.py --root .`.
- External closure execution plan:
  `results/evaluation/genesys2-cva6/current/external_closure_plan.json`,
  checked by `uv run python tools/check_genesys2_external_closure_plan.py --root .`.
