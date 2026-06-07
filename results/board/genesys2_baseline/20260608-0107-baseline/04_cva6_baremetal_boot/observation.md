Status: PASS

# Genesys2 CVA6 Phase 4 Bare-Metal Observation

Run ID: 20260608-0107-baseline
Timestamp: 2026-06-08 03:00 Asia/Shanghai

## Evidence

- `program_build.log`: records the configured `uv run rvmt baremetal:build` failure from missing host `riscv-none-elf-gcc`, then the recovery build of a 126-byte UART marker payload in the Docker cva6-toolchain container with Ubuntu `riscv64-unknown-elf-*` packages.
- `program_manifest.txt`: records the payload source, linker, build directory, hashes, load address, transfer method, and trace boundary.
- `program_during_uart_update.log`: Vivado reprogrammed the baseline `ariane_xilinx.bit` through on-board JTAG and reported `RVMT_PROGRAM_DONE=xc7k325t_0`.
- `serial_or_tohost.log`: COM6 captured boot ROM `Hello World!`, update entry, size `0000007E`, transfer `done!`, and three `RVMT_BAREMETAL_PASS` lines.
- `uart_bootrom_update.py`: evidence-local loader used to open COM6 before programming, enter boot ROM UART update mode, pace the payload bytes, and require the PASS marker.

## Resolved Issues

- The configured host `riscv-none-elf-*` toolchain was unavailable, so the marker payload was built with the container-local `riscv64-unknown-elf-*` toolchain and fully hash-recorded.
- No external CVA6 DMI JTAG wiring or SD boot media was needed for this Phase 4 gate; the existing FPGA boot ROM UART update path loaded the payload at `0x80000000`.
- The first update attempt missed a partially garbled prompt and the second overran the boot ROM RX FIFO; the final run broadened prompt detection and paced payload bytes.

## Acceptance

The full Phase 4 gate passes. Baseline UART output is visible on the PMOD JC
USB-TTL path, the non-trace CVA6 baseline bitstream was reprogrammed through
JTAG, the boot ROM accepted the bare-metal image over COM6, and the payload
reached the expected board-visible `RVMT_BAREMETAL_PASS` end marker.
