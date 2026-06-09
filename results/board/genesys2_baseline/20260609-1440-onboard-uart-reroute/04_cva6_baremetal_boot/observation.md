Status: PASS

# Genesys2 CVA6 Phase 4 Bare-Metal Observation

Run ID: 20260609-1440-onboard-uart-reroute
Timestamp: 2026-06-09 15:58 +08:00

## Evidence

- program_build.log: records an initial docker-daemon-unavailable attempt, then the successful container-local build of a 131-byte UART marker payload for onboard COM7.
- program_manifest.txt: records the payload source, linker, build directory, hashes, load address, transfer method, and trace boundary.
- program_during_uart_update.log: Vivado reprogrammed the baseline ariane_xilinx.bit through on-board JTAG and reported RVMT_PROGRAM_DONE=xc7k325t_0.
- serial_or_tohost.log: COM7 captured the final successful boot ROM update session, including updating!, size 00000083, transfer done!, and three RVMT_BAREMETAL_PASS lines tagged uart=onboard_com7.
- serial_or_tohost_false_autoboot_prompt.log and program_during_uart_update_false_autoboot_prompt.log preserve the first failed attempt where a generic any key matcher hit the U-Boot autoboot prompt too early.
- uart_bootrom_update.py: evidence-local loader used to open COM7 before programming, wait specifically for the boot ROM enter update mode prompt, pace the payload bytes, and require the PASS marker.

## Resolved Issues

- Docker was initially unavailable on the host; once the daemon was started, the container toolchain build completed successfully.
- The first update attempt matched the wrong prompt because onboard COM7 exposes both U-Boot autoboot text and the boot ROM update prompt. The loader was tightened to trigger only on enter update mode.
- After the prompt matcher fix, the final run entered update mode cleanly and loaded the payload to completion.

## Acceptance

The full Phase 4 gate passes on onboard COM7. Baseline UART output is visible on the board FTDI USB-UART path, the non-trace baseline bitstream was reprogrammed through JTAG, the boot ROM accepted the bare-metal image over COM7, and the payload reached the expected board-visible RVMT_BAREMETAL_PASS end marker.
