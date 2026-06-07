# Baseline Bring-up Runbook

Phase 4.3 ordered Genesys 2 baseline board procedure.

This runbook is a procedure, not a board-success record. Keep every observation
under `results/board/genesys2_baseline/<run-id>/` and stop at the first failed
mandatory step. Do not start trace-enabled board work from a failed or skipped
baseline step.

## Preconditions

Run these checks before touching the board:

```powershell
uv run rvmt vivado:check
uv run python tools/check_board_baseline.py
uv run python tools/check_vivado_authorization.py
```

Expected baseline bitstream:

```text
build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ariane_xilinx.bit
```

Hardware assumptions:

- Genesys 2 is powered from a stable supply.
- JTAG is visible to Vivado `hw_server`.
- UART is captured at 115200 baud, 8N1.
- No trace-enabled RTL or trace export path is added for this baseline run.

## Evidence Layout

Use one run directory:

```text
results/board/genesys2_baseline/<run-id>/
  01_led_clock_reset/
  02_uart_hello/
  03_minimal_core_boot/
  04_cva6_baremetal_boot/
  05_linux_boot_optional/
  run_notes.md
```

Each step directory should contain the command transcript, raw UART/JTAG logs
when applicable, and a short `observation.md` with `PASS`, `FAIL`, or `N/A` plus
the reason. `N/A` is allowed only for the optional Linux step or for a documented
missing minimal-core image.

## 1. LED Blink / Clock Reset Sanity

Evidence directory:

```text
results/board/genesys2_baseline/<run-id>/01_led_clock_reset/
```

Procedure:

1. Start `hw_server` and confirm the Genesys 2 JTAG target is visible.
2. Program the baseline bitstream. From `rtl/cva6/corev_apu/fpga`, use:

```powershell
$env:HW_SERVER_URL = "localhost:3121"
E:\vivado\2025.2\Vivado\bin\vivado.bat -mode batch -source scripts\program_genesys2.tcl
```

3. Observe reset release, stable clocks, and LEDs or other board-visible status
   signals after programming.

Pass evidence:

- Vivado programming transcript with `program_hw_devices` success.
- Board observation notes or photo showing stable post-program state.

## 2. UART Hello

Evidence directory:

```text
results/board/genesys2_baseline/<run-id>/02_uart_hello/
```

Procedure:

1. Open the Genesys 2 UART at 115200 baud, 8N1 before releasing reset or before
   the programmed image starts.
2. Capture the first deterministic UART output from the baseline design.
3. Record the exact serial port, baud rate, reset action, and timestamp.

Pass evidence:

- Raw UART log.
- Observation note identifying the first visible baseline output.

## 3. Minimal RISC-V Core Boot

Evidence directory:

```text
results/board/genesys2_baseline/<run-id>/03_minimal_core_boot/
```

Procedure:

1. Use the smallest available non-trace RISC-V hardware image for the board.
2. Boot a minimal program that reaches a clear end marker over UART, JTAG, or a
   documented board-visible signal.
3. If no separate minimal-core image exists in this repository, record `N/A`
   with the reason and do not treat this as a PASS.

Pass evidence:

- Program image identifier and build command.
- Raw UART/JTAG/observation log showing the end marker.

## 4. CVA6 Bare-metal Boot

Evidence directory:

```text
results/board/genesys2_baseline/<run-id>/04_cva6_baremetal_boot/
```

Procedure:

1. Confirm the programmed bitstream is the baseline CVA6 bitstream from the
   precondition section.
2. Boot a CVA6 bare-metal image with no trace modifications.
3. Capture the serial output or other board-visible end marker.

Pass evidence:

- Bare-metal program name and image checksum or build command.
- Raw UART/tohost/JTAG log showing the program reached its expected end state.

## 5. CVA6 Simple Linux Boot (Optional)

Evidence directory:

```text
results/board/genesys2_baseline/<run-id>/05_linux_boot_optional/
```

Procedure:

1. Prepare the SD or boot media expected by the upstream CVA6 FPGA bootrom.
2. Set `UART_SERIAL` to the board serial device.
3. Run the upstream UART monitor if the Linux image is available:

```powershell
$env:UART_SERIAL = "COMx"
python rtl\cva6\corev_apu\fpga\scripts\linux_boot.py
```

Pass evidence:

- `fpga_boot.rpt` or raw UART log containing the Linux boot banner.
- Kernel/rootfs image identifiers.

This step is optional for the MVP. If resources or boot media are not available,
record `N/A` and keep the baseline bring-up decision tied to steps 1 through 4.
