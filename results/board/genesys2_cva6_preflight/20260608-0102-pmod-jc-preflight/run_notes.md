# Genesys2 CVA6 Preflight Run Notes

Run ID: 20260608-0102-pmod-jc-preflight

## Scope

Phase 0 board wiring and host preflight for the CVA6 Genesys 2 bring-up sequence.

## Tooling

- Vivado: `D:/Application/vivado/2025.2/Vivado/bin/vivado.bat`
- Vivado version observed in logs: 2025.2
- UART capture: pyserial through `uv run python`

## Hardware Connections

- Genesys 2 powered from external 12 V supply.
- On-board USB-JTAG connected and used by Vivado hardware manager.
- External 3.3 V USB-TTL connected to PMOD JC:
  - JC1 / AC26 / FPGA UART TX to USB-TTL RXD
  - JC2 / AJ27 / FPGA UART RX to USB-TTL TXD
  - GND common
  - USB-TTL VCC not connected

## Artifacts

- `jtag_scan.log`
- `uart_ttl_test_program.log`
- `uart_ttl_test_capture.log`
- `observation.md`

## Result

PASS. The board was visible over JTAG, the UART TTL test bitstream programmed successfully, and COM6 captured the test banner plus a `ping` echo.
