# Genesys2 CVA6 Phase 0 Observation

Status: PASS

Run ID: 20260608-0102-pmod-jc-preflight
Timestamp: 2026-06-08 01:02 Asia/Shanghai

## Hardware

- Board: Digilent Genesys 2, `xc7k325tffg900-2`
- Power: external 12 V supply connected
- JTAG: on-board Digilent USB-JTAG
- UART: external 3.3 V USB-TTL on PMOD JC
- UART wiring: JC1/AC26 to USB-TTL RXD, JC2/AJ27 to USB-TTL TXD, common GND, USB-TTL VCC not connected
- Serial port: COM6, 115200 8N1

## Evidence

- `jtag_scan.log`: Vivado opened the Digilent hardware target and reported `RVMT_HW_DEVICE=xc7k325t_0 PART=xc7k325t`, followed by `RVMT_GENESYS2_XC7K325T_FOUND`.
- `uart_ttl_test_program.log`: Vivado programmed the UART TTL test bitstream with `program_hw_devices`; startup status was HIGH.
- `uart_ttl_test_capture.log`: COM6 captured repeated `RVMT JC UART TEST` banners and echoed host-sent `ping`.

## Acceptance

Phase 0 passes because JTAG identifies the Genesys 2 Kintex-7 device, programming succeeds through on-board USB-JTAG, COM6 is available as the CH340 USB-TTL adapter, and PMOD JC UART traffic is bidirectional at 115200 8N1.
