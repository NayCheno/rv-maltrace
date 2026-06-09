Status: PASS

# Genesys2 CVA6 Phase 4 UART Hello Observation

Run ID: 20260609-1440-onboard-uart-reroute
Timestamp: 2026-06-09 15:58 +08:00

## Evidence

- serial.log: COM7 captured the onboard USB-UART baseline output while the board was reprogrammed with the non-trace baseline bitstream.
- The log contains Hello World!, the update-mode prompt, SPI and SD initialization, GPT partition entries, and copying boot image progress.
- The capture was started before JTAG programming so the baseline boot transcript was not missed.

## Acceptance

Phase 4 UART visibility passes on the onboard COM7 path. Baseline CVA6 output is visible through the board FTDI USB-UART after programming the onboard-UART baseline bitstream.
