Status: PASS

# Genesys2 CVA6 Phase 4 UART Observation

Run ID: 20260608-0107-baseline
Timestamp: 2026-06-08 03:00 Asia/Shanghai

## Evidence

- `serial.log`: COM6 captured baseline CVA6 UART output at 115200 8N1 after the Phase 3 programmed bitstream was running.
- Captured text: `could not initialize sd... exiting`
- `../04_cva6_baremetal_boot/serial_or_tohost.log`: with COM6 opened before reprogramming, captured the deterministic boot ROM `Hello World!` and update prompt.

## Acceptance

The baseline UART sub-gate passes because deterministic CVA6 boot output is
visible through the PMOD JC USB-TTL path. The later Phase 4 bare-metal evidence
uses the same COM6 PMOD JC path and captures the `RVMT_BAREMETAL_PASS` marker.
