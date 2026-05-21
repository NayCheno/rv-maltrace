# 35T Board Validation Preflight: 35t-targeted-board-validation-20260522

Status: READY_FOR_BOARD_RUN

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

Hardware ready: true

Hardware ready basis: requested UART port is visible through pyserial; this does not prove the 35T board image is running

## Runbook Checks

- schema: PASS
- source_run_id: PASS
- scope: PASS
- claim_level: PASS
- status: PASS
- trace_records: PASS
- trace_profile_policy: PASS
- phases: PASS
- hardware_required: PASS

## Required Scripts

- tools/experiment_35t.py: PASS
- tools/package_35t_board_validation.py: PASS
- tools/check_35t_board_validation.py: PASS
- tools/prepare_35t_board_validation_run.py: PASS

## Host Tools

- uv: PASS (uv 0.11.7 (9d177269e 2026-04-15 x86_64-pc-windows-msvc))
- python: PASS (Python 3.14.3)
- docker: PASS (Docker version 29.4.1, build 055a478)

## Serial Port

- pyserial: PASS
- requested port: `COM5`
- requested port visible: PASS
- available: COM3 (Standard Serial over Bluetooth link (COM3))
- available: COM13 (USB Serial Port (COM13))
- available: COM6 (USB-SERIAL CH340 (COM6))
- available: COM4 (Standard Serial over Bluetooth link (COM4))
- available: COM5 (USB-SERIAL CH340 (COM5))

## Result Paths

- results_root: results/experiments/35t/35t-targeted-board-validation-20260522
- results_root_exists: True
- bundle_root: results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle
- bundle_root_exists: True

## Warnings

- target validation results root already exists; inspect before overwriting or rerunning

## Failures

- none

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
