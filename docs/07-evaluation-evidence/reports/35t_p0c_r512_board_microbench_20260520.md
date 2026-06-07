# 35T p0c r512 board microbench retest status - 2026-05-20

## Scope

- Run id: `35t-p0c-r512-board-semantic-fix-20260520-com5`
- Board target: real 35T/LiteX/VexRiscv UART run on `COM5` at `921600`
- Samples: `hello`, `batch_open_read_write`, `illegal_trap`, `anti_debug_like`
- Trace profile: `p0c_syscall_trap_drop`
- Trace records: `512`
- Runtime order: `abba`
- Warmup: `1`
- Reps: `5`
- Boundary: this is a four-sample p0c r512 microbench retest only. No full matrix was run, no case study was generated, and this report makes no CVA6 board, real malware detection, or mature detector claim.

The new run did not overwrite `35t-p0c-abba-r512-20260520-com5`. To satisfy bundle prerequisites without rerunning unrelated work, only the four selected samples' `build/` and `groundtruth/` directories were copied from `35t-p0c-abba-r512-20260520-com5`. No old `board/` artifacts were copied.

## Serial enumeration

Artifacts:

- `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/command_logs/serial_enumeration.log`

| Command | RC | Result |
| --- | ---: | --- |
| `Get-CimInstance Win32_SerialPort \| Select-Object DeviceID,Name,Description,PNPDeviceID \| Format-List` | 0 | Listed `COM3` and `COM4` Bluetooth serial ports only. |
| `[System.IO.Ports.SerialPort]::GetPortNames() \| Sort-Object` | 0 | Listed `COM13`, `COM3`, `COM4`, `COM5`, `COM6`. |
| `uv run python -` with `serial.tools.list_ports.comports()` | 0 | Confirmed `COM5` as `USB-SERIAL CH340 (COM5)`, VID:PID `1A86:7523`, location `1-2`; `COM6` is a second CH340 at location `1-12.1`. |

Board collection therefore used `COM5/921600` as requested.

## Run config

`results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/run_config.json`

```json
{
  "baud": 921600,
  "port": "COM5",
  "reps": 5,
  "run_id": "35t-p0c-r512-board-semantic-fix-20260520-com5",
  "runtime_order": "abba",
  "samples": [
    "hello",
    "batch_open_read_write",
    "illegal_trap",
    "anti_debug_like"
  ],
  "trace_profile": "p0c_syscall_trap_drop",
  "trace_records": 512,
  "warmup": 1
}
```

## Commands and return codes

| Step | Command | RC | Main artifacts |
| --- | --- | ---: | --- |
| Offline prerequisites | `Copy-Item` four selected samples' `build/` and `groundtruth/` from `results/experiments/35t/35t-p0c-abba-r512-20260520-com5` to the new run; no `board/` copy | 0 | `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/samples/*/*/{build,groundtruth}` |
| Board collect | `uv run python tools/experiment_35t.py --stage board --run-id 35t-p0c-r512-board-semantic-fix-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 | `board/raw_uart.log`; per-sample `board/trace-off/rep_00..04`; per-sample `board/trace-on/rep_00..04` |
| Analyze | `uv run python tools/experiment_35t.py --stage analyze --run-id 35t-p0c-r512-board-semantic-fix-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 | per-rep `trace.jsonl`, `trace_code_map/`, `behavior_recovery/`, `behavior_audit/`, `lightweight/`, `alignment/` |
| Report | `uv run python tools/experiment_35t.py --stage report --run-id 35t-p0c-r512-board-semantic-fix-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 | `aggregate/metrics.json`, `aggregate/metrics.csv`, `aggregate/accuracy_report.md`, `aggregate/bandwidth_report.md`, `aggregate/artifact_index.md` |
| Gate | `uv run python tools/check_35t_next_gate.py --run-id 35t-p0c-r512-board-semantic-fix-20260520-com5 --reps 5 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 | `aggregate/gate_report.json`, `aggregate/gate_report.md` |
| Triage | `uv run python tools/triage_35t_semantic_failures.py --run-id 35t-p0c-r512-board-semantic-fix-20260520-com5 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 | `aggregate/semantic_failure_triage.json`, `aggregate/semantic_failure_triage.md` |
| Trap attribution debug | `uv run python tools/debug_trap_attribution.py --run-id 35t-p0c-r512-board-semantic-fix-20260520-com5 --sample-class malware_like_synthetic --sample-id illegal_trap --out-dir results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/samples/malware_like_synthetic/illegal_trap/aggregate/trap_attribution_debug_board_microbench` | 0 | `trap_attribution_debug.{json,csv,md}` |
| Bundle checker | `uv run python tools/check_35t_experiment_bundle.py --run-id 35t-p0c-r512-board-semantic-fix-20260520-com5 --reps 5 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 | PASS |

Command logs are in `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/command_logs/`.

## Gate table

Source: `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/aggregate/gate_report.json`

| Sample | Gate | Expected | Strong matched | Stable expected | Unexpected strong matched | Weak expected |
| --- | --- | --- | --- | --- | --- | --- |
| `hello` | PASS | none | none | none | none | none |
| `batch_open_read_write` | PASS | `batch_file_read_write` | `batch_file_read_write` | `batch_file_read_write` | none | `batch_file_read_write` |
| `illegal_trap` | PASS | `illegal_instruction_trap` | `illegal_instruction_trap` | `illegal_instruction_trap` | none | none |
| `anti_debug_like` | PASS | `anti_analysis_indicator` | `anti_analysis_indicator` | `anti_analysis_indicator` | none | none |

Key requested checks:

- `hello` unexpected matched: none.
- `illegal_trap` stable expected `illegal_instruction_trap`: true, 5/5 reps strong matched.
- `batch_open_read_write` weak semantic shape: retained, `batch_file_read_write` weak matched in 4/5 reps and strong matched in 1/5 reps.
- `anti_debug_like` expected `anti_analysis_indicator`: stable, 5/5 reps strong matched.
- UNKNOWN/corrupt: 0 for every sample.
- Parser warnings affecting gate: none; all 20 trace-on reps have `warning_count=0`, `unknown_event_count=0`, and `corrupt_record_count=0`.
- Bundle checker: PASS.

## Drop, cap, UNKNOWN, corrupt

| Sample | Captured events median | Drop median | Drop rate median | Drop rate worst | Old run median | Capped reps | UNKNOWN | Corrupt | Parser warning counts |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- |
| `hello` | 332 | 8 | 0.023529 | 0.024390 | 0.023634 | none | 0 | 0 | `{}` |
| `batch_open_read_write` | 372 | 7 | 0.018470 | 0.019126 | 0.018593 | none | 0 | 0 | `{}` |
| `illegal_trap` | 317 | 8 | 0.024615 | 0.025000 | 0.024060 | none | 0 | 0 | `{}` |
| `anti_debug_like` | 358 | 7 | 0.019178 | 0.019499 | 0.018817 | none | 0 | 0 | `{}` |

The new median DROP rates remain in the same p0c low-DROP range as `35t-p0c-abba-r512-20260520-com5`; no sample hit the 512-record capture cap.

## Per-rep rule stability

| Sample | Rep | Trace count | Drop | Strong rules | Weak rules | Unexpected strong | Parser/UNKNOWN/corrupt |
| --- | --- | ---: | ---: | --- | --- | --- | --- |
| `hello` | 00 | 323 | 8 | none | none | none | 0/0/0 |
| `hello` | 01 | 318 | 8 | none | none | none | 0/0/0 |
| `hello` | 02 | 339 | 8 | none | none | none | 0/0/0 |
| `hello` | 03 | 311 | 8 | none | none | none | 0/0/0 |
| `hello` | 04 | 336 | 8 | none | none | none | 0/0/0 |
| `batch_open_read_write` | 00 | 363 | 7 | `batch_file_read_write` | `illegal_instruction_trap` | none | 0/0/0 |
| `batch_open_read_write` | 01 | 350 | 7 | none | `batch_file_read_write`, `illegal_instruction_trap` | none | 0/0/0 |
| `batch_open_read_write` | 02 | 364 | 7 | none | `batch_file_read_write`, `illegal_instruction_trap` | none | 0/0/0 |
| `batch_open_read_write` | 03 | 349 | 7 | none | `batch_file_read_write`, `illegal_instruction_trap` | none | 0/0/0 |
| `batch_open_read_write` | 04 | 372 | 7 | none | `batch_file_read_write`, `illegal_instruction_trap` | none | 0/0/0 |
| `illegal_trap` | 00 | 333 | 8 | `illegal_instruction_trap` | none | none | 0/0/0 |
| `illegal_trap` | 01 | 308 | 8 | `illegal_instruction_trap` | none | none | 0/0/0 |
| `illegal_trap` | 02 | 320 | 8 | `illegal_instruction_trap` | none | none | 0/0/0 |
| `illegal_trap` | 03 | 302 | 8 | `illegal_instruction_trap` | none | none | 0/0/0 |
| `illegal_trap` | 04 | 307 | 8 | `illegal_instruction_trap` | none | none | 0/0/0 |
| `anti_debug_like` | 00 | 347 | 7 | `anti_analysis_indicator` | `illegal_instruction_trap` | none | 0/0/0 |
| `anti_debug_like` | 01 | 348 | 7 | `anti_analysis_indicator` | `illegal_instruction_trap` | none | 0/0/0 |
| `anti_debug_like` | 02 | 361 | 7 | `anti_analysis_indicator` | `illegal_instruction_trap` | none | 0/0/0 |
| `anti_debug_like` | 03 | 343 | 7 | `anti_analysis_indicator` | `illegal_instruction_trap` | none | 0/0/0 |
| `anti_debug_like` | 04 | 367 | 7 | `anti_analysis_indicator` | none | none | 0/0/0 |

Weak `illegal_instruction_trap` evidence appears in some non-`illegal_trap` reps, but it remains weak-only, is not counted as expected matched, and does not create a strong unexpected rule match. The requested `hello` false-positive guard remains clean.

## illegal_trap target/code-map validation

Code map:

- `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/samples/malware_like_synthetic/illegal_trap/build/illegal_trap.code_map.json`
- `binary_role`: `board_rootfs_overlay`
- `elf`: `build/board/artix7_35t/rootfs_exp_overlay/usr/bin/illegal_trap`
- `runtime_path`: `/usr/bin/illegal_trap`
- ELF class: `ELF32`
- SHA256: `82b5f33b58b578350f715f9b205263cf12d733d91b902a5b5db4986faf5d92ea`
- Illegal instruction site: `0x000000000001056c`, symbol `main`, offset `0x44`, asm `.word 0xffffffff`

This confirms the new board run used the target board rootfs overlay `/usr/bin/illegal_trap` code map, not a QEMU ELF64 groundtruth code map.

Trace/code-map join summary for `illegal_trap`:

| Rep | Code-map role | Runtime path | Target-attributed events | Illegal site events | Owner at illegal site |
| --- | --- | --- | ---: | ---: | --- |
| 00 | `board_rootfs_overlay` | `/usr/bin/illegal_trap` | 51 | 2 | `target_sample` |
| 01 | `board_rootfs_overlay` | `/usr/bin/illegal_trap` | 50 | 2 | `target_sample` |
| 02 | `board_rootfs_overlay` | `/usr/bin/illegal_trap` | 50 | 2 | `target_sample` |
| 03 | `board_rootfs_overlay` | `/usr/bin/illegal_trap` | 48 | 2 | `target_sample` |
| 04 | `board_rootfs_overlay` | `/usr/bin/illegal_trap` | 50 | 2 | `target_sample` |

Trap attribution debug:

- `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/samples/malware_like_synthetic/illegal_trap/aggregate/trap_attribution_debug_board_microbench/trap_attribution_debug.json`
- Diagnosis: `MATCHED_EXPECTED_ILLEGAL_INSTRUCTION_SITE_ALL_REPS`
- Every rep has `pc=0x000000000001056c`, `cause=0x00000002`, `code_map_owner=target_sample`, `symbol=main`, `symbol_offset=0x44`, `pc_delta=0`, and empty parser warnings at the illegal site.
- The debug JSON/CSV/MD artifacts retain the full per-event `raw_words`.

## Artifact index

- Run root: `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5`
- Board UART log: `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/board/raw_uart.log`
- Command logs: `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/command_logs/`
- Gate report: `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/aggregate/gate_report.json`
- Semantic triage: `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/aggregate/semantic_failure_triage.json`
- Metrics: `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/aggregate/metrics.json`
- Bundle checker log: `results/experiments/35t/35t-p0c-r512-board-semantic-fix-20260520-com5/command_logs/bundle_checker.log`

## Decision

- `p0c_r512_microbench_ready`: true
- `full_matrix_ready`: false
- `ready_for_next_stage`: limited to the next p0c r512 microbench/planning step; do not treat this as a full matrix result.
- Blocked reasons: none for the requested four-sample board microbench.

The four-sample real-board p0c r512 retest passed the requested gates. No full matrix, case study, CVA6-board upgrade, real malware detection claim, or mature detector claim was made.
