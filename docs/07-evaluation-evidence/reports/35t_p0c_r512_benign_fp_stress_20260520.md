# 35T p0c r512 benign false-positive stress batch - 2026-05-20

## Scope

- Run id: `35t-p0c-r512-benign-fp-stress-20260520-com5`
- Artifact root: `results/experiments/35t/35t-p0c-r512-benign-fp-stress-20260520-com5`
- Board: real 35T/LiteX/VexRiscv via `COM5/921600`
- Samples: `ls`, `cat`, `cp`, `sha256sum`
- Config: `trace-profile=p0c_syscall_trap_drop`, `trace-records=512`, `runtime-order=abba`, `warmup=1`, `reps=5`
- Boundary: staged p0c r512 benign false-positive stress only. No full matrix, no case study, no CVA6 board claim, no real malware detection claim, and no mature detector claim.

Only this batch's `build/` and `groundtruth/` prerequisites were copied from `results/experiments/35t/35t-full-20260520`. No old `board/` artifacts were copied.

## Commands and return codes

| Step | Command | RC | Artifact |
| --- | --- | ---: | --- |
| Prereq copy | `Copy-Item` selected `build/` and `groundtruth/` for `ls`, `cat`, `cp`, `sha256sum` from `35t-full-20260520`; no `board/` copy | 0 | `command_logs/prep_prereqs.log` |
| Serial enum | `[System.IO.Ports.SerialPort]::GetPortNames() \| Sort-Object`; `uv run python -` with `serial.tools.list_ports.comports()` | 0 | `command_logs/serial_enumeration.log`; `COM5` is `USB-SERIAL CH340 (COM5)` |
| Board collect | `uv run python tools/experiment_35t.py --stage board --run-id 35t-p0c-r512-benign-fp-stress-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample ls --sample cat --sample cp --sample sha256sum` | 0 | `board/raw_uart.log`; trace-off/on reps |
| Analyze | `uv run python tools/experiment_35t.py --stage analyze --run-id 35t-p0c-r512-benign-fp-stress-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample ls --sample cat --sample cp --sample sha256sum` | 0 | per-rep analysis artifacts |
| Report | `uv run python tools/experiment_35t.py --stage report --run-id 35t-p0c-r512-benign-fp-stress-20260520-com5 ...` | 0 | `aggregate/metrics.json`, reports |
| Gate | `uv run python tools/check_35t_next_gate.py --run-id 35t-p0c-r512-benign-fp-stress-20260520-com5 --reps 5 --sample ls --sample cat --sample cp --sample sha256sum` | 0 | `aggregate/gate_report.json` |
| Triage | `uv run python tools/triage_35t_semantic_failures.py --run-id 35t-p0c-r512-benign-fp-stress-20260520-com5 --sample ls --sample cat --sample cp --sample sha256sum` | 0 | `aggregate/semantic_failure_triage.json`; legacy four-sample checklist text says `BLOCKED`, not applicable to this batch gate |
| Bundle checker | `uv run python tools/check_35t_experiment_bundle.py --run-id 35t-p0c-r512-benign-fp-stress-20260520-com5 --reps 5 --sample ls --sample cat --sample cp --sample sha256sum` | 0 | PASS |

## Run config

```json
{
  "baud": 921600,
  "port": "COM5",
  "reps": 5,
  "run_id": "35t-p0c-r512-benign-fp-stress-20260520-com5",
  "runtime_order": "abba",
  "samples": ["ls", "cat", "cp", "sha256sum"],
  "trace_control_mask": "0x2c",
  "trace_profile": "p0c_syscall_trap_drop",
  "trace_records": 512,
  "warmup": 1
}
```

## Gate table

Source: `aggregate/gate_report.json`

| Sample | Gate | Strong matched | Weak matched | Unexpected strong matched | Stable expected |
| --- | --- | --- | --- | --- | --- |
| `ls` | PASS | none | `illegal_instruction_trap` | none | none |
| `cat` | PASS | none | `illegal_instruction_trap` | none | none |
| `cp` | PASS | none | `illegal_instruction_trap` | none | none |
| `sha256sum` | PASS | none | `illegal_instruction_trap` | none | none |

Weak `illegal_instruction_trap` evidence was recorded for several benign reps, but it did not become a strong unexpected match.

## DROP, cap, UNKNOWN, corrupt

| Sample | Captured events median | Drop median | Drop rate median | Drop rate worst | Capped reps | UNKNOWN | Corrupt | Parser warning counts |
| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- |
| `ls` | 349 | 8 | 0.022409 | 0.023392 | none | 0 | 0 | `{}` |
| `cat` | 338 | 8 | 0.023121 | 0.023739 | none | 0 | 0 | `{}` |
| `cp` | 359 | 8 | 0.021798 | 0.022727 | none | 0 | 0 | `{}` |
| `sha256sum` | 359 | 8 | 0.021798 | 0.022409 | none | 0 | 0 | `{}` |

DROP remains in the p0c low-DROP range observed in the prior four-sample microbench. No rep hit the 512-record cap.

## Per-rep rule stability

| Sample | Rep | Trace count | Drop | Strong rules | Weak rules | Unexpected strong | Parser/UNKNOWN/corrupt |
| --- | --- | ---: | ---: | --- | --- | --- | --- |
| `ls` | 00 | 348 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `ls` | 01 | 325 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `ls` | 02 | 344 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `ls` | 03 | 339 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `ls` | 04 | 346 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `cat` | 00 | 350 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `cat` | 01 | 325 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `cat` | 02 | 334 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `cat` | 03 | 319 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `cat` | 04 | 335 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `cp` | 00 | 365 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `cp` | 01 | 336 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `cp` | 02 | 357 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `cp` | 03 | 350 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `cp` | 04 | 342 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `sha256sum` | 00 | 361 | 8 | none | none | none | 0/0/0 |
| `sha256sum` | 01 | 340 | 8 | none | none | none | 0/0/0 |
| `sha256sum` | 02 | 351 | 8 | none | none | none | 0/0/0 |
| `sha256sum` | 03 | 341 | 8 | none | `illegal_instruction_trap` | none | 0/0/0 |
| `sha256sum` | 04 | 351 | 8 | none | none | none | 0/0/0 |

## Code-map note

All four benign samples used the board rootfs overlay code map for `build/board/artix7_35t/rootfs_exp_overlay/usr/bin/rvmt_benign_workload`, runtime path `/usr/bin/rvmt_benign_workload`, ELF32.

## Decision

- Stage 1 status: PASS.
- Allowed to enter next batch: true.
- Precise blocker: none.
- `full_matrix_ready`: false.
