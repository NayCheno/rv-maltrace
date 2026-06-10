# Genesys2/CVA6 Evidence Chain Status (2026-06-10)

This report summarizes the current Digilent Genesys2 + CVA6 evidence chain.
Artix-7 35T material is excluded from the current conclusion and is treated
only as historical or tooling reference. Real-malware validation was not run in
this step and remains not demonstrated.

## Scope

Current board path:

- Board: Digilent Genesys2.
- CPU/SoC: CVA6 Linux/Buildroot image.
- JTAG: Genesys2 onboard JTAG through Vivado `hw_server`.
- UART: Genesys2 onboard UART `COM7`, `115200 8N1`.
- Trace bitstream: `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.bit`.

Evidence roots:

- P0 board trace validation: `results/board/genesys2_trace_validation/20260609-2345-phase6-syscall-ret-fix/`.
- P2 safe surrogate chain: `results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610/`.
- Trace quality probe: `results/board/genesys2_trace_quality/20260610-hello-write-entry-ret-correlation/`.

## Gate Status

The artifact gate was repaired before this report: `genesys2-artifacts` now
accepts the trace routed timing summary only when the design state is routed,
and the current trace `.bit` exists.

Fast gates rerun for this report:

- `uv run python tools/run_check_suite.py --suite genesys2-current`: PASS.
- `uv run python tools/run_check_suite.py --suite genesys2-artifacts`: PASS.

Real malware is intentionally outside this step. The current conclusion for
real malware remains: validation not demonstrated.

## P0 Hardware Trace Matrix

Run root: `results/board/genesys2_trace_validation/20260609-2345-phase6-syscall-ret-fix/`.

| Sample | Status | Events | Required evidence | Key limitation |
| --- | --- | ---: | --- | --- |
| `hello_write` | `PARTIAL_PAIRED_RET_BLOCKED` | 25 | `SYSCALL_ENTRY a7=0x40`, `SYSCALL_RET`, compare PASS | Entry and return are present only across separate windows; no same-window pair. |
| `file_open_read_write` | `PARTIAL_MULTI_CAPTURE_WINDOW_LIMIT` | 88 | `openat`, `read`, `write`, `close` entries, `SYSCALL_RET`, compare PASS | Required entries are collected across multiple delayed captures. |
| `fork_exec` | `PARTIAL_PROCESS_ATTRIBUTION_NOT_PROVEN` | 41 | `clone`, `execve`, `wait4` entries, `SYSCALL_RET`, `PRIV`, compare PASS | `execve` capture is ambiguous with shell launch; process ownership is not proven. |
| `illegal_instruction` | `PARTIAL_TRAP_CAPTURE_PROGRAM_EXIT_132` | 21 | `TRAP cause=2`, write entry, compare PASS | Trap is captured, but decoded trap PC is kernel/supervisor context and the program exits with unhandled SIGILL status 132. |

Event totals:

- `hello_write`: `BRANCH=22`, `PRIV=1`, `SYSCALL_ENTRY=1`, `SYSCALL_RET=1`.
- `file_open_read_write`: `BRANCH=73`, `PRIV=7`, `SYSCALL_ENTRY=7`, `SYSCALL_RET=1`.
- `fork_exec`: `BRANCH=34`, `PRIV=3`, `SYSCALL_ENTRY=3`, `SYSCALL_RET=1`.
- `illegal_instruction`: `BRANCH=17`, `PRIV=2`, `SYSCALL_ENTRY=1`, `TRAP=1`.

## P1 Local Code Analysis Matrix

Each P0 sample has `local_code_analysis/code_map.json`,
`source_attribution.json`, and `source_attribution_summary.json`. Each also has
behavior recovery artifacts under `behavior/` (`behavior_graph.json`,
`semantic_events.json`, and `recovery_report.md`).

| Sample | Trace events | Target-attributed events | Process attribution | Source/function attribution |
| --- | ---: | ---: | --- | --- |
| `hello_write` | 25 | 1 | Not proven; runtime process map missing | Source-line and function attribution unavailable. |
| `file_open_read_write` | 88 | 2 | Not proven; runtime process map missing | Source-line and function attribution unavailable. |
| `fork_exec` | 41 | 0 | Not proven; runtime process map missing | Source-line and function attribution unavailable. |
| `illegal_instruction` | 21 | 1 | Not proven; runtime process map missing | Source-line and function attribution unavailable. |

This is enough to support limited local static attribution where decoded PCs
fall into the target ELF map. It is not enough to prove end-to-end runtime
process ownership for the whole trace.

## P2 Safe Surrogate Matrix

Run root: `results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610/`.

Manifest coverage is `PASS`: 8 of 8 repository-authored safe
malware-like/surrogate samples have the required hardware trace, local code
analysis, malware-analysis mapping/report, and integrated validation artifacts.
All samples are `malware_like_synthetic` and `real_malware=false`.

| Sample | Integrated status |
| --- | --- |
| `abnormal_syscall_sequence` | `PASS_SAFE_SURROGATE_WEAK_EVIDENCE_CHAIN_WITH_LIMITATIONS` |
| `anti_debug_like` | `PASS_SAFE_SURROGATE_WEAK_EVIDENCE_CHAIN_WITH_LIMITATIONS` |
| `batch_open_read_write` | `PASS_SAFE_SURROGATE_WEAK_EVIDENCE_CHAIN_WITH_LIMITATIONS` |
| `dynamic_executable_memory` | `PASS_SAFE_SURROGATE_WEAK_EVIDENCE_CHAIN_WITH_LIMITATIONS` |
| `file_scan` | `PASS_SAFE_SURROGATE_WEAK_EVIDENCE_CHAIN_WITH_LIMITATIONS` |
| `illegal_trap` | `PASS_SAFE_SURROGATE_EVIDENCE_CHAIN_WITH_LIMITATIONS` |
| `process_chain` | `PASS_SAFE_SURROGATE_WEAK_EVIDENCE_CHAIN_WITH_LIMITATIONS` |
| `self_copy_sim` | `PASS_SAFE_SURROGATE_WEAK_EVIDENCE_CHAIN_WITH_LIMITATIONS` |

This supports a safe-surrogate evidence chain, not real-malware validation.

## Hardware Trace Quality Probe

A non-sample trace-quality probe was run on the physical Genesys2/CVA6 board
using only the board shell builtin `printf`. No binary payload was transferred
for the passing probe.

Trace-quality root:
`results/board/genesys2_trace_quality/20260610-hello-write-entry-ret-correlation/`.

Passing probe artifacts:

- `builtin_write_entry_event_only.trace.jsonl`: 13 decoded events; includes
  `SYSCALL_ENTRY` with `a7=0x40`.
- `builtin_write_ret_pretrigger.trace.jsonl`: 17 decoded events; includes
  `SYSCALL_RET` at ILA row 1023.
- `builtin_write_entry_event_only_program.log` and
  `builtin_write_ret_pretrigger_program.log`: UART logs show the marker payloads
  printed by the board shell command.

Quality findings:

- Vivado confirmed the programmed device had one ILA core after setting
  `BSCAN_SWITCH_USER_MASK=1` in the capture flow.
- Requesting event-only capture did not take effect:
  `CONTROL.CAPTURE_MODE` is read-only, so the capture remained `ALWAYS`.
- `SYSCALL_ENTRY` and `SYSCALL_RET` are still captured only in separate
  windows. A single continuous entry/return window is not demonstrated.
- Earlier attempts to transfer and execute the large `hello_write.riscv64` ELF
  over UART are not PASS evidence. The first attempt ran with `rc=127` because
  `/tmp/rvmt_phase6/hello_write` was missing; the slower transfer was abandoned
  after serial echo/backlog caused heredoc congestion. These attempts are
  excluded from PASS claims.

## Weak-Evidence Limitations

- Hardware traces are multi-window for several samples. They show required
  event classes and syscall numbers, but not complete continuous executions.
- `hello_write` write entry and syscall return are both present, but not in one
  ILA window.
- Runtime process ownership is generally not proven because PID/SATP/ASID or a
  validated runtime process map is missing for the P0 traces.
- Source-line and function-level attribution are unavailable in the P0 local
  code analysis summaries.
- Safe surrogate behavior mappings are repository-authored synthetic/surrogate
  analyses only.
- Real malware payloads, sources, and binaries are not present in the repository
  and were not evaluated in this step.

## Allowed Claims

- Genesys2/CVA6 board trace validation demonstrates hardware capture of the
  required syscall/trap event classes for the four P0 Linux-user programs, with
  documented multi-window limitations.
- `hello_write` demonstrates `write` syscall entry (`a7=0x40`) and a syscall
  return event on Genesys2/CVA6, but only across separate capture windows.
- Local code analysis artifacts exist for the four P0 traces and provide
  limited target ELF attribution where decoded PCs permit.
- The eight repository-authored safe malware-like/surrogate samples have a
  complete synthetic/surrogate evidence-chain package with documented
  limitations.
- The 2026-06-10 trace-quality probe independently confirms the current
  Genesys2/CVA6 trace bitstream and ILA flow can still capture `SYSCALL_ENTRY`
  and `SYSCALL_RET` on board.

## Non-Claims

- No real malware validation is demonstrated.
- No real malware detection quality, coverage, or efficacy is claimed.
- No synthetic or surrogate sample is claimed to be real malware.
- No real malware payload/source/binary is included or required by this report.
- No single continuous entry/trap/return hardware trace window is claimed.
- No strong per-process runtime attribution is claimed for the P0 traces without
  PID/SATP/ASID/marker-backed evidence.
