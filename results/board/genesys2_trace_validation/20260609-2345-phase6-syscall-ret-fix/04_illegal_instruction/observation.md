# illegal_instruction Board Trace Observation

Status: PARTIAL_TRAP_CAPTURE_PROGRAM_EXIT_132

Run: `20260609-2345-phase6-syscall-ret-fix`
Board: Digilent Genesys2 / CVA6
Runtime path: `/tmp/rvmt_phase6/illegal_instruction`

## Evidence

- Program log: `program.log`
- Merged trace: `trace.jsonl`
- Trace summary: `trace_summary.json`
- Capture manifest: `capture_manifest.json`
- Compare log: `compare.log`

## Event Counts

- BRANCH: 17
- PRIV: 2
- SYSCALL_ENTRY: 1
- TRAP: 1

## Syscall Entry Counts

- 0x0000000000000040: 1

## Capture Boundary

- The board runtime emitted TRAP cause=2, but the program log shows unhandled SIGILL and RVMT_EXIT:132 rather than caught SIGILL exit 0.
- TRAP PC is kernel/supervisor handling context in the packed trace; user illegal PC is visible in UART kernel report, not directly in the decoded TRAP event.

## Capture Set

- `illegal_trap_cause2`: TRAP_cause_0x2; validity=trap_cause2; events=11
- `illegal_write_entry`: SYSCALL_ENTRY_a7_0x40; validity=write_entry_before_sigill; events=10
