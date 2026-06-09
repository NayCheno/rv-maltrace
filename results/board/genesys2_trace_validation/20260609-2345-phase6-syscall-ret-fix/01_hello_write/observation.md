# hello_write Board Trace Observation

Status: PARTIAL_PAIRED_RET_BLOCKED

Run: `20260609-2345-phase6-syscall-ret-fix`
Board: Digilent Genesys2 / CVA6
Runtime path: `/tmp/rvmt_phase6/hello_write`

## Evidence

- Program log: `program.log`
- Merged trace: `trace.jsonl`
- Trace summary: `trace_summary.json`
- Capture manifest: `capture_manifest.json`
- Compare log: `compare.log`

## Event Counts

- BRANCH: 22
- PRIV: 1
- SYSCALL_ENTRY: 1
- SYSCALL_RET: 1

## Syscall Entry Counts

- 0x0000000000000040: 1

## Capture Boundary

- SYSCALL_ENTRY write(64) was captured from a delayed target run with PC 0x000100fe in the minimal runtime ELF.
- SYSCALL_RET is captured only in a separate ret-trigger window; current ILA depth 1024 and capture_mode ALWAYS do not show entry+return in one capture.

## Capture Set

- `hello_write_delayed_entry_write_b64`: SYSCALL_ENTRY_a7_0x40; validity=target_entry_delayed; events=11
- `hello_write_ret_pretrigger`: SYSCALL_RET_any_pretrigger; validity=return_event_unpaired_window_probe; events=14
