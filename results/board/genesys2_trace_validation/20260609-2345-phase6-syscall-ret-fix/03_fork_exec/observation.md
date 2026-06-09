# fork_exec Board Trace Observation

Status: PARTIAL_PROCESS_ATTRIBUTION_NOT_PROVEN

Run: `20260609-2345-phase6-syscall-ret-fix`
Board: Digilent Genesys2 / CVA6
Runtime path: `/tmp/rvmt_phase6/fork_exec`

## Evidence

- Program log: `program.log`
- Merged trace: `trace.jsonl`
- Trace summary: `trace_summary.json`
- Capture manifest: `capture_manifest.json`
- Compare log: `compare.log`

## Event Counts

- BRANCH: 34
- PRIV: 3
- SYSCALL_ENTRY: 3
- SYSCALL_RET: 1

## Syscall Entry Counts

- 0x00000000000000dc: 1
- 0x00000000000000dd: 1
- 0x0000000000000104: 1

## Capture Boundary

- clone and wait4 captures use delayed 'exec /tmp/rvmt_phase6/fork_exec' to avoid shell fork of the target.
- execve capture remains ambiguous because shell exec of the sample has the same syscall number as the sample child execve.
- SYSCALL_RET is a separate return-event window and is not paired with a target entry in the same capture.

## Capture Set

- `fork_clone_entry`: SYSCALL_ENTRY_a7_0xdc; validity=delayed_exec_entry_family; events=11
- `fork_wait4_entry`: SYSCALL_ENTRY_a7_0x104; validity=delayed_exec_entry_family; events=7
- `fork_execve_entry_ambiguous`: SYSCALL_ENTRY_a7_0xdd; validity=execve_family_ambiguous_shell_launch; events=11
- `fork_ret_any`: SYSCALL_RET_any_pretrigger; validity=return_event_unpaired_window_probe; events=12
