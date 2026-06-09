# file_open_read_write Board Trace Observation

Status: PARTIAL_MULTI_CAPTURE_WINDOW_LIMIT

Run: `20260609-2345-phase6-syscall-ret-fix`
Board: Digilent Genesys2 / CVA6
Runtime path: `/tmp/rvmt_phase6/file_open_read_write`

## Evidence

- Program log: `program.log`
- Merged trace: `trace.jsonl`
- Trace summary: `trace_summary.json`
- Capture manifest: `capture_manifest.json`
- Compare log: `compare.log`

## Event Counts

- BRANCH: 73
- PRIV: 7
- SYSCALL_ENTRY: 7
- SYSCALL_RET: 1

## Syscall Entry Counts

- 0x0000000000000038: 2
- 0x0000000000000039: 2
- 0x000000000000003f: 1
- 0x0000000000000040: 2

## Capture Boundary

- Required syscall entries are demonstrated across multiple delayed board captures because the current ILA stores only 1024 always-sampled cycles.
- SYSCALL_RET is captured as a separate return-event window and is not paired with a target entry in the same capture.

## Capture Set

- `file_openat_entry_1`: SYSCALL_ENTRY_a7_0x38; validity=target_entry_delayed; events=11
- `file_openat_entry_2b`: SYSCALL_ENTRY_a7_0x38; validity=target_entry_delayed; events=7
- `file_read_entry_b`: SYSCALL_ENTRY_a7_0x3f; validity=target_entry_delayed; events=11
- `file_write_entry_1`: SYSCALL_ENTRY_a7_0x40; validity=target_entry_delayed; events=11
- `file_write_entry_2b`: SYSCALL_ENTRY_a7_0x40; validity=target_entry_delayed; events=11
- `file_close_entry_1b`: SYSCALL_ENTRY_a7_0x39; validity=target_entry_delayed; events=12
- `file_close_entry_2b`: SYSCALL_ENTRY_a7_0x39; validity=target_entry_delayed; events=13
- `file_ret_any_b`: SYSCALL_RET_any_pretrigger; validity=return_event_unpaired_window_probe; events=12
