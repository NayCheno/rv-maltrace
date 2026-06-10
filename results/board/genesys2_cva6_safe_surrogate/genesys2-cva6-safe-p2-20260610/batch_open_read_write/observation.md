# batch_open_read_write Safe Surrogate Observation

Status: PASS_SAFE_SURROGATE_PARTIAL_ABNORMAL_SYSCALL_ENTRY_TRACE

Run: `genesys2-cva6-safe-p2-20260610`
Board: Digilent Genesys2 / CVA6
Runtime path: `/tmp/rvmt_p2/batch_open_read_write`

## Event Counts

- BRANCH: 38
- PRIV: 5
- SYSCALL_ENTRY: 4
- SYSCALL_RET: 1

## Syscall Entry Counts

- 0x0000000000000038: 1
- 0x0000000000000039: 1
- 0x000000000000003f: 1
- 0x0000000000000040: 1

## Limitations

- Trace evidence is assembled from multiple ILA trigger windows, not one continuous invocation.
- The repeated close loop is only partially captured by the retained close-triggered ILA window.
- The return probe is retained as an unattributed return-window check and is not claimed as a failed syscall return.
- No strong runtime process ownership is claimed without marker/PID/SATP/ASID evidence.
- No real malware payload, source, or binary is included or executed.
