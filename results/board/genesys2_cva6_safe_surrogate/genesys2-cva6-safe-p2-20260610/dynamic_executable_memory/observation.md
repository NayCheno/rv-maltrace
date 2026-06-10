# dynamic_executable_memory Safe Surrogate Observation

Status: PASS_SAFE_SURROGATE_PARTIAL_ABNORMAL_SYSCALL_ENTRY_TRACE

Run: `genesys2-cva6-safe-p2-20260610`
Board: Digilent Genesys2 / CVA6
Runtime path: `/tmp/rvmt_p2/dynamic_executable_memory`

## Event Counts

- BRANCH: 29
- PRIV: 4
- SYSCALL_ENTRY: 3
- SYSCALL_RET: 1

## Syscall Entry Counts

- 0x00000000000000d7: 1
- 0x00000000000000de: 1
- 0x00000000000000e2: 1

## Limitations

- Trace evidence is assembled from multiple ILA trigger windows, not one continuous invocation.
- The repeated close loop is only partially captured by the retained close-triggered ILA window.
- The return probe is retained as an unattributed return-window check and is not claimed as a failed syscall return.
- No strong runtime process ownership is claimed without marker/PID/SATP/ASID evidence.
- No real malware payload, source, or binary is included or executed.
