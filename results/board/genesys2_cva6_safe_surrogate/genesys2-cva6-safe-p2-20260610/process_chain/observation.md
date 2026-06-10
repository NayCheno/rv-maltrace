# process_chain Safe Surrogate Observation

Status: PASS_SAFE_SURROGATE_PARTIAL_ABNORMAL_SYSCALL_ENTRY_TRACE

Run: `genesys2-cva6-safe-p2-20260610`
Board: Digilent Genesys2 / CVA6
Runtime path: `/tmp/rvmt_p2/process_chain`

## Event Counts

- BRANCH: 34
- PRIV: 3
- SYSCALL_ENTRY: 3
- SYSCALL_RET: 1

## Syscall Entry Counts

- 0x000000000000005f: 1
- 0x00000000000000dc: 1
- 0x00000000000000dd: 1

## Limitations

- Trace evidence is assembled from multiple ILA trigger windows, not one continuous invocation.
- The repeated close loop is only partially captured by the retained close-triggered ILA window.
- The return probe is retained as an unattributed return-window check and is not claimed as a failed syscall return.
- No strong runtime process ownership is claimed without marker/PID/SATP/ASID evidence.
- No real malware payload, source, or binary is included or executed.
