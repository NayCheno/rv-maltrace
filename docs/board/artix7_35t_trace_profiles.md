# Artix-7 35T Trace Profiles

This document defines board profiles for the Artix-7 35T LiteX/VexRiscv route.
These profiles do not modify the CVA6 signal map and do not create CVA6 board
evidence.

## Scope

- Board target: `artix7_35t_litex`.
- CPU route: LiteX/VexRiscv only.
- Export rule: trace full must drop/account records; it must not backpressure
  the core.
- First-stage profiles explicitly forbid full retire streams, full jump streams,
  and load/store streams.
- `ARG_MEM` is disabled unless a later gated bitstream and gate report prove
  that pointer snapshots are safe enough for a specific experiment.

## Profiles

| Profile | Purpose | enable_syscall | enable_trap | enable_context | enable_drop | enable_branch | enable_retire | enable_jump | ARG_MEM |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `p0_syscall_trap_context` | correctness first | 1 | 1 | 1 | 1 | 0 | 0 | 0 | disabled |
| `p1_branch_context` | add control-flow fragments | 1 | 1 | 1 | 1 | 1 | 0 | 0 | disabled |
| `p2_pointer_snapshot` | pointer semantics experiment | 1 | 1 | 1 | 1 | 0 | 0 | 0 | gated |
| `p0a_syscall_drop` | syscall entry/return plus DROP only | 1 | 0 | 0 | 1 | 0 | 0 | 0 | disabled |
| `p0b_trap_drop` | trap plus DROP only | 0 | 1 | 0 | 1 | 0 | 0 | 0 | disabled |
| `p0c_syscall_trap_drop` | syscall/trap plus DROP, no context | 1 | 1 | 0 | 1 | 0 | 0 | 0 | disabled |

## Event Gates

For `p0_syscall_trap_context`, trace JSONL may contain only:

```text
SYSCALL_ENTRY
SYSCALL_RET
TRAP
CSR
SATP
PRIV
DROP
```

`RETIRE`, `BRANCH`, `JUMP`, and `ARG_MEM` are forbidden in p0 runs. If one of
those events appears, the run is marked FAIL and cannot promote to a full
matrix run.

`p1_branch_context` permits `BRANCH` but still forbids full retire, full jump,
and memory-load/store streaming. `p2_pointer_snapshot` is a named experiment
profile only; it remains blocked until a separate gate explicitly enables and
validates `ARG_MEM`.

## Runtime Recording

Every 35T experiment `run_config.json` must record:

```json
{
  "trace_profile": "p0_syscall_trap_context",
  "trace_controls": {
    "enable_syscall": true,
    "enable_trap": true,
    "enable_context": true,
    "enable_drop": true,
    "enable_branch": false,
    "enable_retire": false,
    "enable_jump": false,
    "enable_arg_mem": false,
    "arg_mem_policy": "disabled"
  }
}
```

The hardware profile mask is a board-side filter. It is not a proof of mature
semantic recovery; gate reports must still show DROP, event-set, alignment, and
audit behavior before a run can be promoted.
