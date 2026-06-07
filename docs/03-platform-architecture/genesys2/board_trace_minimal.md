# Board Trace Minimal Policy

Phase 5.2 first trace-enabled Genesys 2 board trace policy.

## Decision

First board trace runs use `rtl/trace/trace_board_minimal_top.sv`, which
instantiates `rtl/trace/trace_board_minimal_ctrl.sv` to drive the `trace_top.sv`
filter controls. The `board_minimal` trace-unit regression instantiates that
profile before board integration so the first-board control values are exercised
in simulation.

This is a board bring-up configuration, not evidence that hardware trace has
passed on Genesys 2.

## First-board Control Values

| Control | First-board Value | Purpose |
| --- | ---: | --- |
| `trace_enable_retire_o` | 0 | Keep full retire disabled by default |
| `trace_enable_branch_o` | 1 | Enable committed conditional branch events |
| `trace_enable_jump_o` | 0 | Defer jump events until the branch-only path is proven |
| `trace_enable_syscall_o` | 1 | Enable syscall events |
| `trace_enable_trap_o` | 1 | Enable trap and exception events |
| `trace_enable_context_o` | 1 | Enable CSR, SATP, and privilege context events |
| `trace_enable_marker_o` | 0 | Keep synthetic marker events off for board bring-up |
| `trace_enable_drop_o` | 1 | Keep dropped-event accounting observable |

## Allowed First-board Events

Only syscall, trap, context, and branch behavior events are enabled for the
first board run:

```text
SYSCALL_ENTRY
SYSCALL_RET
TRAP
CSR
SATP
PRIV
BRANCH
```

`DROP` remains enabled as accounting only. `RETIRE`, `JUMP`, and `MARKER` are
not first-board behavior events.

## Filtering And Drop Accounting

`trace_filter.sv` applies event-type filtering before packets enter the
`trace_top.sv` queue. PC range filtering remains available through
`PC_FILTER_ENABLE`, `PC_START`, and `PC_END`, but is disabled by default until a
board run records the selected range.

Drop mode remains enabled. When the queue overflows, `DROP.value` carries the
accumulated `drop_count`.
