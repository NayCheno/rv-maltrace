# Trace Export Decision

Phase 5.1 board trace export path decision.

## Decision

The first trace-enabled Genesys 2 board implementation uses:

```text
BRAM ring buffer + ILA/JTAG dump
```

This is a bring-up choice, not the final high-throughput transport. It keeps
the first hardware trace path local to the FPGA fabric and avoids adding UART
or AXI/Ethernet backpressure risk before the trace event policy is stable.

## Options

| Option | Status | Advantages | Risks | First-version Decision |
| --- | --- | --- | --- | --- |
| BRAM ring buffer + ILA/JTAG dump | SELECTED | Easiest board bring-up; no high-speed peripheral dependency; suitable for first hardware validation | Capacity is limited; not suitable for long-running traces | Use for first trace-enabled board run |
| UART streaming | DEFERRED | Simple to inspect; host parser is straightforward | Low bandwidth; requires aggressive filtering and drop accounting | Keep as a later debug/export path after BRAM trace shape is proven |
| AXI DMA / Ethernet streaming | DEFERRED | Higher bandwidth; better long-term export target | Integration complexity and higher perturbation risk | Do not use for the first board implementation |

## First-version Requirements

- The trace capture buffer is a bounded BRAM ring.
- Host extraction is through Vivado ILA/JTAG or an equivalent JTAG-visible dump.
- Full retire remains disabled by default.
- Phase 5.2 event selection applies before queueing: syscall, trap, context,
  and branch first.
- Drop mode stays allowed; dropped-event count must remain observable.
- The export path must not add ready/stall/backpressure into CVA6 commit logic.

## Deferred Paths

UART streaming and AXI DMA/Ethernet streaming are not rejected permanently. They
are deferred until the BRAM/JTAG path proves packet shape, filtering, and drop
accounting on the board.
