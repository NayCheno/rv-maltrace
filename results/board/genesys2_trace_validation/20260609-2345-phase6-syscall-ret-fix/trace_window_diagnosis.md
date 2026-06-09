# Genesys2/CVA6 Trace Window Diagnosis

Run: `20260609-2345-phase6-syscall-ret-fix`
Board: Digilent Genesys2 / CVA6

## Finding

The current trace-enabled bitstream can capture syscall entry events and can
capture syscall return events, but the current ILA configuration has not yet
demonstrated a target syscall entry and its matching return in one capture
window.

The observed ILA properties in `ila_properties.log` are:

- `CONTROL.DATA_DEPTH = 1024`
- `STATIC.MAX_DATA_DEPTH = 1024`
- `CONTROL.CAPTURE_MODE = ALWAYS`
- `STATIC.IS_BASIC_CAPTURE_MODE_SUPPORTED = 0`

The generated ILA IP configuration also has storage qualification disabled
(`C_EN_STRG_QUAL = 0`). An event-only capture attempt in
`01_hello_write/hello_write_entry_event_only_capture.log` was rejected by Vivado
because `CONTROL.CAPTURE_MODE` is read-only for this core configuration.

## Evidence Boundary

- `hello_write` demonstrates a delayed target `SYSCALL_ENTRY` for write
  (`a7 = 0x40`) at PC `0x000100fe` in the minimal runtime ELF.
- `hello_write` also demonstrates that `SYSCALL_RET` events are decodable from
  the hardware trace, but only in a separate return-trigger capture.
- The merged `trace.jsonl` files are multi-capture evidence packages. They are
  valid for checking event decoder behavior and expected syscall families, but
  they are not single continuous invocation traces.

## Current Root Cause Assessment

The missing paired syscall return is a capture-window/configuration limitation,
not a proven decoder failure:

- The decoder emits `SYSCALL_RET` from return-trigger raw CSV captures.
- Entry-trigger captures do not retain the matching return inside the 1024
  always-sampled window.
- The current ILA core does not expose a writable event-only capture mode.

To close paired entry/return evidence, the trace ILA should be rebuilt with a
larger depth, storage qualification, or another event-buffering strategy, then
the board captures should be repeated.
