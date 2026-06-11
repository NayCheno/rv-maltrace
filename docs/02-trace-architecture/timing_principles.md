# Trace Timing Principles

Phase 3.2 keeps trace logic off the CVA6 critical path.

## Contract

- Trace RTL samples CVA6 commit, writeback, trap, CSR, privilege, and SATP
  sideband signals only.
- `trace_top` and `cva6_rvfi_trace_adapter` default `PIPELINE_INPUTS` to `1`,
  so branch/syscall/trap/context decode and packet formatting operate from a
  registered sideband snapshot.
- `cva6_rvfi_trace_adapter` emits queued packets only. Each cycle it counts
  decoded events for overflow accounting and appends the accepted packets
  directly into the trace queue, without synthesizing separate candidate or
  pending-next packet arrays.
- Trace RTL does not expose ready, stall, backpressure, or waitrequest ports
  toward the core.
- Overflow uses queue drop accounting and `EVT_DROP`; the MVP hardware policy
  is drop-before-core-backpressure.
- The Genesys2 ILA generator defaults to an 8192-sample window, two ILA input
  pipeline stages, storage qualification, and advanced trigger support for the
  next paired entry/return capture run.

## Check

Run the timing-principle check before synthesis-oriented work:

```powershell
uv run python tools/check_timing_principles.py
uv run python tools/check_timing_principles.py --self-test
```
