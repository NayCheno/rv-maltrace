# Trace Timing Principles

Phase 3.2 keeps trace logic off the CVA6 critical path.

## Contract

- Trace RTL samples CVA6 commit, writeback, trap, CSR, privilege, and SATP
  sideband signals only.
- `trace_top` and `cva6_rvfi_trace_adapter` default `PIPELINE_INPUTS` to `1`,
  so branch/syscall/trap/context decode and packet formatting operate from a
  registered sideband snapshot.
- Trace RTL does not expose ready, stall, backpressure, or waitrequest ports
  toward the core.
- Overflow uses queue drop accounting and `EVT_DROP`; the MVP hardware policy
  is drop-before-core-backpressure.

## Check

Run the timing-principle check before synthesis-oriented work:

```powershell
uv run python tools/check_timing_principles.py
uv run python tools/check_timing_principles.py --self-test
```
