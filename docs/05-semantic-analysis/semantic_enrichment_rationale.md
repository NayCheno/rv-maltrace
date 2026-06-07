# Semantic Enrichment Rationale

Phase 7.1 records why later semantic enrichment may be useful. This is a
deferred rationale, not an implementation claim and not experiment evidence.

The policy record is:

```text
experiments/linux_behavior/semantic_enrichment_rationale.json
```

## Hardware Trace Strengths

The RTL trace path is the project core. It is good at:

- seeing the true executed path
- seeing syscall, trap, and context transitions
- avoiding a guest OS instrumentation dependency
- resisting some software-only evasion strategies

## Semantic Gaps

The MVP trace does not try to fully recover:

- fd-to-path mapping
- pointer string or buffer content
- process name and executable path
- kernel object semantics

These gaps explain why a later enrichment layer may be useful after the
trace-enabled FPGA path and Linux recovery workflow have evidence.

## Boundary

eBPF is not an MVP dependency. eBPF is not the core contribution. The core
contribution remains RTL-level committed behavior trace from CVA6. Any eBPF,
kernel helper, or selective memory snapshot work is optional semantic
enrichment and must be evaluated only after the FPGA trace path works.
