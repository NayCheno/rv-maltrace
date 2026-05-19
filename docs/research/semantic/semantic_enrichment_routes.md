# Semantic Enrichment Routes

Phase 7.2 defines three deferred semantic enrichment routes. This is a route
comparison and gating plan, not an implementation claim and not experiment
evidence.

The route record is:

```text
experiments/linux_behavior/semantic_enrichment_routes.json
```

The current trace memory mode remains:

```text
TRACE_MEM_MODE_NONE
```

## Route Matrix

| Route | ID | Class | Purpose | Trigger | Status |
| --- | --- | --- | --- | --- | --- |
| Route A | selective_memory_snapshot | hardware | bounded pointer data around selected syscalls, such as `openat` pathname prefix or `write` buffer prefix | after FPGA trace works | DEFERRED_POST_FPGA |
| Route B | kernel_helper_metadata | kernel helper | pid, fd, and path metadata for offline alignment | after Linux recovery workflow has evidence | DEFERRED_POST_FPGA |
| Route C | ebpf_metadata_alignment | eBPF | high-level kernel semantic events for timestamp or cycle alignment | after Linux experiments have trace evidence | DEFERRED_POST_FPGA |

## Route Risks

Route A may require an extra memory read path, can affect timing, and adds
integration complexity. It must not enable default memory trace or backpressure
the core.

Route B is OS intrusive and can dilute the pure hardware narrative. It must
remain metadata-only and optional; the hardware trace remains authoritative.

Route C can depend on kernel version details and can cause MVP scope drift. eBPF
is not an MVP dependency, is not the core contribution, and may only be used as
comparison or optional semantic enrichment.

All routes remain deferred in this phase. The JSONL/RTL path already defines
default-disabled `ARG_MEM` for syscall-scoped pointer snapshots, but that path
is not Phase 7 route implementation evidence. No route enables default memory
trace; default load/store memory records remain disabled, and no route replaces
RTL-level committed behavior trace.
