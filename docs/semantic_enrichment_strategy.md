# Semantic Enrichment Strategy

Phase 7.3 records the recommended semantic enrichment strategy. This is a
strategy gate record, not implementation evidence and not experiment evidence.

The strategy record is:

```text
experiments/linux_behavior/semantic_enrichment_strategy.json
```

## Recommended Order

1. MVP: no eBPF. The MVP also has no kernel helper and no memory snapshot
   dependency. The core contribution remains RTL-level committed behavior trace.
2. After FPGA trace works: evaluate selective memory snapshot as a gated option.
   The default trace memory mode remains `TRACE_MEM_MODE_NONE`; no default
   memory trace, JSONL payload change, or core backpressure is allowed without
   timing and noninterference evidence.
3. After Linux experiments: optionally add eBPF metadata alignment for offline
   comparison or semantic enrichment. eBPF is not an MVP dependency, is not the
   core contribution, and must not replace RTL-level committed behavior trace.

## Route Position

The preferred later hardware route is `selective_memory_snapshot`, but only
after the FPGA trace path works and after timing impact is measured.

The optional later software alignment route is `ebpf_metadata_alignment`, but
only after Linux behavior experiments have trace evidence.

The `kernel_helper_metadata` route is not on the recommended MVP path because it
is OS intrusive. Revisit it only if Linux experiments show that fd/path metadata
is a blocking analysis gap that eBPF alignment cannot cover cleanly.

## Boundary

This strategy keeps the MVP free of eBPF, kernel helper, and memory snapshot
dependencies. It does not enable any Phase 7 route, does not change the JSONL
event set, and does not add load/store payloads.
