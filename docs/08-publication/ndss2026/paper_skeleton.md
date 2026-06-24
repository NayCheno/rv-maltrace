# RV-MalTrace NDSS Paper Skeleton

Status: `DRAFT_SKELETON_LATEX_BUILD_PASS_HOST_2026-06-24`

## Title

RV-MalTrace: Hardware-Assisted Behavioral Tracing for RISC-V Linux Workloads

## Abstract Claims

- We present a CVA6/Genesys2 trace path for controlled safe and malware-like syscall behavior studies.
- We reconstruct bounded syscall/control-flow semantics from hardware trace records and explicitly tag oracle-derived semantic fields.
- We validate local code-attribution edge cases for exact ELF hashes, PIE/ASLR, runtime maps, dynamic libraries, fork/exec, stripped ELFs, and sidecar non-promotion.
- We provide a reproducible artifact package rooted at `results/evaluation/genesys2-cva6/current/`.

Non-claims:

- No real malware validation is claimed.
- No production streaming/DMA throughput result is claimed until host/board artifacts pass intake.
- No JTAG RAM boot, SD-card kernel update, or board cycle-overhead result is claimed until the required host/board artifacts pass their require-pass checkers.
- No board-native DWARF source-line claim is made from sidecar-only evidence.
- QEMU/strace/host-control logs are validation oracles, not hardware recovery output.

## Sections

1. Introduction
2. Threat Model And Scope
3. Trace Architecture
4. CVA6/Genesys2 Implementation
5. Semantic Reconstruction And Provenance
6. Experimental Methodology
7. Evaluation
8. Limitations
9. Ethics And Artifact Safety
10. Related Work
11. Conclusion

## Required Figures

| Figure | Status | Evidence |
| --- | --- | --- |
| Trace pipeline overview | TODO | RTL/docs diagram needed |
| CVA6 RVFI adapter event ordering | TODO | `rtl/trace/cva6_rvfi_trace_adapter.sv`, `sim/golden/rvfi_adapter.expected.json` |
| Artifact evidence graph | TODO | `reproducibility_manifest.json`, `artifact_package_manifest.json` |
| Host/board blocker flow | TODO | JTAG RAM-boot probe, SD-card write preflight, cycle diagnostics |

## Required Tables

Use `docs/08-publication/ndss2026/experiment_tables.md`.
