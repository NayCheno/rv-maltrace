# RV-MalTrace 35T Paper Evidence Chain

## Scope

This paper evidence chain is limited to Artix-7 35T / LiteX / VexRiscv and to controlled benign plus synthetic malware-like workloads.

Claim level:

```text
35T hardware-trace-assisted synthetic malware-like behavior audit prototype
```

## Verdict

The current evidence supports a bounded prototype paper claim, not a mature detector claim.

```text
paper_support_status: SUPPORTED_WITH_BOUNDED_CLAIMS
strict_single_run_status: PASS
validation_mode: dual_channel
```

The committed machine-readable gate is:

```text
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/paper_evidence_check.json
```

## Evidence Layers

1. Primary full-matrix trace gate
   - Run: `35t-smallcap-r512-full-synthetic-matrix-20260521`
   - Result: `full_matrix_ready`
   - Strict sample gate: 13/13 PASS
   - Sample status: 13/13 PASS
   - Trace budget: 512 records
   - Trace policy: `35t_small_capacity`

2. Targeted side-channel semantic closure
   - Validation run: `35t-targeted-board-validation-20260522`
   - Trace-gate run: `35t-smallcap-r512-full-synthetic-matrix-20260521`
   - Semantic run: `35t-targeted-board-validation-20260522`
   - Validation mode: `dual_channel`
   - Strict trace gate: 13/13 PASS
   - Selected validation bundle: PASS
   - Hardware validated: true
   - fd/path flow: PASS
   - process tree: PASS
   - source attribution: PARTIAL

3. Attribution boundary
   - Function-level attribution: PASS through ELF symbol ranges
   - Source-line attribution: unavailable

## Critical Boundary

The paper-facing targeted validation gate is dual-channel. The low-perturbation
trace-gate channel supplies the strict 13/13 full-matrix gate, and the
side-channel channel supplies selected semantic closure. The side-channel
semantic capture is not itself a single-trace full-matrix all-gates result.

```text
targeted_validation_mode: dual_channel
targeted_trace_gate_run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
targeted_trace_gate_strict_sample_gate: 13/13 PASS
targeted_side_channel_claim_level: prototype_only
targeted_side_channel_sample_status: 13/13 PASS
targeted_side_channel_strict_sample_gate: 9/13 PASS
```

Strict sample-gate failures:

- `batch_open_read_write`: missing strong expected evidence, marker scope failure, median drop rate over 5%, trace cap hit, runtime process attribution blocked
- `illegal_trap`: missing strong expected evidence, marker scope failure, median drop rate over 5%, trace cap hit, runtime process attribution blocked
- `process_chain`: missing strong expected evidence, marker scope failure, median drop rate over 5%, trace cap hit, runtime process attribution blocked
- `dynamic_executable_memory`: missing strong expected evidence

## Supported Wording

Acceptable:

```text
RV-MalTrace demonstrates a 35T hardware-trace-assisted synthetic behavior audit prototype over controlled benign and synthetic malware-like workloads.
```

```text
The targeted 35T validation bundle uses a dual-channel design: the strict trace-gate channel passes the 13-sample full matrix, while the side-channel channel closes representative fd/path and clone/wait explanation paths.
```

## Forbidden Wording

Do not claim:

- CVA6 validation
- real malware execution or real malware detection
- classifier accuracy, family coverage, IOC coverage, or TTP coverage
- mature production detector readiness
- complete semantic reconstruction
- source-line attribution
- single-trace all-gates PASS for the side-channel semantic capture
