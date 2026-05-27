# RV-MalTrace 35T Paper Evidence Chain

## Scope

This paper evidence chain is limited to Artix-7 35T / LiteX / VexRiscv. It covers the controlled benign plus synthetic malware-like primary matrix and the 5/24 real-malware-derived DarthRa/Mirai behavior-validation packages.

Claim level:

```text
35T hardware-trace-assisted malware-behavior evidence-chain prototype
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

4. Real-malware-derived behavior validation
   - Lineage package: `35t-real-malware-derived-lineage-20260524`
   - Baseline package: `35t-real-malware-derived-baseline-comparison-20260524`
   - DarthRa-derived run: `35t-surrogate-darthra-p0a-r512-abba-r5-20260524`
   - Mirai-reference run: `35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524`
   - Result: 6/6 real-malware-derived behavior rows PASS
   - Paper use: evidence that selected behaviors from real malware references are traceable, verifiable, and rule-detectable/auditable on the 35T prototype under safety controls

## Critical Boundary

The paper-facing targeted validation gate is dual-channel. The low-perturbation
trace-gate channel supplies the strict 13/13 full-matrix gate, and the
side-channel channel supplies selected semantic closure. The side-channel
semantic capture is not itself a single-trace full-matrix all-gates result.

For the real-malware-derived cases, the safety controls are an execution and
release boundary, not a reason to exclude the cases from the real-malware
feasibility narrative. The paper can say that RV-MalTrace validated tracking,
verification, and rule-detection/audit recovery for behaviors selected from real malware references. It
should not turn that into an uncontrolled payload-execution, family-accuracy,
IOC/TTP coverage, or payload-equivalence claim.

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
RV-MalTrace demonstrates a 35T hardware-trace-assisted malware-behavior evidence-chain prototype over controlled benign, synthetic malware-like, and real-malware-derived behavior workloads.
```

```text
The targeted 35T validation bundle uses a dual-channel design: the strict trace-gate channel passes the 13-sample full matrix, while the side-channel channel closes representative fd/path and clone/wait explanation paths.
```

```text
The 5/24 real-malware-derived evidence packages show that selected DarthRa- and Mirai-derived behaviors are traceable, verifiable, and rule-detectable/auditable on the Artix-7 35T prototype under safety controls.
```

## Forbidden Wording

Do not claim:

- CVA6 validation
- uncontrolled or network-enabled real-malware payload execution
- malware-family detection accuracy, classifier accuracy, family coverage, IOC coverage, or TTP coverage
- payload equivalence to the original malware binaries or full harmful capability sets
- mature production detector readiness
- complete semantic reconstruction
- source-line attribution
- single-trace all-gates PASS for the side-channel semantic capture
