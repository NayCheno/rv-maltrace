# 35T Paper Evidence Check: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: PASS

Paper support status: SUPPORTED_WITH_BOUNDED_CLAIMS

Strict single-run status: PASS

Validation mode: dual_channel

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Primary Full-Matrix Gate

- run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
- claim_level: full_matrix_ready
- samples gate PASS: 13/13
- sample status PASS: 13/13
- trace_records: 512
- trace_profile_policy: 35t_small_capacity
- UNKNOWN events: 0
- corrupt records: 0

## Targeted Validation Gate

- validation_run_id: 35t-targeted-board-validation-20260522
- trace_gate_run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
- next gate claim_level: full_matrix_ready
- samples gate PASS: 13/13
- sample status PASS: 13/13

## Targeted Side-Channel Semantic Closure

- semantic_run_id: 35t-targeted-board-validation-20260522
- side-channel samples gate PASS: 9/13
- side-channel sample status PASS: 13/13
- bundle status: PASS
- checker status: PASS
- hardware_validated: true
- fd/path: PASS (syscall_side_channel)
- process tree: PASS (2 edges)
- function attribution: PASS
- source attribution: PARTIAL

## Focused Side-Channel Closure

- closure_run_id: 35t-sidechannel-closure-r2048-20260522
- trace_records: 2048
- focused samples gate PASS: 4/4
- focused sample status PASS: 4/4
- status: PASS
- gate report: results/experiments/35t/35t-sidechannel-closure-r2048-20260522/aggregate/gate_report.json
- plan: docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/side_channel_closure_plan.json

This focused R2048 closure covers the four previously failing side-channel samples. It does not convert the earlier R512 side-channel semantic capture into a single-run 13/13 side-channel result.

## Assessment Requirement Matrix

- status: ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK
- requirement count: 14

## Hardware Trace Prototype

- status: HARDWARE_TRACE_PROTOTYPE_PASS_35T_SMALL_CAPACITY
- trace_records: 512
- trace_profile_policy: 35t_small_capacity
- samples gate PASS: 13/13
- decoded trace files: 65

Boundaries:
- 35T / LiteX / VexRiscv only; no CVA6 board claim
- decoded trace artifacts are local evidence and large raw UART logs remain outside the lightweight snapshot
- hardware trace evidence supports the prototype trace gate, not complete semantic reconstruction by itself

## Local Code Analysis

- status: LOCAL_CODE_ANALYSIS_PROTOTYPE_PASS_WITH_BOUNDED_ATTRIBUTION
- samples: 13
- complete trace-on repetitions: 65/65

Boundaries:
- PC-in-ELF is static code-range evidence, not complete process ownership
- stronger process ownership still depends on marker scope plus runtime process map evidence
- source-line attribution is unavailable in this evidence set
- complete semantic reconstruction is not claimed
- rule-based audit is synthetic behavior triage, not real malware detection quality evidence

## Malware Behavior Audit

- status: SYNTHETIC_MALWARE_LIKE_BEHAVIOR_AUDIT_PASS_REAL_MALWARE_DEFERRED
- samples: 8
- rules: 8
- gate expected rules PASS: 8/8

Boundaries:
- no real malware execution
- no real malware analysis or detection claim
- no malware family, IOC, or TTP coverage claim
- no classifier accuracy claim
- per-repetition audit variation is recorded; the 3.3 pass claim is the aggregate 35T gate result

## Raw Artifact Sanitization

- status: RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED
- class count: 2
- full raw material: deferred until explicit sanitization approval or controlled-release approval

## Raw Artifact Escrow

- status: LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED
- payload files: 66
- payload bytes: 3681202
- package dir: results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_escrow_package

## Supported Claims

- 35T / LiteX / VexRiscv prototype scope
- controlled benign and synthetic malware-like workload matrix
- 512-record 35T small-capacity primary trace gate with 13/13 sample gate PASS
- targeted dual-channel validation bundle with strict trace gate separated from side-channel semantic capture
- targeted board side-channel fd/path closure for representative file-scan behavior
- targeted board side-channel clone/wait process-edge closure for representative process-chain behavior
- focused R2048 side-channel closure for the four previously failing semantic samples
- 512-record 35T small-capacity hardware trace prototype with decoded trace artifacts for all trace-on repetitions
- full-matrix local code-analysis artifacts for code maps, trace-code joins, runtime process maps, semantic recovery, and rule audit
- 8-rule synthetic malware-like behavior audit with real-malware detection claims explicitly deferred
- ELF-symbol function-level attribution for the case-study samples

## Forbidden Claims

- CVA6 validation
- real malware execution or real malware detection
- classifier accuracy, family coverage, IOC coverage, or TTP coverage
- mature production detector readiness
- complete semantic reconstruction
- source-line attribution
- single-trace all-gates PASS for the side-channel semantic capture

## Limitations

- The evidence chain is dual-channel: a low-perturbation trace-gate channel supplies the strict full-matrix gate, while a syscall side-channel capture supplies semantic closure evidence.
- The side-channel semantic capture is not itself a strict single-trace all-gates PASS and must not be used as the trace-gate channel.
- The R2048 side-channel closure is a focused larger-buffer follow-up for the four failed samples, not a single 13-sample side-channel rerun.
- Hardware trace evidence is scoped to 35T / LiteX / VexRiscv and must not be generalized to CVA6.
- Local code analysis is prototype-level attribution: PC-in-ELF is static code-range evidence and source-line attribution remains unavailable.
- Malware analysis is a controlled synthetic behavior-rule audit, not real malware execution, family classification, IOC/TTP coverage, or detector accuracy evidence.
- Function attribution is symbol/range based; source-line records are unavailable.
- Process-tree evidence still leaves the target parent PID unresolved and must not be described as complete process ownership.

## Side-Channel Gate Failures

- batch_open_read_write: failures=missing_strong_expected, marker_scope, drop_rate_median_gt_5pct; blockers=trace_record_cap_hit, runtime_process_attribution; marker=FAIL; runtime=BLOCKED; capped_reps=5
- illegal_trap: failures=missing_strong_expected, marker_scope, drop_rate_median_gt_5pct; blockers=trace_record_cap_hit, runtime_process_attribution; marker=FAIL; runtime=BLOCKED; capped_reps=5
- process_chain: failures=missing_strong_expected, marker_scope, drop_rate_median_gt_5pct; blockers=trace_record_cap_hit, runtime_process_attribution; marker=FAIL; runtime=BLOCKED; capped_reps=5
- dynamic_executable_memory: failures=missing_strong_expected; blockers=none; marker=PASS; runtime=PASS; capped_reps=0

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim

## Warnings

- side-channel semantic capture has strict gate failures and is not used as the trace-gate channel

## Failures

- none
