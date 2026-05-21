# RV-MalTrace 35T Application Closure Result Card

## Scope

This result card is limited to Artix-7 35T / LiteX / VexRiscv.

It does not start or include CVA6 validation, real malware execution, real malware detection accuracy, a mature detector claim, or complete semantic reconstruction.

## Current Claim Level

Current claim level:

```text
35T hardware-trace-assisted synthetic malware-like behavior audit prototype
```

Recommended short interpretation:

```text
RV-MalTrace has completed a controlled 35T prototype loop: hardware trace,
runtime process attribution, local ELF/code-map assisted trace analysis, and
rule-based audit over benign and synthetic malware-like workloads.
```

## Evidence Bundle

Primary run:

```text
run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
trace_records: 512
trace_profile_policy: 35t_small_capacity
samples: 13
gate: 13/13 PASS
full_matrix_ready: True
```

Primary committed evidence snapshot:

```text
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/README.md
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/evidence_manifest.json
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/sample_matrix_summary.md
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/case_study_artifact_index.json
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/source_attribution_summary.md
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/explanation_readiness_summary.md
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_attempt_summary.md
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_plan.md
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_preflight.md
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_runbook.md
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_status.md
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/command_log.md
```

Source result paths retained for local provenance:

```text
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/run_config.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/semantic_failure_triage.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/semantic_failure_triage.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/process_chain_capacity_debug.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/process_chain_capacity_debug.json
```

Checked source and planning references:

```text
docs/planning/rv_maltrace_35t_gap_and_next_steps.md
tools/experiment_35t.py
tools/check_35t_next_gate.py
tools/triage_35t_semantic_failures.py
src/rv_maltrace/trace_profiles.py
tools/build_code_map.py
tools/join_trace_code_map.py
experiments/linux_behavior/malware_like/manifest.json
experiments/linux_behavior/behavior_audit_rules.json
docs/linux/linux_behavior_audit.md
```

Relevant boundary facts:

- `experiments/linux_behavior/malware_like/manifest.json` marks the workload class as `malware_like_synthetic`.
- Every malware-like sample in that manifest has `real_malware: false`.
- `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/run_config.json` records `real_malware: forbidden`.
- `experiments/linux_behavior/behavior_audit_rules.json` lists non-goals: real malware execution, malware detection quality claim, and classifier accuracy claim.

## Hardware Trace Result

The current 35T run used a fixed 512-record trace budget. It did not pass by increasing the trace ring to 1024 records.

The run passed the current next gate:

- 13 samples, 13/13 PASS.
- Marker scope valid for every trace-on repetition.
- Runtime process attribution valid for every trace-on repetition.
- UNKNOWN/corrupt event count is zero.
- Median DROP rate is within the gate limit.
- No capped repetitions were observed.
- Strong expected audit evidence is present for every expected synthetic rule.

The top-level trace profile is `p0c_syscall_trap_drop`, but `trace_profile_policy: 35t_small_capacity` selects per-sample minimal profiles:

- `illegal_trap`: `p0c_syscall_trap_drop`, because trap evidence is required.
- The other 12 samples: `p0a_syscall_drop`, because syscall entry/return, marker, and DROP accounting are enough for the current expected rule evidence.

## Local Code Analysis Support

The local code-map tooling is present and self-tested:

- `tools/build_code_map.py` emits `schema: rvmt.code_map.v1`.
- Code maps include ELF identity, SHA-256 hash, load ranges, sections, symbols, syscall sites, and trap sites.
- `tools/join_trace_code_map.py` joins trace events with code-map evidence and can use `rvmt.runtime_process_map.v1`.
- The trace-code join summary uses `schema: rvmt.trace_code_join.summary.v1` and records `attribution_model: marker_scope_static_code_map_runtime_process_map`.

The evidence bundle contains per-sample code maps and trace-code joins. Example case-study artifacts:

```text
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/illegal_trap/build/illegal_trap.code_map.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/illegal_trap/board/trace-on/rep_00/trace_code_map/trace_code_map_summary.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/process_chain/build/process_chain.code_map.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/trace_code_map/trace_code_map_summary.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/dynamic_executable_memory/build/dynamic_executable_memory.code_map.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/dynamic_executable_memory/board/trace-on/rep_00/trace_code_map/trace_code_map_summary.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/file_scan/build/file_scan.code_map.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/file_scan/board/trace-on/rep_00/trace_code_map/trace_code_map_summary.json
```

Important limitation:

```text
PC-in-ELF is static code-range evidence. It is not complete process ownership
by itself. Strong attribution still depends on marker scope and runtime process
map evidence, and would need PID/SATP/ASID or equivalent runtime load-map
evidence for broader claims.
```

## Synthetic Malware-like Behavior Audit Result

The current behavior audit is controlled, synthetic, and rule-based.

The audit rules cover:

- `many_file_scan`
- `batch_file_read_write`
- `self_copy_simulation`
- `abnormal_syscall_sequence`
- `illegal_instruction_trap`
- `process_creation_chain`
- `dynamic_executable_memory`
- `anti_analysis_indicator`

The current run demonstrates synthetic behavior-rule hits under 35T hardware trace and runtime/code-map assisted analysis. It does not measure real malware detection quality, family coverage, IOC coverage, TTP coverage, or classifier accuracy.

## Full Matrix Summary

| Sample | Class | Profile | Gate | Strong Evidence | Notes |
|---|---|---|---|---|---|
| `hello` | benign | `p0a_syscall_drop` | PASS | yes, baseline gate satisfied | baseline; expected audit rules are none |
| `ls` | benign | `p0a_syscall_drop` | PASS | yes, benign baseline with overlap explained | `many_file_scan` is treated as benign expected overlap, not unexpected strong malware evidence |
| `cat` | benign | `p0a_syscall_drop` | PASS | yes, baseline gate satisfied | baseline; expected audit rules are none |
| `cp` | benign | `p0a_syscall_drop` | PASS | yes, baseline gate satisfied | baseline; expected audit rules are none |
| `sha256sum` | benign | `p0a_syscall_drop` | PASS | yes, baseline gate satisfied | baseline; expected audit rules are none |
| `file_scan` | `malware_like_synthetic` | `p0a_syscall_drop` | PASS | yes | synthetic only; `many_file_scan` matched |
| `batch_open_read_write` | `malware_like_synthetic` | `p0a_syscall_drop` | PASS | yes | synthetic only; `batch_file_read_write` matched |
| `self_copy_sim` | `malware_like_synthetic` | `p0a_syscall_drop` | PASS | yes | synthetic only; `self_copy_simulation` matched |
| `abnormal_syscall_sequence` | `malware_like_synthetic` | `p0a_syscall_drop` | PASS | yes | synthetic only; `abnormal_syscall_sequence` matched |
| `illegal_trap` | `malware_like_synthetic` | `p0c_syscall_trap_drop` | PASS | yes | trap profile needed; `illegal_instruction_trap` matched |
| `process_chain` | `malware_like_synthetic` | `p0a_syscall_drop` | PASS | yes | capacity risk resolved under 512 records; `process_creation_chain` matched |
| `dynamic_executable_memory` | `malware_like_synthetic` | `p0a_syscall_drop` | PASS | yes | synthetic only; `dynamic_executable_memory` matched |
| `anti_debug_like` | `malware_like_synthetic` | `p0a_syscall_drop` | PASS | yes | synthetic only; `anti_analysis_indicator` matched |

## Case Study Index

Detailed case studies are in:

```text
docs/results/rv_maltrace_35t_application_case_studies.md
```

Covered cases:

- `illegal_trap`
- `process_chain`
- `dynamic_executable_memory`
- `file_scan`

## What This Proves

- The current RV-MalTrace prototype has a 35T/LiteX/VexRiscv hardware trace evidence chain for the controlled matrix.
- Under a 512-record trace budget, `35t_small_capacity` per-sample profiling can keep the full 13-sample matrix within marker, runtime attribution, UNKNOWN/corrupt, DROP, capacity, and strong-evidence gates.
- Local code-map assisted trace analysis works at the prototype level through `rvmt.code_map.v1` and `rvmt.trace_code_join.summary.v1`.
- Synthetic malware-like behavior-rule audit can recover and audit controlled syscall/trap patterns for the current samples.
- `process_chain` is no longer a 35T full-matrix blocker under the current 512-record small-capacity policy.

## What This Does Not Prove

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
- no real malware accuracy, classifier accuracy, family coverage, IOC coverage, or TTP coverage claim
- no claim that static PC-in-ELF evidence alone proves complete process ownership

## Regression Commands

| Command | Status | Reason | Next action |
|---|---|---|---|
| `uv run python tools/experiment_35t.py --stage self-test` | PASS | Reported `[PASS] 35T experiment self-test`. | Keep in regression gate. |
| `uv run python tools/check_35t_next_gate.py --self-test` | PASS | Reported `[PASS] 35T next gate self-test`. | Keep in regression gate. |
| `uv run python tools/triage_35t_semantic_failures.py --self-test` | PASS | Reported `[PASS] semantic failure triage self-test`. | Keep in regression gate. |
| `uv run python tools/recover_behavior.py --self-test` | PASS | Reported `[PASS] behavior recovery self-test`. | Keep in regression gate. |
| `uv run python tools/audit_behavior.py --self-test` | PASS | Reported `[PASS] behavior audit self-test`. | Keep in regression gate. |
| `uv run python tools/build_code_map.py --self-test` | PASS | Reported `[PASS] build_code_map self-test`. | Keep in regression gate. |
| `uv run python tools/join_trace_code_map.py --self-test` | PASS | Reported `[PASS] join_trace_code_map self-test`. | Keep in regression gate. |
| `uv run python -m compileall tools src/rv_maltrace` | PASS | `compileall` completed for `tools` and `src/rv_maltrace`. | Keep after tooling edits. |

No command was hidden, skipped, or converted to PASS without execution.

## Remaining Work

Priority backlog:

1. `fd/path flow recovery`
   - Current status: committed summary remains `PARTIAL`; the updated flow logic now separates target entries from return-only register snapshots and the readiness summary aggregates `file_scan`, `batch_open_read_write`, and `self_copy_sim` across 5 reps.
   - Remaining goal: recover dereferenced path strings and stronger paired `openat(path) -> fd -> read/write/getdents64/close` relations from targeted board evidence.
   - Value: improves `file_scan`, `batch_open_read_write`, and `self_copy_sim` explanations without raising the claim beyond synthetic behavior audit.

2. `process tree explanation`
   - Current status: committed summary remains `PARTIAL`; the updated process-tree logic no longer closes an edge unless clone-return child PID and wait PID evidence match.
   - Remaining goal: capture parent-side positive clone-return child PID, exec boundary, child runtime ownership, and wait PID evidence in the same board evidence window.
   - Value: improves `process_chain` presentation beyond current syscall-shape evidence without claiming complete process-tree reconstruction.

3. `function/source-line attribution`
   - Current status: function-level attribution is available from ELF symbols; source-line attribution is unavailable in the committed evidence because source locations/DWARF line records are absent.
   - Committed status artifact: `source_attribution_summary.md` is `PARTIAL`.
   - Goal: retain or derive source-line records and join them back to target syscall/trap PCs.
   - Value: strengthens local code analysis wording without claiming full reconstruction.

4. `strong/weak/benign-overlap separation`
   - Goal: keep strong evidence, weak shape, and benign expected overlap separate in reports.
   - Value: prevents benign behavior from being written as malware detection success.

5. `targeted 35T board validation`
   - Current status: `board_validation_status.md` is `RESULTS_PARTIAL`; the attempted board-validation bundle is not a strict PASS.
   - Current attempt: `board_validation_attempt_summary.md` records validation run `35t-targeted-board-validation-20260522`; groundtruth, rootfs, board capture, analyze, report, and next-gate completed, with 13/13 sample status PASS and `full_matrix_ready`.
   - Current preflight: `board_validation_preflight.md` checks host tools, scripts, runbook consistency, and UART visibility only; it is not board validation evidence.
   - Current run entry: `board_validation_runbook.md` lists the exact 35T `groundtruth`, `rootfs`, `board`, `analyze`, `report`, `package`, and `check` commands for validation run `35t-targeted-board-validation-20260522`.
   - Current strict-check result: `CANDIDATE_PARTIAL`; fd/path flow and process-tree summaries remain `PARTIAL`, so hardware validation remains false.
   - Goal: capture the required fd/path, process-tree, source-attribution, and benign-overlap artifacts on Artix-7 35T hardware.
   - Value: turns the current local readiness boundary into board-backed evidence without expanding the claim beyond the 35T synthetic prototype.

## Recommended Paper Wording

Acceptable wording:

```text
We validated the current RV-MalTrace prototype on an Artix-7 35T LiteX/VexRiscv
board using controlled benign and synthetic malware-like workloads.
```

```text
Under a 512-record trace budget, the 13-sample synthetic matrix passes marker
scope, runtime process attribution, UNKNOWN/corrupt, DROP, capacity, and
strong-evidence gates.
```

```text
The current 35T result demonstrates a hardware-trace-assisted synthetic
behavior audit prototype, not a mature real-malware detector.
```

Do not use wording that says or implies:

- RV-MalTrace detects real malware.
- The current result validates CVA6.
- The current synthetic matrix measures real malware detection accuracy.
- The full matrix passed because the trace capacity was increased.
- The system has complete semantic reconstruction.
