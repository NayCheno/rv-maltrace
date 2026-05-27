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
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/function_attribution_summary.md
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

## Targeted Board Validation Closure

The follow-up targeted board validation run is:

```text
validation_run_id: 35t-targeted-board-validation-20260522
bundle_root: results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle
validation_mode: dual_channel
trace_gate_run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
semantic_run_id: 35t-targeted-board-validation-20260522
status: PASS
hardware_validated: true
fd_path_flow: PASS
process_tree: PASS
source_attribution: PARTIAL
strict_sample_gate: PASS (trace-gate channel, 13/13 sample gate_status PASS)
side_channel_semantic_gate: FAIL (9/13 sample gate_status PASS, not used as trace gate)
```

The PASS fd/path and process-tree summaries use the board syscall side-channel
evidence captured in that targeted 35T run. They close the representative
`openat(path) -> fd -> getdents64/read/write/close` and
`clone return child PID -> wait PID` explanation paths, while source-line
attribution remains unavailable because no DWARF/source-location records are
present in the committed evidence.

This upgrades the previous manual/committed semantic closure to a dual-channel
targeted 35T validation PASS. The strict trace-gate channel uses the
low-perturbation full-matrix run, while the syscall side-channel channel is
used only for selected semantic closure. The side-channel semantic capture has
13/13 `sample_status` PASS but only 9/13 strict `samples[].gate_status` PASS,
so it must not be described as the single-trace all-gates result.

## Paper Evidence Chain

The paper-supporting evidence chain is layered:

1. Primary full-matrix trace gate:
   - Source: `35t-smallcap-r512-full-synthetic-matrix-20260521`.
   - Result: `full_matrix_ready`, 13/13 strict sample gate PASS, 13/13 sample status PASS, zero UNKNOWN/corrupt events.

2. Targeted side-channel semantic closure:
   - Source: `35t-targeted-board-validation-20260522`.
   - Result: selected validation bundle PASS in `dual_channel` mode, hardware validated, fd/path PASS, process-tree PASS, source attribution PARTIAL.
   - Boundary: side-channel semantic capture remains 9/13 strict sample-gate PASS and is not used as the trace-gate channel; failed side-channel gate samples are `batch_open_read_write`, `illegal_trap`, `process_chain`, and `dynamic_executable_memory`.

3. Attribution boundary:
   - Function-level attribution is PASS through ELF symbol ranges.
   - Source-line attribution is unavailable and must not be claimed.

The committed paper gate is:

```text
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/paper_evidence_check.md
```

Current paper support status:

```text
SUPPORTED_WITH_BOUNDED_CLAIMS
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

The committed function attribution summary is `function_attribution_summary.md`.
It records function-level attribution as `PASS` for the six case-study samples
from ELF symbol ranges. `source_attribution_summary.md` remains `PARTIAL`
because source-line records are unavailable.

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

Closed in the current 35T prototype boundary:

1. `fd/path flow recovery`
   - Current status: `PASS`.
   - Evidence: `fd_path_flow_summary.md` records a board syscall side-channel backed `openat(path) -> fd -> getdents64 -> getdents64 -> close` flow for `file_scan`, including `path_source`, `fd_generation`, `open_seq`, `ops`, and closed lifetime status.

2. `process tree explanation`
   - Current status: `PASS`.
   - Evidence: `process_tree_summary.md` records matched clone-return child PID and wait PID edges for `process_chain`, plus exec path source metadata.

3. `targeted 35T board validation`
   - Current status: `PASS`.
   - Evidence: `board_validation_status.md` and `board_validation_attempt_summary.md` point to `35t-targeted-board-validation-20260522`, with `validation_mode: dual_channel`, trace-gate 13/13 strict sample gate PASS, side-channel semantic gate 9/13 PASS, selected fd/path and process-tree validation PASS, and hardware validation true for the current prototype claim.

Still deliberately not claimed:

1. `single-run all-gates side-channel result`
   - Current status: not claimed.
   - The targeted side-channel semantic capture remains `prototype_only` with strict sample gate failures for `batch_open_read_write`, `illegal_trap`, `process_chain`, and `dynamic_executable_memory`; it is deliberately separated from the trace-gate channel.

2. `source-line attribution`
   - Current status: source-line unavailable.
   - Function-level attribution is `PASS` through ELF symbol ranges in `function_attribution_summary.md`; `source_attribution_summary.md` remains `PARTIAL` because no DWARF/source-location records are committed.

3. `complete semantic reconstruction`
   - fd/path and process-tree explanations are closed for the targeted 35T validation artifacts, but they do not prove complete process ownership, complete memory semantics, or broad semantic reconstruction.

4. `real malware accuracy or payload-equivalence`
   - Strong, weak, and benign-overlap evidence must remain separated. The 5/24 real-malware-derived packages support a feasibility statement about tracking, validating, and rule-detecting/auditing selected behaviors from real malware references; they do not measure malware-family accuracy, IOC/TTP coverage, or equivalence to the original harmful payloads.

## Recommended Paper Wording

Acceptable wording:

```text
We validated the current RV-MalTrace prototype on an Artix-7 35T LiteX/VexRiscv
board using controlled benign, synthetic malware-like, and real-malware-derived
behavior workloads.
```

```text
Under a 512-record trace budget, the 13-sample synthetic matrix passes marker
scope, runtime process attribution, UNKNOWN/corrupt, DROP, capacity, and
strong-evidence gates.
```

```text
The current 35T result demonstrates that selected behaviors from real malware
references can be traced, verified, and rule-detected/audited under safety controls; it
does not claim malware-family accuracy or mature detector readiness.
```

Do not use wording that says or implies:

- RV-MalTrace measures real-malware family detection accuracy.
- The current result validates CVA6.
- The current result executes uncontrolled or network-enabled malware payloads.
- The current result is payload-equivalent to the original malware binaries.
- The full matrix passed because the trace capacity was increased.
- The system has complete semantic reconstruction.
