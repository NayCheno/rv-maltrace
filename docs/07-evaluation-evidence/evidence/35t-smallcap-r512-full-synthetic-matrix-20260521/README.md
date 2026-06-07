# 35T Evidence Snapshot: 35t-smallcap-r512-full-synthetic-matrix-20260521

## Scope

Artix-7 35T / LiteX / VexRiscv only.

## Claim Level

35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## What Is Included

This directory contains committed lightweight summary artifacts for the primary 35T run:

- `run_config.json`
- `gate_report.json` and `gate_report.md`
- `semantic_failure_triage.json` and `semantic_failure_triage.md`
- `process_chain_capacity_debug.json` and `process_chain_capacity_debug.md`
- `sample_matrix_summary.json` and `sample_matrix_summary.md`
- `case_study_artifact_index.json`
- `fd_path_flow_summary.json` and `fd_path_flow_summary.md`
- `process_tree_summary.json` and `process_tree_summary.md`
- `function_attribution_summary.json` and `function_attribution_summary.md`
- `source_attribution_summary.json` and `source_attribution_summary.md`
- `explanation_readiness_summary.json` and `explanation_readiness_summary.md`
- `board_validation_attempt_summary.json` and `board_validation_attempt_summary.md`
- `board_validation_plan.json` and `board_validation_plan.md`
- `board_validation_preflight.json` and `board_validation_preflight.md`
- `board_validation_runbook.json` and `board_validation_runbook.md`
- `board_validation_status.json` and `board_validation_status.md`
- `paper_evidence_check.json` and `paper_evidence_check.md`
- `fd_path_case_studies.json` and `fd_path_case_studies.md`
- `process_tree_case_study.json` and `process_tree_case_study.md`
- `pointer_semantics_preflight.json` and `pointer_semantics_preflight.md`
- `pointer_snapshot_enablement_gate.json` and `pointer_snapshot_enablement_gate.md`
- `pointer_snapshot_design_review.json` and `pointer_snapshot_design_review.md`
- `advanced_baseline_preflight.json` and `advanced_baseline_preflight.md`
- `artifact_package_readiness.json` and `artifact_package_readiness.md`
- `raw_artifact_sanitization.json` and `raw_artifact_sanitization.md`
- `raw_artifact_escrow.json` and `raw_artifact_escrow.md`
- `paper_artifact_package_manifest.json` and `paper_artifact_package_manifest.md`
- `paper_artifact_release_policy.json` and `paper_artifact_release_policy.md`
- `synthetic_suite_extension_check.json` and `synthetic_suite_extension_check.md`
- `synthetic_extension_host_smoke.json` and `synthetic_extension_host_smoke.md`
- `synthetic_extension_target_smoke.json` and `synthetic_extension_target_smoke.md`
- `synthetic_extension_behavior_smoke.json` and `synthetic_extension_behavior_smoke.md`
- `extension_35t_enablement_preflight.json` and `extension_35t_enablement_preflight.md`
- `baseline_evaluation_summary.json` and `baseline_evaluation_summary.md`
- `baseline_evaluation_check.json` and `baseline_evaluation_check.md`
- `baseline_execution_spec_check.json` and `baseline_execution_spec_check.md`
- `ebpf_baseline_summary.json` and `ebpf_baseline_summary.md`
- `qemu_plugin_build_preflight.json` and `qemu_plugin_build_preflight.md`
- `evaluation_table.json` and `evaluation_table.md`
- `metric_coverage.json` and `metric_coverage.md`
- `threat_model_boundary.json` and `threat_model_boundary.md`
- `helper_alignment.json` and `helper_alignment.md`
- `software_instrumentation_baseline_summary.json` and `software_instrumentation_baseline_summary.md`
- `assessment_closure.json` and `assessment_closure.md`
- `assessment_traceability.json` and `assessment_traceability.md`
- `assessment_requirement_matrix.json` and `assessment_requirement_matrix.md`
- `assessment_reconciliation.json` and `assessment_reconciliation.md`
- `assessment_gate_criteria.json` and `assessment_gate_criteria.md`
- `hardware_trace_prototype.json` and `hardware_trace_prototype.md`
- `local_code_analysis.json` and `local_code_analysis.md`
- `malware_behavior_audit.json` and `malware_behavior_audit.md`
- `remaining_external_work.json` and `remaining_external_work.md`
- `paper_positioning.json` and `paper_positioning.md`
- `command_log.md`

## What Is Not Included

This snapshot intentionally does not include full large trace dumps, full raw UART logs, bitstreams, Vivado builds, board build directories, ELF binaries, or the complete `results/` tree. It does include hash inventory, sanitized public excerpts, and a local controlled escrow manifest for the raw UART and decoded trace classes.

## How To Re-check

Run the committed closure checker from the repository root:

```bash
uv run python tools/check_35t_application_closure.py --repo-root .
```

The checker reads the closure document, case-study document, and this evidence manifest. It does not require hardware, Vivado, board artifacts, or the full local `results/` directory.

Run the paper evidence checker when the full local `results/` directory is available:

```bash
uv run python tools/check_35t_paper_evidence.py --repo-root .
```

Current paper support status is `SUPPORTED_WITH_BOUNDED_CLAIMS`. The same check records `strict_single_run_status: PASS` in `dual_channel` mode: the trace-gate channel is 13/13 strict sample-gate PASS, while the side-channel semantic channel remains 9/13 and must not be described as a single-trace all-gates PASS.

Run the assessment closure checker to map the assessment document's P0-P6 goals
onto the current bounded evidence:

```bash
uv run python tools/check_35t_pointer_semantics_preflight.py --repo-root .
uv run python tools/check_35t_fd_path_case_studies.py --repo-root .
uv run python tools/check_35t_process_tree_case_study.py --repo-root .
uv run python tools/check_35t_pointer_snapshot_gate.py --repo-root .
uv run python tools/check_35t_pointer_snapshot_design_review.py --repo-root .
uv run python tools/check_35t_evaluation_table.py --repo-root .
uv run python tools/check_35t_metric_coverage.py --repo-root .
uv run python tools/check_35t_baseline_execution_spec.py --repo-root .
uv run python tools/check_35t_qemu_plugin_build_preflight.py --repo-root .
uv run python tools/check_35t_threat_model.py --repo-root .
uv run python tools/check_35t_helper_alignment.py --repo-root .
uv run python tools/check_35t_synthetic_suite_extension.py --repo-root .
uv run python tools/check_35t_synthetic_extension_host_smoke.py --repo-root .
uv run python tools/check_35t_synthetic_extension_target_smoke.py --repo-root .
uv run python tools/check_35t_synthetic_extension_behavior_smoke.py --repo-root .
uv run python tools/check_35t_extension_35t_enablement.py --repo-root .
uv run python tools/check_35t_raw_artifact_sanitization.py --repo-root .
uv run python tools/check_35t_raw_artifact_escrow.py --repo-root .
uv run python tools/check_35t_artifact_package_readiness.py --repo-root .
uv run python tools/package_35t_paper_artifacts.py --repo-root .
uv run python tools/check_35t_assessment_closure.py --repo-root .
uv run python tools/check_35t_assessment_traceability.py --repo-root .
uv run python tools/check_35t_assessment_requirement_matrix.py --repo-root .
uv run python tools/check_35t_remaining_external_work.py --repo-root .
uv run python tools/check_35t_paper_positioning.py --repo-root .
uv run python tools/check_35t_assessment_reconciliation.py --repo-root .
uv run python tools/check_35t_assessment_gate_criteria.py --repo-root .
uv run python tools/check_35t_hardware_trace_prototype.py --repo-root .
uv run python tools/check_35t_local_code_analysis.py --repo-root .
uv run python tools/check_35t_malware_behavior_audit.py --repo-root .
uv run python tools/check_35t_evidence_consistency.py --no-write
```

The generated `assessment_closure.md` records P0-P2 as closed for the current
35T prototype, records the host/QEMU/strace, software-instrumentation, and
host eBPF/bpftrace baseline subset as closed, records representative trusted
helper alignment for fd/path and process-tree evidence, keeps QEMU-plugin as a
blocked advanced baseline, records P5 extension sources as implemented but not
yet 35T-gated, and keeps hardware pointer snapshots, expanded sample coverage,
and full paper-artifact packaging as bounded remaining work where the current
repository does not yet contain complete evidence.

Run the baseline evaluation checker to verify the baseline subset separately:

```bash
uv run python tools/check_35t_advanced_baseline_preflight.py --repo-root .
uv run python tools/check_35t_baseline_evaluation.py --repo-root .
```

To prepare a candidate 35T board-validation result bundle from a local run, use:

```bash
uv run python tools/package_35t_board_validation.py --repo-root .
uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_bundle --require-results
```

The primary evidence run bundle remains useful as a local candidate check. The completed board-validation evidence is the separate targeted run `35t-targeted-board-validation-20260522`, which was captured on the 35T board with the syscall side channel enabled.

To inspect the targeted 35T board-validation sequence, follow:

```bash
uv run python tools/prepare_35t_board_validation_run.py --repo-root . --validation-run-id 35t-targeted-board-validation-20260522
```

The generated `board_validation_runbook.md` keeps the source evidence run fixed at `35t-smallcap-r512-full-synthetic-matrix-20260521` while using a separate validation run id for the board capture.

Before running the board stage, use the preflight checker:

```bash
uv run python tools/check_35t_board_preflight.py --repo-root .
```

The preflight status only checks host tools, scripts, runbook consistency, and whether the requested UART port is visible. It does not prove the 35T board image is running and does not count as board validation.

The completed targeted validation bundle is checked with:

```bash
uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle --require-results
```

Current selected-artifact validation result: `PASS`; hardware validation is true for this 35T prototype closure. The targeted validation bundle is `dual_channel`: the trace-gate artifact is 13/13 strict sample-gate PASS, and the side-channel run supplies semantic fd/path and process-tree evidence. The side-channel run itself still has 13/13 `sample_status` PASS but 9/13 strict `samples[].gate_status` PASS, so it is semantic closure evidence, not the trace-gate result. Source attribution remains `PARTIAL`, so this still does not claim complete semantic reconstruction.

## Artifact Index

See `evidence_manifest.json` for hashes and source paths. See `case_study_artifact_index.json` for indexed case-study source artifacts that are referenced but not committed in this lightweight snapshot. The committed fd/path and process-tree summaries are now synchronized from the targeted board-validation bundle and record `PASS`; neither claims complete semantic reconstruction.

`explanation_readiness_summary.md` records the local closure boundary used before the targeted validation run. The follow-up side-channel validation closed fd/path and process-tree summaries; source-line attribution still requires retained source-location evidence.

`function_attribution_summary.md` records function-level attribution `PASS` from ELF symbol ranges. `source_attribution_summary.md` records function-level attribution availability and keeps source-line attribution explicitly unavailable until source-location evidence exists.

`board_validation_plan.md` and `board_validation_status.md` define the targeted 35T board-validation artifact set. The current status is `PASS`; hardware validation is true for the 35T targeted validation bundle.

`board_validation_runbook.md` records the exact command sequence for the targeted 35T board validation run. It is command provenance; the board evidence is in the checked validation bundle and attempt summary.

`board_validation_preflight.md` records the current host and UART readiness for that run plan. It is a readiness check, not board evidence.

`board_validation_attempt_summary.md` records the targeted 35T validation attempt `35t-targeted-board-validation-20260522`: the dual-channel validation bundle is `PASS`, the trace-gate channel is 13/13 strict sample-gate PASS, and the side-channel semantic channel remains 9/13 strict sample-gate PASS. The selected-artifact validation bundle is `PASS`, with fd/path flow and process-tree summaries also `PASS`.

`paper_evidence_check.md` records the paper-facing gate: the primary run supplies the 13/13 strict full-matrix trace result, while the targeted side-channel run supplies fd/path and process-tree semantic closure. It explicitly forbids single-trace all-gates wording for the side-channel semantic capture.

`fd_path_case_studies.md` records the broader P1 fd/path case-study coverage.
It verifies that `file_scan`, `batch_open_read_write`, and `self_copy_sim` each
have a targeted board syscall side-channel candidate with closed fd/path flows.
The compact `fd_path_flow_summary.md` remains the selected `file_scan`
explanation, while this artifact prevents that representative summary from
being over-read as full-suite coverage.

`process_tree_case_study.md` records the P2 process-chain case study. It
verifies positive clone child PIDs, child `execve` path strings, parent
`waitid` PID arguments, and parent-child graph output from the targeted board
syscall side-channel. It keeps the parent PID unresolved until PID/SATP/ASID or
equivalent ownership evidence is available.

`pointer_semantics_preflight.md` records the P3 boundary. Synthetic ARG_MEM
simulation covers pointer strings and guardrails, and board syscall
side-channel evidence closes representative fd/path and process-tree semantics,
but the current 35T small-capacity run still does not enable hardware
user-pointer snapshots.

`pointer_snapshot_enablement_gate.md` records the pre-enable gates for hardware
user-pointer snapshot work. It requires design, safety, timing/resource,
bandwidth/drop, noninterference, semantic accuracy, artifact-policy, and
threat-model evidence before the current `TRACE_MEM_MODE_NONE` policy can be
changed.

`pointer_snapshot_design_review.md` records the bounded design-review evidence
for a future selective user-pointer snapshot route. It keeps the route
default-disabled, limits the current allowlist to bounded `openat` and `execve`
pathname prefixes, forbids default memory-trace payload capture, and does not
claim hardware user-pointer snapshot enablement or measurement pass.

`advanced_baseline_preflight.md` records the packaged-environment capability
boundary for advanced baselines. It probes Docker `linux-behavior` and WSL
separately so capabilities are not combined across environments. The rebuilt
cap-enabled Docker `linux-behavior` path now has clang/llc, bpftrace, writable
tracefs/kprobe access, and a passing bpftrace kprobe smoke, so eBPF-only is
`READY` at preflight level. Packaged Docker still has `qemu-riscv64` without
user-mode `-plugin`, so the preflight remains a packaged-environment boundary;
the completed QEMU-plugin baseline below uses a locally built upstream QEMU
8.2.2 user-mode binary configured with `--enable-plugins`.

`ebpf_baseline_summary.md` records the completed host Linux eBPF/bpftrace
baseline for all 13 samples over 3 reps. It captures comm-filtered
`raw_syscalls:sys_enter` event counts and conservative end-to-end bpftrace
runtime ratios. It is host software baseline evidence, not hardware trace,
QEMU-plugin, pointer snapshot, or real malware evidence.

`baseline_evaluation_summary.md` records that host native, host strace, QEMU
native, QEMU strace, and source-level software instrumentation evidence exists
for all 13 samples. It also records eBPF-only as PASS from
`ebpf_baseline_summary.md` and QEMU-plugin as PASS from
`qemu_plugin_baseline_summary.md`. The QEMU-plugin row is a simulator
syscall-count baseline only; it is not hardware trace, DBI, or real malware
evidence.

`qemu_plugin_build_preflight.md` records that a minimal TCG plugin can be built
and loaded by `qemu-system-riscv64`. `qemu_plugin_baseline_summary.md` records
the separate completed 13-sample user-mode QEMU TCG-plugin baseline. It uses a
local upstream QEMU 8.2.2 `qemu-riscv64` build with `--enable-plugins`, runs all
13 existing RISC-V synthetic samples over 3 reps, and records per-sample syscall
count output and timings under `results/experiments/35t/35t-qemu-plugin-baseline-20260523`.

`software_instrumentation_baseline_summary.md` records the separate
`35t-software-instrumentation-baseline-20260523` host baseline. It uses
GCC `-finstrument-functions` source-level function entry/exit logging, reports
13/13 PASS over 5 reps, and keeps raw function logs in the local `results/`
tree rather than this lightweight snapshot.

`baseline_evaluation_check.md` validates that bounded baseline status.

`baseline_execution_spec_check.md` validates
`experiments/linux_behavior/baseline_execution_spec.json`. That spec maps the
assessment's P4 baseline families to current evidence rows, reproduction
commands, required artifacts, pass gates, and non-substitution rules so blocked
or deferred rows cannot be silently reported as completed comparisons.

`evaluation_table.md` records the bounded P4 evaluation table. It combines
host/QEMU/strace timing, software instrumentation, board trace-on/off ratios,
host eBPF/bpftrace timing, DROP/cap accounting, resource/Fmax summaries, and
`anti_debug_like` synthetic anti-analysis evidence while keeping QEMU-plugin
non-PASS until separate full plugin evidence exists.

`metric_coverage.md` enumerates the P4 metric list from the assessment. It maps
each item to current evidence and explicitly marks which values are measured,
alignment proxies, case-study scoped, or deferred until stronger full-suite
semantic or advanced-baseline evidence exists.

`threat_model_boundary.md` records the P3/P4 threat-model boundary requested by
the assessment. It states the trusted-kernel, user-mode malware-like workload
assumption, keeps helper/eBPF routes optional and deferred, and makes kernel
rootkit resistance an explicit non-claim.

`artifact_package_readiness.md` maps the paper artifact package requested by
the assessment to current local evidence. It verifies 22 required artifact
classes, records that raw UART logs, decoded trace JSONL, and the local escrow
package are local-only or hash/summary artifacts, and keeps full public raw
release deferred until large raw artifacts are explicitly approved for
controlled external release.

`raw_artifact_sanitization.md` inventories the raw UART and decoded trace JSONL
classes for the primary 35T run. It records 1 raw UART log and 65 decoded trace
JSONL files with class hashes, representative file hashes, and sanitized public
excerpts. Full raw release is still deferred; these excerpts are not a
substitute for publishing or escrowing the complete raw artifacts.

`raw_artifact_escrow.md` records the local controlled escrow package under
`results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_escrow_package/`.
It verifies 66 copied raw payload files with sizes and SHA-256 hashes, records
an access policy, and keeps public or external raw release deferred.

`paper_artifact_package_manifest.md` records the generated lightweight
release-candidate package under
`results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/paper_artifact_package/`.
The package contains a README, release policy, hash manifest, reproduction
commands, and copied lightweight evidence summaries. It still does not include
raw UART logs, decoded trace JSONL, generated bitstreams, board build
directories, or ELF binaries.

`paper_artifact_release_policy.md` records which artifact classes can be
included or referenced publicly, which are summary/hash-only, and which remain
local-only until sanitization or controlled-release approval.

`synthetic_suite_extension_check.md` records P5 extension readiness. It keeps
the current claim limited to the existing 8 synthetic malware-like samples,
adds 9 source-implemented disabled-by-default extension candidates, and records
the source/legal/containment/isolation/replay/sanitization gates required
before real malware can enter scope. These sources are not expanded 35T
coverage until they are explicitly enabled, built, and run through the same
gates.

`synthetic_extension_host_smoke.md` records the host compile-only preflight for
those extension sources. The current Windows host uses WSL and `/usr/bin/cc` to
compile all 9 candidates without executing them or starting loopback network
activity. `synthetic_extension_target_smoke.md` records the Docker
`riscv64-linux-gnu-gcc` static RISC-V Linux cross-compile smoke for the same 9
candidates. `synthetic_extension_behavior_smoke.md` records host native,
host strace, QEMU native, and QEMU guest-strace behavior smoke for the 8
non-network candidates, while keeping the loopback network candidate skipped
by default. This evidence still does not claim expanded 35T coverage.

`extension_35t_enablement_preflight.md` records the next P5 prerequisite: the
extension candidates are present in the 35T runner table, remain
default-disabled, are included in the Artix-7 rootfs build path, and can be
selected through explicit `experiment_35t.py --include-extension-samples`
dry-run commands. This preflight still does not execute the board or claim an
extension gate pass.

`assessment_closure.md` maps the assessment goals to current evidence. It is the
quickest way to see which goals are PASS under the 35T prototype boundary and
which remain bounded partial/deferred items.

`assessment_traceability.md` maps the source assessment document's P0-P6
requirements to the current evidence files, accepted statuses, and remaining
bounded conditions. It is the requirement-to-evidence audit for the active
assessment objective and does not upgrade bounded/deferred work to completed
external evidence.

`assessment_requirement_matrix.md` maps the source assessment document section
by section, including the overall conclusion, evidence chain, 3.1 hardware
trace, 3.2 local code analysis, 3.3 malware-analysis boundary, P1-P6 follow-up
items, CCF-A positioning, and final judgment. It verifies 14 requirement rows
against current evidence and keeps P3-P6 external conditions explicit.

`assessment_reconciliation.md` reconciles the source assessment snapshot with
newer evidence. In particular, it records that the P0 claim boundary now has an
independent local-code-analysis gate, that P1/P2 are representative
board-side-channel case-study PASS items, and that P3-P6 still retain explicit
deferred/current-environment boundaries.

`assessment_gate_criteria.md` verifies the specific gate criteria named by the
assessment: the 512-record 35T run is 13/13 PASS, marker scope and runtime
process attribution pass for each trace-on repetition, UNKNOWN/corrupt counts
are zero, DROP remains within limits, cap hits are absent, strong expected
rules are satisfied, `ls` benign overlap is bounded, and per-sample profiles
match the small-capacity policy.

`hardware_trace_prototype.md` verifies the assessment's 3.1 hardware-trace
claim. It checks the primary 35T gate and run config for a 512-record
small-capacity profile policy, 13/13 sample PASS, marker/runtime attribution,
UNKNOWN/corrupt/DROP/cap conditions, and 65 nonempty decoded trace artifacts.
It keeps the evidence scoped to 35T / LiteX / VexRiscv and does not infer CVA6
board validation.

`local_code_analysis.md` verifies the assessment's local-code-analysis claim.
It checks all 13 samples and all 65 trace-on repetitions for board ELF code
maps, trace-code joins, runtime process maps, semantic recovery outputs,
behavior graphs, and rule-based audit files. It keeps the attribution boundary
explicit: PC-in-ELF is static range evidence, source-line attribution is not
available, and the rule audit is synthetic behavior triage rather than real
malware detection quality evidence.

`malware_behavior_audit.md` verifies the assessment's 3.3 malware-analysis
boundary. It checks the 8-rule synthetic malware-like behavior audit against
the rules file, manifest, 35T aggregate gate, and per-repetition audit files.
It records that the current pass claim is controlled synthetic behavior-rule
audit only, not real malware execution, detector accuracy, family
classification, IOC coverage, or TTP coverage.

`remaining_external_work.md` records the external or deferred conditions that
still prevent P3-P6 from being upgraded to fully completed external work. It
ties each item to current evidence, required conditions, unblock criteria, and
no-substitution rules.

`helper_alignment.md` records the P3 trusted-helper side-channel alignment now
satisfied for representative fd/path and process-tree evidence. It is bounded
to trusted Linux-kernel, user-mode malware-like workloads and explicitly is not
a hardware user-pointer memory snapshot, hardware-only trace claim, QEMU-plugin
substitute, or complete semantic reconstruction claim.

`paper_positioning.md` records the publication boundary required by the
assessment: the current 35T line supports bounded low-cost FPGA feasibility /
constrained-board prototype evidence only. It explicitly prevents upgrading the
35T result into a standalone CCF-A main contribution, real malware detection,
CVA6 validation, mature detector, or complete semantic reconstruction claim.

`tools/check_35t_evidence_consistency.py --no-write` verifies that the generated
evidence files agree with each other after regeneration. It checks manifest
hashes, current evidence-file coverage, P6 committed artifact counts,
closure/traceability goal status alignment, source requirement-matrix status,
artifact readiness status, and paper package validation commands.

`board_syscall_side_channel_smoke.md` records the follow-up syscall side-channel work: the new runner builds into the 35T rootfs, the board was rebooted through the LiteX serial image path, and `35t-sidechannel-smoke-20260522e` closed fd/path and process-tree smoke evidence. The later targeted validation bundle passed for selected semantic artifacts after that boot.

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
