# Check Suites

Use check suites instead of picking commands from the long workflow catalog.
The suite manifest is `tools/check_suites.json`, and the runner is:

```powershell
uv run python tools/run_check_suite.py --list-suites
```

## Reviewer Shortcuts

Use these short commands before reaching for the long suite catalog:

```powershell
uv run rvmt repro:quick
uv run rvmt repro:local
uv run rvmt repro:full
```

`repro:quick` is the lightweight manifest/package check. `repro:local` is the
recommended local CCF-A evidence-package reproduction pass: it adds current
quality, case-study, and bitstream-artifact checks while avoiding board/Vivado
reruns. `repro:full` is the strict closure suite and is allowed to fail while
the external UART streaming evidence remains unresolved.

## Current Route

Current Digilent Genesys2 + CVA6 gate:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-current
```

Compatibility wrapper:

```powershell
uv run python tools/check_genesys2_current.py
```

This is the default fast round. It checks existing repository evidence and local
policy gates; it must not run Vivado synthesis, implementation, or bitstream
generation. The current standard is
`results/evaluation/genesys2-cva6/current/latest_manifest.json`; current gates
must resolve board run roots through this manifest instead of selecting a
`202606xx-*` directory by chronological order. Dated board result directories
remain provenance for transcripts and hashes, not the selection mechanism. It
also runs `tools/check_ccfa_claim_boundaries.py`, which rejects
safe-surrogate, ILA/debug-sink, multi-window, process-attribution, and
simulation/board overclaims, `tools/check_risk_log_current.py`, which keeps
the process risk log synchronized with the current evidence boundary and
external-closure state, and `tools/check_evaluation_plan.py`, which keeps
`docs/07-evaluation-evidence/evaluation_plan.md` synchronized with the current
scoped evidence index instead of the old placeholder planning state.
`tools/check_genesys2_review_closure_audit.py` keeps the original review
requirements mapped to current evidence, objective exclusions, and the four
still-open external intake records. The current
round also checks the Phase 4.4 baseline pass criteria against the documented
Genesys2 board run, the manifest-selected Genesys2/CVA6 P0 continuous
recapture, the Phase C BRAM ring trace-sink board evidence, the
safe-surrogate BRAM marker-window board evidence,
captured-window drop accounting, controlled repetition/statistical robustness,
bounded fuzz trace invariant fixtures,
streaming/DMA target-baseline evidence,
bounded-prefix pointer snapshot guardrails,
hardware ARG_MEM byte-prefix evidence, full hardware pointer-string readiness,
BRAM-first trace-export boundary,
source-line toolchain probe evidence, debug ELF source-line rerun readiness,
benign-control false-positive evidence,
per-sample controlled case-study packages,
reproducibility manifest linkage, lightweight artifact-package/fresh-clone
reproduction linkage, external closure readiness contracts, the
external closure intake gate, the external closure execution plan, and the
external closure local preflight gate, the external operator handoff packet,
plus the external summary template
non-evidence guard, plus the
Phase D/E/F controlled safe-surrogate semantic/provenance/evaluation
summaries. It then runs a current-quality artifact-integrity gate over the
non-real-malware evidence chain, plus the real-malware containment policy
boundary:

```powershell
uv run python tools/check_genesys2_latest_standard.py --root .
uv run python tools/check_board_baseline.py --root .
uv run python tools/check_baseline_pass_criteria.py --root .
uv run python tools/check_board_trace_minimal.py --root .
uv run python tools/check_trace_export_decision.py --root .
uv run python tools/check_board_trace_programs.py --root .
uv run python tools/check_board_trace_evidence.py --root .
uv run python tools/check_board_local_code_analysis.py --root .
uv run python tools/check_genesys2_safe_surrogate.py --root .
uv run python tools/check_genesys2_safe_surrogate_coverage.py --root .
uv run python tools/check_genesys2_cva_evidence_boundary.py --root .
uv run python tools/check_ccfa_claim_boundaries.py --root .
uv run python tools/check_genesys2_p0_continuous_trace.py --root .
uv run python tools/check_risk_log_current.py --root .
uv run python tools/check_evaluation_plan.py --root .
uv run python tools/check_genesys2_review_closure_audit.py --root .
uv run python tools/check_genesys2_cva_closure_readiness.py --root .
uv run python tools/check_genesys2_oled_status.py --root .
uv run python tools/check_genesys2_bram_trace_sink_readiness.py --root .
uv run python tools/check_genesys2_bram_trace_sink.py --root .
uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .
uv run python tools/check_genesys2_p0_bram_trace.py --root .
uv run python tools/check_trace_drop_accounting.py --root .
uv run python tools/check_fuzz_trace_plan.py --root .
uv run python tools/check_genesys2_statistical_robustness.py --root .
uv run python tools/check_genesys2_streaming_dma_target.py --root .
uv run python tools/check_genesys2_streaming_dma_readiness.py --root .
uv run python tools/check_pointer_snapshot_guardrails.py --root .
uv run python tools/check_hardware_pointer_prefixes.py --root .
uv run python tools/check_genesys2_pointer_string_readiness.py --root .
uv run python tools/check_syscall_semantic_reconstruction.py --root .
uv run python tools/check_fd_path_graph.py --root .
uv run python tools/check_source_line_attribution.py --root .
uv run python tools/check_source_line_toolchain_probe.py --root .
uv run python tools/check_genesys2_debug_elf_readiness.py --root .
uv run python tools/check_process_elf_ownership.py --root .
uv run python tools/check_dynamic_mapping_attribution.py --root .
uv run python tools/check_ccfa_evaluation_matrix.py --root .
uv run python tools/check_baseline_alignment.py --root .
uv run python tools/check_behavior_audit_metrics.py --root .
uv run python tools/check_ccfa_case_study_manifest.py --root .
uv run python tools/check_benign_control_summary.py --root .
uv run python tools/check_genesys2_board_benign_readiness.py --root .
uv run python tools/check_ccfa_current_quality.py --root .
uv run python tools/check_genesys2_reproducibility_manifest.py --root .
uv run python tools/check_genesys2_artifact_package.py --root .
uv run python tools/check_genesys2_external_closure_readiness.py --root .
uv run python tools/check_genesys2_external_closure_intake.py --root .
uv run python tools/check_genesys2_external_closure_plan.py --root .
uv run python tools/check_genesys2_external_closure_preflight.py --root .
uv run python tools/check_genesys2_external_operator_packet.py --root .
uv run python tools/prepare_genesys2_external_summary.py --root . --check-templates
uv run python tools/check_real_malware_containment.py --root .
```

The BRAM trace-sink gate is evidence-backed, not just a static RTL inspection.
It requires `results/evaluation/genesys2-cva6/current/trace_sink_summary.json`
to summarize 10/10 `hello_write` and 10/10 `illegal_instruction` repetitions
from `results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/`
with parse success, expected event recall, and unaccounted drops checked by
`tools/check_genesys2_bram_trace_sink.py`.
The safe-surrogate BRAM marker-window gate requires
`results/evaluation/genesys2-cva6/current/safe_surrogate_bram_trace_summary.json`
to summarize one board `bram_ring` repetition for each of the eight safe
syscall-only surrogate workloads from
`results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait/`,
with begin-marker clearing, expected raw syscall-entry counts, no sequence
gaps, no wrap, and zero unaccounted drops checked by
`tools/check_genesys2_safe_surrogate_bram_trace.py`.
The drop-accounting gate is intentionally scoped to captured trace windows; it
does not convert raw trace captures into pointer semantic reconstruction or a
full CCF-A real-malware claim.
The statistical robustness gate verifies
`results/evaluation/genesys2-cva6/current/statistical_robustness_summary.json`:
120 accepted controlled board marker-window repetitions across 12 P0 and
safe-surrogate samples, one retained failed P0 attempt, zero accepted-window
unaccounted DROP/wrap/dropped count, 12 controlled case studies, and five local
benign controls with unexpected false-positive rate 0.0. It is not a randomized
workload generalization study, real-malware validation, production long-run
stability evidence, or Genesys2 board benign-control evidence.

The streaming/DMA target gate verifies
`results/evaluation/genesys2-cva6/current/streaming_dma_target_summary.json`:
the 120 accepted marker-window repetitions define a p95 target of
`0.01981178801386825` compact event bytes per marker-window cycle for future
non-BRAM transport experiments. It is not production streaming/DMA throughput
evidence; future summaries still need exact streaming-bitstream clock, host
receiver, timing, resource, drop, and noninterference artifacts.
`tools/check_genesys2_streaming_dma_readiness.py` verifies
`streaming_dma_readiness_summary.json`, which turns the p95 target into a
future non-BRAM transport contract: allowed/disallowed transport kinds, exact
clock conversion, host receiver log fields, required evidence artifact kinds,
summary fields, and no-substitution boundaries. It is readiness only and does
not complete production streaming/DMA throughput evidence.

The Phase D/E/F gates consume
`results/evaluation/genesys2-cva6/current/semantic_reconstruction_summary.json`,
`fd_path_graph_summary.json`, `source_line_attribution_summary.json`,
`process_elf_ownership_summary.json`, `dynamic_mapping_attribution_summary.json`,
`ccfa_evaluation_matrix.json`, `baseline_alignment_summary.json`, and
`behavior_audit_metrics.json`. These summaries are generated by
`tools/package_ccfa_phase_def_summaries.py` from the P0 continuous traces, the
safe-surrogate BRAM run, Genesys2 runtime process maps, safe/P0 qemu and strace
transcripts, and source-equivalent sidecar metadata. The pointer snapshot
guardrail gate currently passes for bounded-prefix hardware ARG_MEM evidence
covering openat / execve / write. It still records no full memory dump, no
kernel memory capture, no raw pointer payload release, and no hardware-derived
full pointer-string claim. Pointer argument strings remain companion-derived
unless the hardware ARG_MEM prefix itself directly supports the narrower claim.
`hardware_pointer_prefix_summary.json` is the narrower board-backed artifact for
that last case: it verifies 30 BRAM pointer-snapshot repetitions, hardware
byte fragments/prefixes for openat / write / execve, zero kernel fragments, and
an explicit non-claim for complete hardware strings.
`tools/check_genesys2_pointer_string_readiness.py` verifies
`pointer_string_readiness_summary.json`, which turns the prefix/guardrail
evidence into a future full-string contract requiring contiguous bytes from
offset 0, terminator or bounded-truncation evidence, mem_last/terminator
reporting, artifact hashes, redaction policy, and no companion or
gapped-fragment substitution. It is readiness only and does not complete full
hardware pointer-string evidence.
The behavior audit gate also requires the eight safe-surrogate samples to have
per-sample `semantic_events.json`, `behavior_graph.json`, `behavior_mapping.json`,
`integrated_validation.json`, and `behavior_audit_metrics.json` wrappers under
`results/evaluation/genesys2-cva6/current/samples/<sample>/`, each marked as
safe malware-like audit evidence rather than real malware validation.
`tools/check_ccfa_case_study_manifest.py` verifies
`case_study_manifest.json` and every per-sample `case_study_summary.json`.
Those summaries package the trace, semantic reconstruction, local code
attribution, baseline comparison, audit decision, metrics, limitations, and
reviewer traceability for all P0 and safe-surrogate samples.
`tools/check_benign_control_summary.py` verifies
`benign_control_summary.json`, which records five local Linux non-network
benign controls (`hello`, `ls`, `cat`, `cp`, `sha256sum`) with strace-derived
semantic events, behavior graphs, behavior audits, documented benign rule
overlaps, and unexpected false-positive rate 0.0. This is local Linux control
evidence, not Genesys2 board benign-trace evidence or malware detection
accuracy.
`tools/check_genesys2_board_benign_readiness.py` verifies
`board_benign_readiness_summary.json`, which turns that local benign-control
set into a future Genesys2 board collection contract with required sample ids,
trace-route/readiness inputs, per-sample board artifact requirements,
acceptance criteria, and explicit no-substitution claim boundaries. It is
readiness only and does not complete board benign-control evidence.
`tools/check_ccfa_current_quality.py` additionally verifies that the current
matrix paths, per-sample baseline logs, semantic path/write/exec provenance,
source-line sidecar rows, runtime process maps, and manifest-selected
BRAM/drop roots are all internally consistent. `tools/check_genesys2_latest_standard.py`
also rejects current-suite commands that hardcode dated Genesys2 board run roots.
`tools/check_genesys2_reproducibility_manifest.py` verifies that
`reproducibility_manifest.json` ties paper-facing report rows to summary JSON
hashes, manifest-selected raw board roots, and checker commands.
`tools/check_genesys2_artifact_package.py` verifies
`artifact_package_manifest.json`, a lightweight package manifest that hashes the
current reports, checker entrypoints, summary artifacts, and reproduction
tools, references raw board roots without copying them, and points fresh-clone
reviewers to `uv run rvmt repro:quick`, `uv run rvmt repro:local`, or the
strict `uv run rvmt repro:full` route.
`tools/check_genesys2_external_closure_readiness.py` verifies
`external_closure_readiness.json`, which records the remaining non-real-malware
external blockers, required artifacts, acceptance criteria, future checker
contracts, and no-substitution rules. It is a readiness-contract gate only; it
does not claim board-native DWARF source lines, full hardware pointer strings,
production streaming/DMA throughput, or Genesys2 board benign controls are
complete.
`tools/check_genesys2_external_closure_intake.py` verifies
`external_closure_intake.json`, the optional future external-summary intake
gate. Current status is `OPEN_EXTERNAL_ARTIFACTS_REQUIRED`: missing summaries
are allowed, but any present summary must satisfy the strict schema, threshold,
no-substitution, and artifact-backed `evidence_artifacts` checks before it can
be counted as accepted external evidence. Accepted candidate summaries must
reference the required artifact kinds with existing files and matching sha256
values.
`tools/check_genesys2_external_closure_plan.py` verifies
`external_closure_plan.json`, the plan-only runbook for those remaining
external blockers. It requires operator inputs, preflight commands, collection
commands, packaging commands, validation commands, and template-only summaries,
while preserving that templates are not evidence and do not close the open
intake state.
`tools/check_genesys2_external_closure_preflight.py` verifies
`external_closure_preflight.json`, which proves the local scripts, dry-run
hooks, schema/path contracts, and no-substitution rules are ready before an
operator runs the remaining external board/RTL work. It is still preflight
only and cannot close any of the four external blockers without accepted
external summaries.
`tools/check_genesys2_external_operator_packet.py` verifies
`external_operator_packet.json`, which packages the remaining external work as
an operator handoff: per-blocker execution order, required artifact kinds,
preflight/collection/packaging/intake steps, and no-substitution rules. It is
not evidence that the external board, RTL, host transport, or reviewer work has
been executed.
`tools/prepare_genesys2_external_summary.py --check-templates` verifies that
the four exported external-summary templates under
`results/evaluation/genesys2-cva6/current/external_closure_templates/` still
match the generator and remain `TEMPLATE_NOT_EVIDENCE`. These templates are
operator scaffolding only; their `evidence_artifacts` rows are placeholders.
Candidate summaries must be validated separately with real artifact rows and
then accepted through `external_closure_intake.json`.
`tools/check_risk_log_current.py` verifies `docs/10-process/risk_log.md`
against the same boundary: real malware remains excluded from the current
objective, 35T artifacts remain historical, eBPF remains optional semantic
enrichment, memory semantics are scoped to bounded-prefix `ARG_MEM` unless
external full-string evidence is accepted, and host PATH toolchains are not
required for the current Docker/fresh-clone path.
`tools/check_evaluation_plan.py` verifies that
`docs/07-evaluation-evidence/evaluation_plan.md` no longer carries stale
placeholder rows for RQs, baselines, datasets, or artifact gates. It requires scoped
PASS_CURRENT/PASS_SAFE statuses, links them to the current evaluation matrix,
baseline alignment, behavior metrics, case-study, runtime, reproducibility, and
external-closure artifacts, and keeps the four non-real external closure items
explicitly open until accepted external summaries exist.
`tools/check_source_line_toolchain_probe.py` verifies that the Docker
`linux-behavior` RISC-V debug/no-PIE path can produce `.debug_line` records
resolved by `addr2line`, while the current generated board ELFs remain recorded
as no-DWARF/function-level board trace artifacts. `tools/check_trace_export_decision.py`
keeps the current evidence scoped to BRAM ring plus ILA/JTAG and rejects
UART/AXI DMA/Ethernet as first-version or throughput claims.
`tools/check_genesys2_debug_elf_readiness.py` verifies the 12-sample debug ELF
readiness package for a future board source-line rerun: every P0 and
safe-surrogate sample has a debug/no-PIE RISC-V Linux ELF, `.debug_line`
readelf transcript, source/ELF/code-map hash linkage, and local `addr2line`
code-map evidence. This remains rerun readiness only, not current board-native
source-line attribution.

P0-only continuous trace gate:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-p0-continuous
```

Board-only subset without safe surrogate evidence:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-board
```

Existing bitstream artifact inventory:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-artifacts
uv run python tools/check_genesys2_bitstream_artifacts.py --strict
```

This inventory is still a fast check: it fails quickly when reusable artifacts
are missing or timing is not clean. It must not repair the artifacts or start a
Vivado rebuild by itself.
Trace-marker builds created after the source-hash manifest update record
SHA-256 hashes for the key RTL, ILA Tcl, capture Tcl, and decoder files. A
missing or stale source-hash manifest is reported as WARN in the fast inventory
and as failure under `--strict`; rebuild the trace-marker bitstream before using
that artifact as source-bound evidence.

Fast fixture self-tests for the current checkers:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-self-test
```

Strict CCF-A gate checker self-tests:

```powershell
uv run python tools/run_check_suite.py --suite ccfa-gate-self-test
```

This suite uses temporary fixtures only. A PASS here means the gate scripts
accept complete evidence and reject known bad states; it does not mean the
current repository has completed the full CCF-A evidence matrix.
It includes both the real-malware containment checker and the real-malware
validation gate self-test; neither one executes, fetches, or stores malware
payloads.

## Long Vivado Tasks

Vivado bitstream builds are not part of the default fast round. They are
explicit long tasks and the suite runner refuses to execute them unless
`--include-long` is passed.

Dry-run a trace-enabled rebuild command:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-trace-bitstream-long --dry-run
```

Run a trace-enabled rebuild only when trace RTL or trace bitstream artifacts
actually need regeneration:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-trace-bitstream-long --include-long
```

The baseline rebuild suite is similarly explicit:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-baseline-bitstream-long --include-long
```

## Local Analysis

Repository-local Linux behavior and code-analysis checks:

```powershell
uv run python tools/run_check_suite.py --suite linux-behavior-local
```

Repository hygiene inventory:

```powershell
uv run python tools/run_check_suite.py --suite repo-hygiene
```

## Boundaries

The current suites must not include 35T checks. The manifest self-test enforces
that rule for suites marked `current: true` and `legacy: false`.

Legacy 35T tools and documents may remain for historical reference or tool
design reference, but they are not current Genesys2/CVA6 completion evidence.
Real malware validation remains blocked unless the real-malware gate has
authorization, containment, hash metadata, hardware trace, local code analysis,
malware analysis, and integrated validation.
