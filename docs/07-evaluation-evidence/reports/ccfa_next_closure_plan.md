# CCF-A Next Closure Plan

Review date: 2026-06-12

Scope: Digilent Genesys2 + CVA6 only. Artix-7 35T / LiteX / VexRiscv evidence is historical reference and is not part of the current claim.

Current readiness score: 82/100 for the controlled non-real-malware Genesys2+CVA6 evidence chain. Overall status remains NOT CCF-A READY and not paper-ready.

## Paper-Facing Claim Boundary

| Field | Current value |
| --- | --- |
| allowed claims | Controlled Genesys2/CVA6 P0 and safe-surrogate BRAM marker-window evidence, bounded-prefix hardware ARG_MEM coverage for openat/write/execve, controlled repetition/statistical robustness audit, cycle-normalized streaming/DMA target baseline for future throughput experiments, future non-BRAM streaming/DMA transport readiness, future full hardware pointer-string collection readiness, local code/process attribution summaries, debug/no-PIE source-line toolchain probe evidence, 12-sample debug ELF source-line rerun readiness, local Linux benign-control false-positive audit, future board benign-control collection readiness, per-sample controlled case-study packages, lightweight artifact package / fresh-clone reproduction commands, external closure readiness/intake/plan/preflight contracts, external operator handoff packet, non-evidence external summary templates, and malware-like behavior audit over safe surrogate workloads. |
| non-claims | No real malware validation, no malware detection accuracy, no malware-family coverage, no randomized workload generalization, no production long-run stability claim, no full hardware-derived pointer strings, no full memory dump, no kernel memory capture, and no production streaming/DMA throughput claim. |
| artifact root | Canonical selector: `results/evaluation/genesys2-cva6/current/latest_manifest.json`. Current summaries: `results/evaluation/genesys2-cva6/current/`; `results/evaluation/genesys2-cva6/current/samples/`. Dated board roots under `results/board/genesys2_trace_validation/` are provenance only. |
| run id | `20260612-p0-bram-repetitions`; `20260611-safe-surrogate-bram-ring-busywait`; `20260612-pointer-snapshot-bram`; `current-quality-20260612` |
| board / CPU / bitstream hash | Board Digilent Genesys2; CPU CVA6 rv64gc sv39; P0 BRAM bitstream `2667492eb30ed2660a4a2a2f2b0128bce4c43b7305fb9844eb9fa11dae604992`; safe BRAM bitstream `5ab54e577456532936a117fe89c3e5800758e5e42819d8618db42622ce9447cc`; LTX `0a647dbd67f4921dc4a449f269b94caf9fa407627e840ab386d168775981467c` |
| command transcript | `results/board/genesys2_trace_validation/20260612-p0-bram-repetitions/*/rep_*/capture.log`; `results/board/genesys2_trace_validation/20260612-p0-bram-repetitions/*/rep_*/uart.log`; `results/board/genesys2_trace_validation/20260612-pointer-snapshot-bram/*/rep_*/capture.log`; `results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait/*/rep_*/capture.log` |
| checker command | `uv run python tools/run_check_suite.py --suite genesys2-current`; `uv run python tools/run_check_suite.py --suite genesys2-artifacts`; `uv run python tools/check_genesys2_latest_standard.py --root .`; `uv run python tools/check_trace_export_decision.py --root .`; `uv run python tools/check_ccfa_claim_boundaries.py --root .`; `uv run python tools/check_pointer_snapshot_guardrails.py --root .`; `uv run python tools/check_hardware_pointer_prefixes.py --root .`; `uv run python tools/check_genesys2_pointer_string_readiness.py --root .`; `uv run python tools/check_genesys2_statistical_robustness.py --root .`; `uv run python tools/check_genesys2_streaming_dma_target.py --root .`; `uv run python tools/check_genesys2_streaming_dma_readiness.py --root .`; `uv run python tools/check_benign_control_summary.py --root .`; `uv run python tools/check_genesys2_board_benign_readiness.py --root .`; `uv run python tools/check_source_line_toolchain_probe.py --root .`; `uv run python tools/check_genesys2_debug_elf_readiness.py --root .`; `uv run python tools/check_ccfa_case_study_manifest.py --root .`; `uv run python tools/check_genesys2_reproducibility_manifest.py --root .`; `uv run python tools/check_genesys2_artifact_package.py --root .`; `uv run python tools/check_genesys2_external_closure_readiness.py --root .`; `uv run python tools/check_genesys2_external_closure_intake.py --root .`; `uv run python tools/check_genesys2_external_closure_plan.py --root .`; `uv run python tools/check_genesys2_external_closure_preflight.py --root .`; `uv run python tools/check_genesys2_external_operator_packet.py --root .`; `uv run python tools/prepare_genesys2_external_summary.py --check-templates`; `uv run python tools/reproduce_genesys2_current.py --full --dry-run`; `uv run python tools/check_behavior_audit_metrics.py --root .` |

## Completed Items

- P0 hardware BRAM trace: 40 accepted PASS repetitions across `hello_write`, `file_open_read_write`, `fork_exec`, and `illegal_instruction`. One failed `fork_exec/rep_03` attempt with dropped count 3612 and wrap count 4 is retained and not counted as accepted evidence.
- Safe-surrogate hardware BRAM trace: 80/80 accepted PASS repetitions across eight safe syscall-only surrogate samples.
- Statistical robustness audit: `statistical_robustness_summary.json` records 120 accepted controlled board repetitions across 12 P0/safe-surrogate samples, one retained failed P0 attempt, zero accepted-window unaccounted DROP/wrap/dropped count, 12 controlled case studies, and five local benign controls with unexpected false-positive rate 0.0. It explicitly does not claim randomized workload generalization, real-malware validation, or production long-run stability.
- Streaming/DMA target baseline: `streaming_dma_target_summary.json` turns the 120 accepted marker-window repetitions into a future external throughput target: 136-bit compact records, 17 bytes per event, p95 `0.01981178801386825` event bytes per marker-window cycle, and a requirement that future external summaries convert that target with the exact streaming bitstream clock report before comparing sustained bytes/sec.
- Streaming/DMA readiness: `streaming_dma_readiness_summary.json` turns the p95 target into a future non-BRAM transport contract covering allowed/disallowed transport kinds, exact clock conversion, host receiver log fields, required artifact kinds, summary fields, and no-substitution boundaries. It keeps `production_streaming_dma_throughput_claimed=false`.
- Hardware pointer semantics: 514 bounded-prefix ARG_MEM records across 30 board repetitions, with hardware syscall coverage for openat, write, and execve.
- Hardware pointer byte-prefix audit: `hardware_pointer_prefix_summary.json` records 51 hardware pointer groups and 1156 compact ARG_MEM bytes across 30 board repetitions, keeps gapped fragments separate, and makes `full_string_claimed=false` explicit.
- Full hardware pointer-string readiness: `pointer_string_readiness_summary.json` links the current prefix/guardrail evidence to the future `rvmt.genesys2.hardware_pointer_strings.v1` contract, requiring contiguous bytes from offset 0 through a terminator or documented bounded truncation, mem_last/terminator evidence, artifact hashes, redaction policy, and no companion or gapped-fragment substitution. It keeps `full_hardware_pointer_strings_claimed=false`.
- Guardrails: pointer summaries distinguish hardware ARG_MEM bytes from trusted companion strings and reject companion-derived strings claimed as hardware pointer strings.
- Reproducibility manifest: `reproducibility_manifest.json` now links paper-facing report rows to summary JSON hashes, active raw board roots, raw file counts, and checker commands.
- Lightweight artifact package: `artifact_package_manifest.json` records report/checker/summary hashes, referenced raw board roots, raw-artifact release policy, and fresh-clone reproduction commands through `tools/reproduce_genesys2_current.py`.
- External closure readiness contract: `external_closure_readiness.json` records the four remaining non-real-malware external blockers, their required artifacts, acceptance criteria, future checker contract, and no-substitution rules without claiming those external experiments are complete.
- External closure intake gate: `external_closure_intake.json` records the optional external-summary paths and strict schemas for closing the four non-real-malware external blockers. Its current status is `OPEN_EXTERNAL_ARTIFACTS_REQUIRED`; it fails on weak or substitutive external summaries, and any accepted candidate summary must include `evidence_artifacts` rows with the required artifact kinds, existing files, and matching sha256 values.
- External closure execution plan: `external_closure_plan.json` turns those four blockers into concrete operator inputs, preflight commands, collection commands, packaging commands, validation commands, and template-only summaries. The embedded templates are explicitly not evidence.
- External closure local preflight: `external_closure_preflight.json` proves the local scripts, dry-run hooks, schema/path contracts, and no-substitution guardrails are ready before the remaining external board/RTL work is run. It is explicitly not completion evidence.
- External operator handoff packet: `external_operator_packet.json` and `ccfa_external_operator_packet.md` consolidate the four remaining non-real external blockers into per-blocker execution steps, required evidence artifact kinds, intake paths, and no-substitution rules. It is explicitly not board/RTL/host transport execution evidence.
- External summary templates: `external_closure_templates/*.template.json` now exports the four strict external-summary shapes outside the intake evidence path, including the required `evidence_artifacts` placeholders, and `tools/prepare_genesys2_external_summary.py` can pre-validate candidate summaries before they are moved into intake. Templates are explicitly not evidence.
- Review closure audit: `review_closure_audit.json` and `ccfa_review_closure_audit.md` map the original 2026-06 CCF-A review requirements to current evidence, objective exclusions, checker commands, and the four still-open non-real external intake records.
- Source-line toolchain probe: `source_line_toolchain_probe.json` proves the Docker `linux-behavior` debug/no-PIE RISC-V `addr2line` path has `.debug_line` coverage, and separately records that current generated board ELFs have no DWARF debug sections.
- Debug ELF rerun readiness: `debug_elf_readiness_summary.json` builds all 12 P0/safe-surrogate debug/no-PIE RISC-V Linux ELFs, records per-sample `.debug_line` readelf transcripts, hashes each ELF/source/code-map artifact, and proves local `addr2line` source-line code maps are ready for a future board rerun. It explicitly does not claim the current board captures used those exact ELF hashes.
- Trace-export boundary: `tools/check_trace_export_decision.py` is now part of the current suite and keeps the first/current hardware evidence scoped to BRAM ring buffer plus ILA/JTAG dump, with UART streaming and AXI DMA/Ethernet streaming deferred.
- Local analysis: current summaries cover runtime process maps, ELF/function attribution, dynamic mapping attribution, and source attribution sidecars.
- Malware-like behavior audit: all eight safe surrogate samples now have current per-sample `semantic_events.json`, `behavior_graph.json`, `behavior_mapping.json`, `integrated_validation.json`, and `behavior_audit_metrics.json` wrappers under `results/evaluation/genesys2-cva6/current/samples/<sample>/`. These wrappers point back to source evidence and carry `real_malware=false` non-claims.
- Per-sample case-study packages: `case_study_manifest.json` now links all twelve P0/safe-surrogate samples to `case_study_summary.json` files covering hardware trace, semantic reconstruction, local code attribution, baseline comparison, audit decision, metrics, limitations, and reviewer traceability.
- Benign control audit: `benign_control_summary.json` records five non-network benign workloads (`hello`, `ls`, `cat`, `cp`, `sha256sum`) run under Docker `linux-behavior` with strace-derived semantic events, behavior graphs, behavior audits, documented benign rule overlaps, and unexpected false-positive rate 0.0.
- Board benign-control readiness: `board_benign_readiness_summary.json` links the five local benign controls to the current trace-route/readiness evidence, records the required future board artifacts and summary fields, and keeps `genesys2_board_benign_control_claimed=false`.
- Claim boundary checks: current reports explicitly preserve allowed claims, non-claims, artifact roots, run ids, board/CPU/bitstream hashes, command transcripts, and checker commands.
- Checker guardrails: claim-boundary fixtures reject simulation-as-board, safe-surrogate-as-real-malware, and companion-string-as-hardware shorthand. Artifact gates reject missing per-sample audit artifacts, missing trace paths in the evaluation matrix, unexplained DROP in drop accounting, and stale trace-marker source hashes.
- Latest standard: `current/latest_manifest.json` is now the single active evidence selector. Current suite commands resolve dated board roots through the manifest; dated roots remain provenance only and are not chosen by timeline order.

## Remaining Blockers

- Board-native DWARF/source-line attribution for the current board traces still requires rebuilding the exact board workload ELF with DWARF, rerunning the board capture, and rejoining traces to that ELF. The toolchain path and 12 debug ELF candidates are now proven, but current generated board ELFs remain function-level only and no `captured_elf_sha256` exact-match board rerun has been accepted.
- Full hardware-derived pointer strings remain unclaimed. The current BRAM ARG_MEM evidence proves bounded prefixes and fragments, and `pointer_string_readiness_summary.json` makes the future full-string acceptance contract checkable, but closure still requires new gap-free RTL/board evidence accepted through `hardware_pointer_strings_summary.json`.
- Production streaming/DMA sink throughput remains unclaimed. The BRAM-first trace-export boundary, p95 event-byte target baseline, and non-BRAM transport readiness contract are machine-checked, but no UART/DMA/ethernet/PCIe streaming throughput experiment has been accepted.
- Benign control evidence is local Linux behavior evidence, not Genesys2 board trace evidence. `board_benign_readiness_summary.json` makes the future board collection contract checkable, but it supports readiness only and does not close Genesys2 board benign-control false-positive evidence.
- Artifact package evidence is a lightweight manifest and reproduction-command package; it does not copy large raw board artifacts or replace external reviewer execution.
- `external_closure_readiness.json` makes these remaining non-real-malware standards machine-checkable, but it is readiness evidence only and does not replace the needed board/RTL runs.
- `external_closure_intake.json` makes future board/RTL summary intake machine-checkable, but its current open status means no external blocker is accepted as closed yet.
- `external_closure_plan.json` makes the required external work executable, but it is plan-only and does not close the open intake status.
- `external_closure_preflight.json` makes the local command/schema prerequisites machine-checkable, but it is preflight-only and does not replace board/RTL execution.
- `external_operator_packet.json` makes the external execution handoff machine-checkable, but it is operator guidance only and does not replace board/RTL/host transport execution.
- `external_closure_templates/*.template.json` makes future external-summary packaging less error-prone, but templates are not board/RTL-derived evidence.
- `statistical_robustness_summary.json` organizes the current controlled repetition evidence, but it does not close randomized/general workload coverage, production long-run stability, or real-malware generalization.
- Real malware remains outside the current success condition. It is limited to containment policy and an optional future case-study gate.
- The current evidence package is paper-facing controlled evidence, not a full CCF-A-ready validation package.

## Next Experiments

- Re-run safe-surrogate BRAM repetitions against the same bitstream generation as the latest P0 run if the paper requires one uniform bitstream hash across all board evidence.
- If source-line evidence is needed for the exact board traces, use `debug_elf_readiness_summary.json` as the candidate debug ELF manifest, rerun board captures from those retained-DWARF ELFs, require exact `captured_elf_sha256` matches, and use the existing `addr2line` path to regenerate joined trace/code maps.
- Add optional real-malware case-study planning only after containment review, without making it a current CCF-A success condition.

## Acceptance Standards

- Board evidence cannot be replaced by simulation or fixture evidence.
- Every accepted sample must have clear begin/end markers, syscall entry/return pairing where pairable, no sequence gaps, wrap count 0, unaccounted DROP 0, and parse success.
- Any DROP/wrap attempt must be retained as FAIL/BLOCKED evidence with impact analysis and must not be counted as accepted PASS evidence.
- Hardware pointer claims must be bounded-prefix ARG_MEM only unless a later hardware mechanism directly supports stronger recovery.
- Full pointer-string readiness must not be described as completed full-string evidence; current prefixes, gapped fragments, qemu/strace strings, and fd/path graph strings cannot substitute for hardware-derived full strings.
- Safe surrogate behavior audit may be claimed only as malware-like behavior audit, not real malware validation.
- Companion-derived strings may be used only as trusted semantic companions and must never be reported as hardware-derived strings.
- Board trace code attribution is function-level unless a board ELF with DWARF directly supports source-line attribution.
- Source-line toolchain proof must not be described as board-native source-line evidence unless the exact captured board ELF carries DWARF and the board trace is regenerated or rejoined against that ELF.
- Debug ELF readiness must not be described as current board-native source-line evidence until a new board capture proves exact captured-ELF hash linkage to the retained-DWARF ELF.
- External closure summaries must be artifact-backed: `evidence_artifacts` must cover the required artifact kinds for the blocker, point to existing files, and carry sha256 values that match those files.
- Current trace-sink evidence remains BRAM ring plus ILA/JTAG; UART streaming and AXI DMA/Ethernet streaming are deferred and cannot be used as current throughput evidence.
- Current gates must pass `tools/check_genesys2_latest_standard.py`; hardcoded dated board roots in current-suite commands are rejected.

## Validation Commands

```powershell
uv run python tools/run_check_suite.py --suite genesys2-current
uv run python tools/run_check_suite.py --suite genesys2-artifacts
uv run python tools/run_check_suite.py --suite genesys2-p0-continuous
uv run python tools/check_trace_export_decision.py --root .
uv run python tools/check_ccfa_claim_boundaries.py --root .
uv run python tools/check_genesys2_bram_trace_sink.py --root .
uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .
uv run python tools/check_genesys2_p0_bram_trace.py --root .
uv run python tools/check_trace_drop_accounting.py --root .
uv run python tools/check_genesys2_statistical_robustness.py --root .
uv run python tools/check_genesys2_streaming_dma_target.py --root .
uv run python tools/check_genesys2_streaming_dma_readiness.py --root .
uv run python tools/check_pointer_snapshot_guardrails.py --root .
uv run python tools/check_hardware_pointer_prefixes.py --root .
uv run python tools/check_genesys2_pointer_string_readiness.py --root .
uv run python tools/check_benign_control_summary.py --root .
uv run python tools/check_genesys2_board_benign_readiness.py --root .
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
uv run python tools/check_genesys2_reproducibility_manifest.py --root .
uv run python tools/check_genesys2_artifact_package.py --root .
uv run python tools/check_genesys2_review_closure_audit.py --root .
uv run python tools/check_genesys2_external_closure_readiness.py --root .
uv run python tools/check_genesys2_external_closure_intake.py --root .
uv run python tools/check_genesys2_external_closure_plan.py --root .
uv run python tools/check_genesys2_external_closure_preflight.py --root .
uv run python tools/check_genesys2_external_operator_packet.py --root .
uv run python tools/prepare_genesys2_external_summary.py --check-templates
uv run python tools/reproduce_genesys2_current.py --full --dry-run
uv run python tools/check_real_malware_containment.py
```
