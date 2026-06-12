# CCF-A Next Closure Plan

Review date: 2026-06-12

Scope: Digilent Genesys2 + CVA6 only. Artix-7 35T / LiteX / VexRiscv evidence is historical reference and is not part of the current claim.

Current readiness score: 84/100 for the controlled non-real-malware Genesys2+CVA6 evidence chain. Overall status remains NOT CCF-A READY.

## Paper-Facing Claim Boundary

| Field | Current value |
| --- | --- |
| allowed claims | Controlled Genesys2/CVA6 P0 and safe-surrogate BRAM marker-window evidence, bounded-prefix hardware ARG_MEM coverage for openat/write/execve, local code/process attribution summaries, and malware-like behavior audit over safe surrogate workloads. |
| non-claims | No real malware validation, no malware detection accuracy, no malware-family coverage, no full hardware-derived pointer strings, no full memory dump, no kernel memory capture, and no production streaming/DMA throughput claim. |
| artifact root | `results/evaluation/genesys2-cva6/current/`; `results/board/genesys2_trace_validation/20260612-p0-bram-repetitions/`; `results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait/`; `results/board/genesys2_trace_validation/20260612-pointer-snapshot-bram/` |
| run id | `20260612-p0-bram-repetitions`; `20260611-safe-surrogate-bram-ring-busywait`; `20260612-pointer-snapshot-bram`; `current-quality-20260612` |
| board / CPU / bitstream hash | Board Digilent Genesys2; CPU CVA6 rv64gc sv39; P0 BRAM bitstream `2667492eb30ed2660a4a2a2f2b0128bce4c43b7305fb9844eb9fa11dae604992`; safe BRAM bitstream `5ab54e577456532936a117fe89c3e5800758e5e42819d8618db42622ce9447cc`; LTX `0a647dbd67f4921dc4a449f269b94caf9fa407627e840ab386d168775981467c` |
| command transcript | `results/board/genesys2_trace_validation/20260612-p0-bram-repetitions/*/rep_*/capture.log`; `results/board/genesys2_trace_validation/20260612-p0-bram-repetitions/*/rep_*/uart.log`; `results/board/genesys2_trace_validation/20260612-pointer-snapshot-bram/*/rep_*/capture.log`; `results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait/*/rep_*/capture.log` |
| checker command | `uv run python tools/run_check_suite.py --suite genesys2-current`; `uv run python tools/check_ccfa_claim_boundaries.py --root .` |

## Completed Items

- P0 hardware BRAM trace: 40 accepted PASS repetitions across `hello_write`, `file_open_read_write`, `fork_exec`, and `illegal_instruction`. One failed `fork_exec/rep_03` attempt with dropped count 3612 and wrap count 4 is retained and not counted as accepted evidence.
- Safe-surrogate hardware BRAM trace: 80/80 accepted PASS repetitions across eight safe syscall-only surrogate samples.
- Hardware pointer semantics: 514 bounded-prefix ARG_MEM records across 30 board repetitions, with hardware syscall coverage for openat, write, and execve.
- Guardrails: pointer summaries distinguish hardware ARG_MEM bytes from trusted companion strings and reject companion-derived strings claimed as hardware pointer strings.
- Local analysis: current summaries cover runtime process maps, ELF/function attribution, dynamic mapping attribution, and source attribution sidecars.
- Malware-like behavior audit: safe surrogate artifacts include semantic events, behavior graphs, behavior mappings, integrated validation, baseline alignment, and behavior metrics.
- Claim boundary checks: current reports explicitly preserve allowed claims, non-claims, artifact roots, run ids, board/CPU/bitstream hashes, command transcripts, and checker commands.

## Remaining Blockers

- Paper-ready narrative still needs a final reproducibility pass that ties raw board artifacts, summary JSON, and figures/tables together.
- DWARF/source-line attribution is only claimed where supported by sidecar/source-equivalent evidence; generated board ELFs without DWARF remain function-level only.
- Production streaming/DMA sink throughput is not demonstrated by the current marker-window BRAM captures.
- Real malware remains outside the current success condition. It is limited to containment policy and an optional future case-study gate.

## Next Experiments

- Re-run safe-surrogate BRAM repetitions against the same bitstream generation as the latest P0 run if the paper requires one uniform bitstream hash across all board evidence.
- Add a report-level artifact manifest that maps every paper table row to source JSON, raw UART log, capture log, decoded trace, and checker command.
- Extend source-line attribution only for board ELFs that carry DWARF, and keep function-level-only language for stripped/generated ELFs.
- Add optional real-malware case-study planning only after containment review, without making it a current CCF-A success condition.

## Acceptance Standards

- Board evidence cannot be replaced by simulation or fixture evidence.
- Every accepted sample must have clear begin/end markers, syscall entry/return pairing where pairable, no sequence gaps, wrap count 0, unaccounted DROP 0, and parse success.
- Any DROP/wrap attempt must be retained as FAIL/BLOCKED evidence with impact analysis and must not be counted as accepted PASS evidence.
- Hardware pointer claims must be bounded-prefix ARG_MEM only unless a later hardware mechanism directly supports stronger recovery.
- Safe surrogate behavior audit may be claimed only as malware-like behavior audit, not real malware validation.

## Validation Commands

```powershell
uv run python tools/run_check_suite.py --suite genesys2-current
uv run python tools/run_check_suite.py --suite genesys2-artifacts
uv run python tools/run_check_suite.py --suite genesys2-p0-continuous
uv run python tools/check_ccfa_claim_boundaries.py --root .
uv run python tools/check_genesys2_bram_trace_sink.py --root .
uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .
uv run python tools/check_genesys2_p0_bram_trace.py --root .
uv run python tools/check_trace_drop_accounting.py --root .
uv run python tools/check_pointer_snapshot_guardrails.py --root .
uv run python tools/check_syscall_semantic_reconstruction.py --root .
uv run python tools/check_fd_path_graph.py --root .
uv run python tools/check_source_line_attribution.py --root .
uv run python tools/check_process_elf_ownership.py --root .
uv run python tools/check_dynamic_mapping_attribution.py --root .
uv run python tools/check_ccfa_evaluation_matrix.py --root .
uv run python tools/check_baseline_alignment.py --root .
uv run python tools/check_behavior_audit_metrics.py --root .
uv run python tools/check_real_malware_containment.py
```
