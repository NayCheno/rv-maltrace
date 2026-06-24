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
reruns. `repro:full` is the strict closure suite: unresolved external hardware
items must appear as explicit BLOCKED/open evidence records, and the suite
passes only when those non-claims are artifact-backed and internally
consistent.

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
bounded fuzz trace invariant fixtures, directed trace-correctness corpus,
static timing/strict-SRET integration
guardrails,
streaming/DMA target-baseline evidence,
bounded-prefix pointer snapshot guardrails,
hardware ARG_MEM byte-prefix evidence, full hardware pointer-string readiness,
accepted scoped full hardware pointer-string evidence,
BRAM-first trace-export boundary,
source-line toolchain probe evidence, debug ELF source-line rerun readiness,
local code-analysis fixture provenance for exact ELF, PIE/load-bias, runtime
maps, fork/exec, dynamic libraries, stripped ELF, and sidecar non-claims,
benign-control false-positive evidence,
per-sample controlled case-study packages,
reproducibility manifest linkage, lightweight artifact-package/fresh-clone
reproduction linkage, local raw-artifact release archive validation, board
bootrom counter-delegation build validation, board cycle-source probe and
diagnostic claim-boundary validation, board counter-access matrix
claim-boundary validation, live kernel-config export validation, Linux
counter-path preflight validation, host-side Vivado part/board preflight
validation, host-side NDSS LaTeX skeleton-build validation, external
closure readiness contracts, the
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
uv run python tools/check_genesys2_strict_sret_board_smoke.py --root .
uv run python tools/check_trace_drop_accounting.py --root .
uv run python tools/check_fuzz_trace_plan.py --root .
uv run python tools/check_trace_correctness_directed.py --root .
uv run python tools/check_timing_principles.py
uv run python tools/check_genesys2_statistical_robustness.py --root .
uv run python tools/check_genesys2_streaming_dma_target.py --root .
uv run python tools/check_genesys2_streaming_dma_readiness.py --root .
uv run python tools/check_pointer_snapshot_guardrails.py --root .
uv run python tools/check_hardware_pointer_prefixes.py --root .
uv run python tools/check_genesys2_pointer_string_readiness.py --root .
uv run python tools/check_genesys2_hardware_pointer_strings.py --root .
uv run python tools/check_syscall_semantic_reconstruction.py --root .
uv run python tools/check_genesys2_semantic_provenance.py --root .
uv run python tools/check_fd_path_graph.py --root .
uv run python tools/check_source_line_attribution.py --root .
uv run python tools/check_source_line_toolchain_probe.py --root .
uv run python tools/check_genesys2_debug_elf_readiness.py --root .
uv run python tools/check_process_elf_ownership.py --root .
uv run python tools/check_dynamic_mapping_attribution.py --root .
uv run python tools/check_genesys2_local_code_analysis_fixtures.py --root .
uv run python tools/check_ccfa_evaluation_matrix.py --root .
uv run python tools/check_baseline_alignment.py --root .
uv run python tools/check_genesys2_tracer_visibility_baseline.py --root .
uv run python tools/check_behavior_audit_metrics.py --root .
uv run python tools/check_ccfa_case_study_manifest.py --root .
uv run python tools/check_benign_control_summary.py --root .
uv run python tools/check_genesys2_board_benign_readiness.py --root .
uv run python tools/check_ccfa_current_quality.py --root .
uv run python tools/check_genesys2_reproducibility_manifest.py --root .
uv run python tools/check_genesys2_artifact_package.py --root .
uv run python tools/check_genesys2_raw_artifact_release.py --root .
uv run python tools/check_genesys2_artifact_integrity.py --root .
uv run python tools/check_genesys2_bootrom_counter_delegation.py --root .
uv run python tools/check_genesys2_cycle_source_probe.py --root .
uv run python tools/check_genesys2_cycle_diagnostics.py --root .
uv run python tools/check_genesys2_counter_access_matrix.py --root .
uv run python tools/check_genesys2_sdcard_linux_manifest.py --root .
uv run python tools/check_genesys2_boot_sdcard_image.py --root .
uv run python tools/check_genesys2_sdcard_write_preflight.py --root .
uv run python tools/check_ndss_host_vivado_check.py --root .
uv run python tools/check_genesys2_trace_marker_programming.py --root .
uv run python tools/check_genesys2_jtag_ram_boot_probe.py --root .
uv run python tools/check_genesys2_live_kernel_config_export.py --root .
uv run python tools/check_genesys2_linux_rebuild_manifest.py --root .
uv run python tools/check_genesys2_linux_counter_path_preflight.py --root .
uv run python tools/check_ndss_host_latex_build.py --root .
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
`results/board/genesys2_trace_validation/20260624-current-safe-surrogate-cohort/`,
with begin-marker clearing, expected raw syscall-entry counts, no sequence
gaps, no wrap, and zero unaccounted drops checked by
`tools/check_genesys2_safe_surrogate_bram_trace.py`.
The drop-accounting gate is intentionally scoped to captured trace windows; it
does not convert raw trace captures into pointer semantic reconstruction or a
full CCF-A real-malware claim.
The statistical robustness gate verifies
`results/evaluation/genesys2-cva6/current/statistical_robustness_summary.json`:
122 accepted controlled board marker-window repetitions across 12 P0 and
safe-surrogate samples, four retained failed P0 attempts, zero accepted-window
unaccounted DROP/wrap/dropped count, 12 controlled case studies, and five local
benign controls with unexpected false-positive rate 0.0. It is not a randomized
workload generalization study, real-malware validation, production long-run
stability evidence, or Genesys2 board benign-control evidence.

`tools/check_trace_correctness_directed.py` verifies
`trace_correctness_directed_summary.json`: 50 deterministic directed
trace-event cases plus 10 seeded random event-sequence fixtures, covering
strict syscall entry/return pairing, trap versus retire separation,
privilege/context transitions, same-cycle event ordering, dual-retire
`commit_port` ordering, argument-memory fragments, and DROP monotonicity. This
is a local trace-invariant corpus, not a Vivado, Genesys2 board, RISCV-DV, or
malware-validation claim.

`tools/check_genesys2_cycle_diagnostics.py` verifies
`cycle_source_diagnostics_summary.json`, a live Genesys2 SD-card Linux
diagnostic capture. It records Linux 6.19.6, root-shell access, CPU ISA
advertising `zicntr`/`zihpm`, no `/proc/sys/kernel/perf_event_paranoid`, no
`/sys/bus/event_source/devices`, no observed SBI PMU extension, no PMU/perf
device-tree node, no readable `/proc/config.gz` / `/boot/config-6.19.6` /
kernel build `.config`, no `/lib/modules/6.19.6`, and retained prior user
`rdcycle` illegal-instruction traps. The summary includes an
`enablement_preflight` section that lists the kernel-perf and user-`rdcycle`
conditions that must be satisfied before any cycle-source claim. This is a
stronger blocker diagnostic for cycle-level overhead work; it does not claim a
usable cycle source or any trace-on/off slowdown measurement.

`tools/check_genesys2_bootrom_counter_delegation.py` verifies the current
Genesys2/CVA6 bootrom build artifact under `build/bootrom/genesys2-cva6/`.
It checks the bootrom source hash, generated `bootrom_64.sv`, ELF/bin/img
artifacts, and disassembly evidence for `csrw mcounteren`, `csrw scounteren`,
and `csrw mcountinhibit`. This is a firmware-level counter-delegation attempt
only; the board still must pass the counter-access matrix or kernel-perf
cycle-source probe before any cycle-source or overhead claim.

`tools/check_genesys2_sdcard_linux_manifest.py` verifies
`sdcard_linux_manifest.json`, a live Genesys2/CVA6 SD-card Linux identity
manifest captured over UART. It binds the raw UART log, kernel release,
cmdline, root filesystem identity hashes, block inventory, and
`/proc/device-tree` file hashes. This narrows the SD-card provenance gap but
does not claim a Buildroot/OpenSBI/kernel rebuild path, readable live kernel
config, board cycle source, or runtime overhead.

`tools/check_genesys2_boot_sdcard_image.py` verifies
`sdcard_image_manifest.json`, the local GPT SD-card image generated from a real
`fw_payload.bin` and optional rootfs. It checks the image SHA256, GPT
signatures, first-partition boot-payload contract for the CVA6 bootrom, source
payload/rootfs hashes, partition byte content, and zero padding. This is a
local image-creation PASS only; it does not claim physical SD-card write,
Genesys2 boot from that image, live kernel config export, PMU visibility, or
cycle-source availability.

`tools/check_genesys2_sdcard_write_preflight.py` verifies
`sdcard_write_preflight_summary.json`, a read-only host disk inventory and
target-selection preflight for writing the generated Genesys2/CVA6 SD-card
image. A PASS requires an explicit safe target disk number; the default host
run may be a truthful BLOCKED state when no small non-system SD/USB target is
available. This checker never claims a physical SD-card write or board boot.

`tools/check_ndss_host_vivado_check.py` verifies
`host_vivado_check_summary.json` and `host_vivado_check.log`, a host-side Vivado
preflight for tool availability plus the Genesys2 FPGA part and board part.
This is not synthesis, implementation, bitstream generation, board programming,
or board runtime evidence; those remain separate host/Vivado/JTAG steps.

`tools/check_genesys2_trace_marker_programming.py` verifies
`trace_marker_programming_summary.json` and `trace_marker_programming.log`, a
host Vivado JTAG programming run for the source-bound trace-marker bitstream.
It requires the programmed `xc7k325t_0` target, the Digilent Genesys2 JTAG
serial, `RVMT_PROGRAM_DONE`, and a refresh report showing one ILA core. This is
not SD-card image write/boot evidence, cycle-source or overhead evidence,
production streaming/DMA throughput evidence, or real-malware validation.

`tools/check_genesys2_jtag_ram_boot_probe.py` verifies
`jtag_ram_boot_probe_summary.json` and `jtag_ram_boot_probe.log`, a read-only
Vivado Hardware Manager probe for JTAG-visible RAM boot control paths. The
default accepted current state may be
`BLOCKED_JTAG_RAM_BOOT_NO_MEMORY_CONTROL` when the target/device/ILA are
visible but no `hw_axis`, `hw_axi`, or `hw_mem` object exists. The checker
requires a log hash match and rejects programming, reset, memory-write, or
board-boot claims; use `--require-ram-control` only after a bitstream exposes a
real RAM-write path.

`tools/check_genesys2_strict_sret_board_smoke.py` verifies
`strict_sret_board_smoke_summary.json`, a current-bitstream `hello_write`
Genesys2 BRAM/ILA marker-window smoke rerun. It requires the exact transferred
board ELF hash, current trace-marker bitstream and LTX hashes, JTAG programming
evidence, `RVMT_ILA_CAPTURE_DONE`, board command `rc=0`, clear begin/end
markers, strict syscall-id entry/return pairing, trap and privilege-transition
events, sequence continuity, wrap=0, and drop=0. This is a one-sample
strict-SRET smoke; the separate `p0_bram_trace_summary.json` now covers the
full current-bitstream P0 cohort. Neither summary claims SD-card-image boot,
overhead, production streaming, or real-malware validation.

`tools/check_genesys2_live_kernel_config_export.py` verifies
`live_kernel_config_export_summary.json`, the live UART attempt to export the
kernel config from `/proc/config.gz`, `/boot/config-$(uname -r)`, or
`/lib/modules/$(uname -r)/build/.config`. The current board summary is
`BLOCKED_LIVE_KERNEL_CONFIG_UNAVAILABLE`: the board reached a root shell on
Linux 6.19.6, but none of those paths exists. This is hashed board evidence for
the missing live-config anchor, not a source-level defconfig substitute and not
a cycle-source or overhead claim.

`tools/check_genesys2_linux_rebuild_manifest.py` verifies
`linux_rebuild_manifest.json`, the Docker-side Buildroot/OpenSBI rebuild
preparation or full-build manifest. The accepted preparation status means the
Docker container has the required Buildroot tools and the generated CVA6 DTS
and generated Buildroot defconfig are hash-bound. A payload-build PASS requires
`fw_payload.bin` in `output_artifacts`; it still does not claim that a physical
SD card was written, Genesys2 booted the image, or live board PMU/cycle-source
checks passed.

`tools/check_genesys2_linux_counter_path_preflight.py` verifies
`linux_counter_path_preflight.json`, the repo-local SD-card Linux counter-path
rebuild preflight. It scans for Genesys2/CVA6-specific Buildroot, Linux kernel
config, OpenSBI, SD-card manifest, PMU device-tree, and live kernel-config
export anchors; rejects Artix-7/LiteX/VexRiscv substitutes; and binds the
existing bootrom, cycle-smoke, kernel-perf probe, diagnostics, and
counter-access matrix summaries by hash. The current source template
`rtl/cva6/corev_apu/fpga/src/bootrom/cv64a6.dts.in` satisfies the PMU
device-tree source anchor with a `compatible = "riscv,pmu"` node, but this is
not live-board PMU evidence until a rebuilt DTB/SD-card image and board
diagnostics prove PMU visibility. The Linux build entrypoint, Buildroot
source/defconfig, and OpenSBI manifest anchors are semantic anchors: the
checker requires content-level Genesys2/CVA6, Buildroot, OpenSBI, SD-card, and
source/hash evidence instead of accepting placeholder paths.
`uv run rvmt ndss:linux-source-lock` validates the current repo-owned
Buildroot defconfig, Linux counter config, OpenSBI source manifest, PMU DTS
template, and live SD-card identity manifest as a source-level rebuild contract.
`uv run rvmt ndss:linux-rebuild-prep --fetch --configure` runs inside Docker
and prepares or configures the Buildroot/OpenSBI rebuild path without claiming
a payload unless `--execute` produces a hash-bound `fw_payload.bin`.
`uv run rvmt ndss:live-kernel-config-export` validates the board-side readable
kernel-config export attempt and records a truthful BLOCKED summary until a
rebuilt image exposes that config.
The current status is a truthful 6/7-anchor
`BLOCKED_SD_CARD_LINUX_SOURCE_MISSING`: the remaining missing required anchor is
the exported live kernel config from a rebuilt board image. A future preflight PASS
would still not claim runtime overhead; the board cycle-source `--require-pass`
checks must pass first.

The streaming/DMA target gate verifies
`results/evaluation/genesys2-cva6/current/streaming_dma_target_summary.json`:
the 122 accepted marker-window repetitions define p50/p95/p99 compact
event-byte targets of `0.006971521218847351`, `0.01981178801386825`, and
`0.020308813427709585` bytes per marker-window cycle for future non-BRAM
transport experiments. The future sustained transport threshold is
`1.5 * p99_event_bytes_per_cycle * exact_trace_clock_hz`; the cycle-normalized
threshold is `0.030463220141564377` event bytes/cycle before exact-clock
conversion. This is not production streaming/DMA throughput evidence; future
summaries still need exact streaming-bitstream clock, host receiver, timing,
resource, drop, and noninterference artifacts.
`tools/check_genesys2_streaming_dma_readiness.py` verifies
`streaming_dma_readiness_summary.json`, which turns the p99 1.5x target into a
future non-BRAM transport contract: allowed/disallowed transport kinds, exact
clock conversion, host receiver log fields, required evidence artifact kinds,
required p99/required-sustained summary fields, and no-substitution boundaries.
It is readiness only and does not complete production streaming/DMA throughput
evidence.

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
`tools/check_genesys2_tracer_visibility_baseline.py` verifies
`tracer_visibility_baseline_summary.json`, a Docker-run safe software baseline
for anti-analysis comparison tables. It builds and runs the same probe as
native/no-tracer, native/strace, qemu-user, and qemu-user-strace; validates
`TracerPid`, `PTRACE_TRACEME`, stdout/stderr, and strace-log hashes; and marks
all qemu/strace outputs as software oracles only. This is not Genesys2 board
evidence, real-malware validation, malware-detection accuracy, or a hardware
anti-analysis advantage claim.
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
`tools/check_genesys2_semantic_provenance.py` verifies
`semantic_provenance_summary.json` and every per-sample `semantic_events.json`
provenance map, requiring hardware trace fields to be hardware-marked and
QEMU/strace/host companion rows to remain validation oracles rather than
board-derived recovery claims.
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
strict `uv run rvmt repro:full` route. For a clean checkout, the raw ZIP must
be extracted into the repository root before these checks can validate raw-board
paths.
`tools/check_genesys2_raw_artifact_release.py` verifies
`raw_artifact_release_manifest.json` and the local raw-board ZIP archive by
file count, member path, size, and SHA256. It is a local release candidate until
published as an external immutable asset.
`tools/prepare_genesys2_clean_repro_bundle.py` creates a local clean-export
snapshot of the current worktree, extracts the raw ZIP, copies the bitstream
checker artifacts and CVA6 source-hash inputs, and runs `uv run rvmt
repro:quick` plus `uv run rvmt repro:local` inside that isolated directory.
`tools/check_genesys2_clean_repro_bundle.py` validates the resulting
`clean_repro_bundle_manifest.json` while preserving that this is not a
committed/tagged Git fresh clone.
`tools/check_genesys2_artifact_integrity.py` recursively verifies the canonical
`results/evaluation/genesys2-cva6/current/` evidence root for existing paths,
matching SHA256 values, and absence of wildcard artifacts in PASS-bearing
records.
`tools/check_genesys2_external_closure_readiness.py` verifies
`external_closure_readiness.json`, which records the remaining non-real-malware
external blockers, required artifacts, acceptance criteria, future checker
contracts, and no-substitution rules. It is a readiness-contract gate only; it
does not claim board-native DWARF source lines, full hardware pointer strings,
production streaming/DMA throughput, or Genesys2 board benign controls are
complete.
`tools/check_genesys2_external_closure_intake.py` verifies
`external_closure_intake.json`, the optional future external-summary intake
gate. Current status is `BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED`: missing summaries
are allowed, but any present summary must satisfy the strict schema, threshold,
no-substitution, and artifact-backed `evidence_artifacts` checks before it can
be counted as accepted external evidence. Accepted candidate summaries must
reference the required artifact kinds with existing files and matching sha256
values.
`tools/check_genesys2_hardware_pointer_strings.py` verifies the accepted scoped
full hardware pointer-string external summary. It requires artifact-backed v3
Genesys2/CVA6 openat/write/execve string groups, offset-zero contiguity,
mem_last or terminator evidence, no companion-string substitution, no
kernel-memory fragments, and no full memory dump.
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
missing source-hash manifest is reported as WARN in the fast inventory. A stale
source-hash manifest is reported as `BLOCKED_HOST_VIVADO_REBUILD_REQUIRED` in
the fast inventory and as failure under `--strict`; rebuild the trace-marker
bitstream before using that artifact as source-bound evidence.

Fast fixture self-tests for the current checkers:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-self-test
```

This includes the cycle-counter smoke, cycle-source probe, cycle-source
diagnostics, counter-access matrix, live SD-card Linux manifest, bootrom SD-card
image layout builder, SD-card write-target preflight runner/checker, host
Vivado part/board preflight runner/checker, trace-marker programming
packager/checker, read-only JTAG RAM boot probe runner/checker, Linux rebuild preparer/checker, and Linux counter-path
preflight checker/packager self-tests. Those entries
validate fixture parsing and claim boundaries only; the live Genesys2/UART runs
remain host-side `uv run rvmt ndss:cycle-smoke`, `uv run rvmt
ndss:cycle-source-probe`, `uv run rvmt ndss:cycle-diagnostics`, and `uv run
rvmt ndss:counter-access-matrix` tasks; the live SD-card manifest is captured
with `uv run rvmt ndss:sdcard-linux-manifest`, and the SD-card source preflight
uses `uv run rvmt ndss:sdcard-write-preflight`, `uv run rvmt ndss:linux-source-lock` and `uv run rvmt
ndss:linux-rebuild-prep`/`uv run rvmt ndss:linux-counter-preflight`. The SD-card image builder self-test creates only
a temporary local GPT image fixture and does not claim that a Buildroot/OpenSBI
payload was compiled, written to the physical SD card, or booted on Genesys2.

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
