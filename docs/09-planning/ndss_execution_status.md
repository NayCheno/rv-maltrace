# NDSS Execution Status - 2026-06-24

Canonical evidence root: `results/evaluation/genesys2-cva6/current/`.

Overall status: `NOT_NDSS_SUBMISSION_READY`. The local evidence root, checker
chain, trace-correctness fixtures, provenance boundaries, and quick/local
reproduction are substantially tighter. Remaining SD-card/new-kernel,
production streaming/DMA, cycle-overhead, and final paper tasks are still
explicitly blocked or TODO. No unrun Vivado, board, LaTeX, or malware
experiment is marked PASS.

## Completed

- Unified current evidence under
  `results/evaluation/genesys2-cva6/current/` and added the recursive
  artifact/path/SHA256 checker. Current quick/local reproduction now validates
  reproducibility, artifact package, raw ZIP, semantic provenance, local code
  analysis, trace correctness, JTAG RAM-boot probe, and recursive integrity.
- Strengthened CVA6 trace correctness for paper-facing evidence: relaxed SRET
  qualification remains disallowed, syscall entry/return pairing is strict, and
  directed fixtures cover trap, privilege transition, dual-commit, same-cycle
  event ordering, and negative unqualified-SRET cases.
- Added field-level semantic provenance and local code-analysis fixtures for
  exact board ELF hash, PIE/ASLR load bias, runtime process maps, dynamic
  libraries, fork/exec ownership, stripped ELF degradation, and sidecar
  non-promotion. The local fixture summary is
  `PASS_LOCAL_CODE_ANALYSIS_FIXTURES`; it does not claim a new Genesys2 board
  run or board-native DWARF.
- Retained external-summary intake records for board-native source lines,
  scoped full hardware pointer strings, production streaming/DMA throughput,
  and Genesys2 board benign controls through `external_closure_intake.json`.
  The intake remains `OPEN_EXTERNAL_ARTIFACTS_REQUIRED`: current candidate
  summaries are present-invalid/open and are not completion evidence.
- Tightened production streaming/DMA intake: accepted throughput now requires
  eight evidence artifact kinds: transport design manifest, exact streaming
  bitstream clock report, host receiver log, parser output log, drop accounting
  report, timing report, resource report, and noninterference report. The
  current summary is intentionally not accepted as throughput evidence.
- Added a read-only Vivado Hardware Manager JTAG RAM-boot feasibility probe.
  The actual host run observed target
  `localhost:3121/xilinx_tcf/Digilent/200300B81858B`, device `xc7k325t_0`, and
  `hw_ila_1`, but no `hw_axis`, `hw_axi`, or `hw_mem` memory-control object.
  The status is `BLOCKED_JTAG_RAM_BOOT_NO_MEMORY_CONTROL`; no programming,
  reset, memory write, RAM boot, kernel update, SD-card modification, or board
  boot is claimed.
- Added the JTAG RAM-boot probe to `genesys2-current`, `genesys2-self-test`,
  and `rvmt repro:quick`, so the BLOCKED conclusion is itself checked from a
  hash-bound summary/log.
- Refreshed downstream external closure readiness/intake/plan/preflight,
  operator packet, review audit, reproducibility manifest, raw artifact ZIP,
  artifact package manifest, and recursive integrity records after the new
  code and evidence landed.
- Updated NDSS artifact instructions and check-suite documentation so fresh
  clone reproduction uses `uv run rvmt repro:quick` / `uv run rvmt repro:local`
  and the raw ZIP SHA256 is current.

## Key Artifacts

- Raw artifact release candidate:
  `build/ndss_artifacts/rv-maltrace-genesys2-cva6-current-raw-artifacts.zip`
  SHA256 `d88dc671ca2ab90d72a6b5d6340a6726d98572a41988b9f1ca499e4fff6eac04`,
  file count 1998, size 285238085 bytes.
- Host LaTeX skeleton build:
  `results/evaluation/genesys2-cva6/current/host_latex_build_summary.json`
  SHA256 `b5a30117261a9f58529ef93248adacf1b4607e49f9dec980767b3fe60438b135`;
  `docs/08-publication/ndss2026-rv-maltrace/build/main.pdf` SHA256
  `f234a44632779f73c692ebc6106963cac65ebc437c1b5f98697d40363d4bc937`,
  status `PASS`. This is a skeleton compile only.
- JTAG RAM-boot probe summary:
  `results/evaluation/genesys2-cva6/current/jtag_ram_boot_probe_summary.json`
  SHA256 `064fdf488db30eb72f7124841ee55538abac04267e6aa03dbd5fc3a96bfe9ed4`,
  status `BLOCKED_JTAG_RAM_BOOT_NO_MEMORY_CONTROL`.
- JTAG RAM-boot probe log:
  `results/evaluation/genesys2-cva6/current/jtag_ram_boot_probe.log` SHA256
  `b1e59dbbb581c6af047459735d246770835f0be6b9f61ec0e6d2cb68fb8b85a7`.
- Local code-analysis fixture summary:
  `results/evaluation/genesys2-cva6/current/local_code_analysis_fixture_summary.json`
  SHA256 `9483a40c292299fe9533b5463e69a510f7a44a5df8d092ec4afee11b0585612f`,
  status `PASS_LOCAL_CODE_ANALYSIS_FIXTURES`.
- Trace correctness directed summary:
  `results/evaluation/genesys2-cva6/current/trace_correctness_directed_summary.json`,
  status `PASS`.
- Board benign control external summary:
  `results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json`
  SHA256 `ff8459209a8ce27836ffa7c90ca10fe2efe7d93f72c4d09896747ff39aa083d2`,
  status `PASS`.
- Streaming/DMA throughput template:
  `results/evaluation/genesys2-cva6/current/external_closure_templates/streaming_dma_throughput_summary.template.json`
  SHA256 `0e108a9f5b3357a3f2a63f3e0bfded5c6bbf6e38996bb849ddca50fca561d51f`.

## Modified Files

- CLI and suite wiring: `src/rv_maltrace/cli.py`,
  `tools/check_suites.json`, `tools/run_check_suite.py`,
  `tools/reproduce_genesys2_current.py`.
- Trace correctness: `tools/check_fuzz_trace.py`,
  `tools/package_trace_correctness_directed.py`,
  `tools/check_trace_correctness_directed.py`,
  `results/evaluation/genesys2-cva6/current/trace_correctness_directed_summary.json`.
- Local code analysis: `tools/package_genesys2_local_code_analysis_fixtures.py`,
  `tools/check_genesys2_local_code_analysis_fixtures.py`,
  `results/evaluation/genesys2-cva6/current/local_code_analysis_fixture_summary.json`.
- JTAG RAM-boot probe: `tools/probe_genesys2_jtag_ram_boot.tcl`,
  `tools/run_genesys2_jtag_ram_boot_probe.py`,
  `tools/check_genesys2_jtag_ram_boot_probe.py`,
  `results/evaluation/genesys2-cva6/current/jtag_ram_boot_probe_summary.json`,
  `results/evaluation/genesys2-cva6/current/jtag_ram_boot_probe.log`.
- External closure and streaming/DMA:
  `tools/check_genesys2_external_closure_intake.py`,
  `tools/package_genesys2_external_closure_plan.py`,
  `tools/package_genesys2_streaming_dma_throughput.py`,
  `results/evaluation/genesys2-cva6/current/external_closure_intake.json`,
  `results/evaluation/genesys2-cva6/current/external_closure_plan.json`,
  `results/evaluation/genesys2-cva6/current/external_closure_templates/streaming_dma_throughput_summary.template.json`.
- Artifact/repro documents and manifests:
  `docs/07-evaluation-evidence/ndss_artifact_instructions.md`,
  `docs/07-evaluation-evidence/ndss_host_runbook.md`,
  `docs/08-publication/ndss2026/claim_nonclaim_matrix.md`,
  `docs/08-publication/ndss2026/experiment_tables.md`,
  `docs/08-publication/ndss2026/paper.tex`,
  `docs/08-publication/ndss2026/paper_skeleton.md`,
  `docs/10-process/check_suites.md`,
  `results/evaluation/genesys2-cva6/current/reproducibility_manifest.json`,
  `results/evaluation/genesys2-cva6/current/artifact_package_manifest.json`,
  `results/evaluation/genesys2-cva6/current/raw_artifact_release_manifest.json`.

## Commands And Results

- `uv run rvmt ndss:jtag-ram-boot-probe` - executed on host Vivado; wrote the
  JTAG RAM-boot probe summary/log with
  `BLOCKED_JTAG_RAM_BOOT_NO_MEMORY_CONTROL`.
- `uv run python tools/check_genesys2_jtag_ram_boot_probe.py --root .` - PASS
  for the evidence-backed BLOCKED summary.
- `uv run python tools/check_genesys2_jtag_ram_boot_probe.py --self-test` -
  PASS.
- `uv run python tools/run_genesys2_jtag_ram_boot_probe.py --self-test` -
  PASS.
- `uv run rvmt ndss:trace-correctness-directed` - PASS; regenerated directed
  trace correctness summary.
- `uv run python tools/check_fuzz_trace.py --self-test` - PASS.
- `uv run python tools/package_trace_correctness_directed.py --self-test` -
  PASS.
- `uv run python tools/check_trace_correctness_directed.py --self-test` -
  PASS.
- `uv run python tools/check_timing_principles.py --self-test` - PASS.
- `uv run python tools/check_timing_principles.py` - PASS.
- `uv run rvmt ndss:local-code-analysis` - PASS.
- `uv run python tools/package_genesys2_local_code_analysis_fixtures.py --self-test`
  - PASS.
- `uv run python tools/check_genesys2_local_code_analysis_fixtures.py --self-test`
  - PASS.
- `uv run python tools/analyze_single_riscv_binary_trace.py --self-test` -
  PASS.
- `uv run python tools/package_genesys2_streaming_dma_throughput.py --self-test`
  - PASS.
- `uv run python tools/check_genesys2_external_closure_intake.py --self-test`
  - PASS.
- `uv run python tools/package_genesys2_external_closure_plan.py --self-test`
  - PASS.
- `uv run python tools/check_genesys2_external_closure_plan.py --root .` -
  PASS.
- `uv run python tools/prepare_genesys2_external_summary.py --root . --check-templates`
  - PASS.
- `uv run python tools/check_genesys2_streaming_dma_readiness.py --root .` -
  PASS.
- `uv run python tools/check_genesys2_external_closure_intake.py --root .` -
  PASS; overall closure remains `OPEN_EXTERNAL_ARTIFACTS_REQUIRED`.
- `uv run python tools/run_check_suite.py --self-test` - PASS.
- `uv run python tools/reproduce_genesys2_current.py --self-test` - PASS.
- `uv run rvmt repro:quick` - PASS after manifest refresh.
- `uv run rvmt repro:local` - PASS after manifest refresh.
- `uv run rvmt repro:full` - PASS; includes compileall, `genesys2-current`
  76/76, artifact suite, `genesys2-self-test` 102/102, and
  `ccfa-gate-self-test` 52/52.
- `uv run rvmt ndss:host-latex` - PASS on host LaTeX; generated the skeleton
  PDF listed above. The log contains layout warnings, so this is not a final
  paper-layout readiness claim.
- `uv run python tools/check_ndss_host_latex_build.py --root .` - PASS.
- `uv run rvmt ndss:docker-full` - PASS in Docker `linux-behavior`; it reran
  the full reproduction set inside the container with
  `UV_PROJECT_ENVIRONMENT=/tmp/rvmt-uv-env` and
  `UV_CACHE_DIR=/tmp/rvmt-uv-cache`.

## Still Host/External

- Physical SD-card write of `build/linux/genesys2-cva6/sdcard.img` has not
  been performed because the user is away from the card and no safe host target
  is currently available.
- Genesys2 boot from the newly built SD image has not been captured.
- Live kernel config export from the newly built board image remains blocked.
- PMU/SBI PMU, user `rdcycle`, kernel perf cycles, and cycle-level overhead
  remain unproved on board. Existing board summaries are truthful BLOCKED
  evidence only.
- Direct RAM boot or kernel update over JTAG is not feasible with the current
  observed bitstream/control path. A new bitstream exposing JTAG-to-AXI or an
  equivalent memory-control/hart-control path is required before any non-SD
  RAM-load experiment.
- Production non-BRAM streaming/DMA throughput remains blocked until the
  required eight-artifact external throughput summary is produced and accepted.
- Independent real malware validation remains open and non-claimed.
- The NDSS paper is still a skeleton; host LaTeX build proves only that the
  skeleton compiles, not submission readiness.

## Next Priority

With the user away from the SD card, the next highest-priority actionable task
is to design and build a Genesys2/CVA6 trace/debug bitstream that exposes a
Vivado-accessible memory-control path, such as JTAG-to-AXI, then rerun
`uv run rvmt ndss:jtag-ram-boot-probe` and only proceed to a separate
non-read-only RAM-load experiment if `--require-ram-control` passes.
