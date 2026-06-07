# FPGA Workspace

This directory is reserved for repository-owned FPGA bring-up notes, board
profiles, ILA plans, constraints overlays, and host-side scripts. The current
scaffold contains notes only. Generated Vivado outputs remain under
`build/vivado/<board>-<target>/` or the upstream CVA6 working tree and are
intentionally ignored by git.

## Stable Artifact Convention

`uv run rvmt bitstream:build` and `uv run rvmt bitstream:collect` use:

```text
build/vivado/<board>-<target>/
  project/      Vivado GUI project generated for source/constraint browsing
  work-fpga/    bitstream, cfgmem image, checkpoint, copied IP artifacts
  reports/      timing, utilization, route, and check_timing reports
```

For the current default configuration, the resolved directory is:

```text
build/vivado/genesys2-cv64a6_imafdc_sv39/
```

Do not commit generated `.bit`, `.mcs`, `.dcp`, `.rpt`, `.wdb`, `.xpr`, or
Vivado work directories. Promote only small, stable summaries or scripts that
are needed to reproduce the gate.

## Board Profiles

| Board | Profile | Status | Notes |
| --- | --- | --- | --- |
| Genesys 2 | `fpga/genesys2/` | TODO(BOARD) | Repository-local notes exist; physical-board evidence still belongs under `results/board/.../<run-id>/`. |

## Evidence Boundary

- Bitstream generation evidence belongs in `docs/03-platform-architecture/genesys2/board_bringup.md` and
  `docs/03-platform-architecture/genesys2/baseline_pass_criteria.md` only when the expected Vivado artifacts
  exist.
- Physical-board evidence must include run-specific transcripts, UART/tohost
  output, trace dumps, and decoded comparisons under `results/board/...`.
- First-board trace profiles must keep high-volume full retire and full memory
  tracing disabled unless a separate bandwidth and timing gate enables them.
