# Phase 5 Observation

Status: PASS.

The trace-enabled Genesys2/CVA6 build completed with `uv run rvmt bitstream:build-trace` and generated a routed bitstream plus JTAG-visible ILA `.ltx` export metadata. Routed timing is met with WNS 0.031 ns and no route errors. The UART constraint file has no diff from the accepted Phase 2 PMOD JC pinout.

The ILA export is intentionally minimal for first-board validation: probe0 is trace fire, and probe1 is a 104-bit packed event payload containing event kind, cycle, low PC, and an event-specific primary field. Full retire remains disabled; the export is bounded and JTAG-visible and does not add ready/stall/backpressure to CVA6 commit logic.

Phase 6 is not claimed by this evidence. Phase 6 still requires board-side Linux user workload execution for `hello_write`, `file_open_read_write`, `fork_exec`, and `illegal_instruction`, with real `program.log`, captured `trace.jsonl`, `compare.log`, and per-program observation files.
