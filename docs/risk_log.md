# Risk Log

| Risk | Impact | Mitigation | Status |
| --- | --- | --- | --- |
| Committed instruction bits are not exposed at CVA6 commit stage | Branch/syscall decode cannot be wired directly from raw commit-stage RTL yet | Phase 1 uses CVA6 RVFI in verification builds; direct commit-stage `orig_instr` plumbing remains future work before a non-RVFI integration claim | Mitigated for Phase 1 direct-core xsim; open for production RTL integration |
| Committed CSR address is not exposed at CVA6 commit stage | Full watched CSR/SATP events cannot be identified from raw commit-stage RTL yet | Phase 1 RVFI direct-core path wires `satp`; synthetic tests cover SATP/watched CSR semantics; direct-core CSR/SATP program coverage and decoded CSR address plumbing remain future work | Mitigated for synthetic semantics and direct-core wiring; open for direct-core CSR/SATP coverage and full watched-CSR CVA6 integration |
| Vivado xsim runtime is high | Slow iteration | Use synthetic commit-level tap testbench first, then run `sim:cva6-smoke` only after tap checks pass | Mitigated by split `sim:trace-unit` and direct-core `sim:cva6-smoke` gates |
| Vivado v2025.2 xsim kernel fatal in upstream CVA6 `axi_demux.sv` | Full `ariane_testharness` SoC smoke cannot retire the test program locally | Use the direct-core `sim:cva6-smoke` matrix as the local committed-trace execution gate; rerun full SoC smoke with an alternate Vivado/xsim setting or upstream AXI fix before claiming full testharness PASS | Open |
| Genesys 2 Vivado part or board files unavailable | Baseline bitstream build cannot start | Run `uv run rvmt vivado:check` before bitstream work | Preflight PASS on 2026-05-08 for `xc7k325tffg900-2` and `digilentinc.com:genesys2:part0:1.1`; bitstream/license gate still open |
| Trace logic affects core timing | Invalid hardware claim | Keep tap sideband-only, register packet formatting, default to drop mode on board | Open |
| Trace bandwidth is too high | Lost events or core perturbation | Disable full retire by default on board and add filters/FIFO in Phase 2 | Open |
| Toolchain is not visible on Windows PATH | Bare-metal build cannot run locally | Use Docker `cva6-toolchain` service or point scripts at installed toolchain | Open |
