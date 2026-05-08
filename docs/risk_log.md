# Risk Log

| Risk | Impact | Mitigation | Status |
| --- | --- | --- | --- |
| Committed instruction bits are not exposed at CVA6 commit stage | Branch/syscall decode cannot be wired directly yet | Plumb `orig_instr` to commit trace integration or use RVFI trace path for verification builds | Open |
| Committed CSR address is not exposed at CVA6 commit stage | CSR/SATP events cannot identify watched CSR | Plumb decoded CSR address beside `commit_csr_o` | Open |
| Vivado xsim runtime is high | Slow iteration | Use synthetic commit-level tap testbench first, then CVA6 smoke only after tap checks pass | Open |
| Trace logic affects core timing | Invalid hardware claim | Keep tap sideband-only, register packet formatting, default to drop mode on board | Open |
| Trace bandwidth is too high | Lost events or core perturbation | Disable full retire by default on board and add filters/FIFO in Phase 2 | Open |
| Toolchain is not visible on Windows PATH | Bare-metal build cannot run locally | Use Docker `cva6-toolchain` service or point scripts at installed toolchain | Open |
