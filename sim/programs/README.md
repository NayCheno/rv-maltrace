# Bare-metal Program Seeds

These programs are the Phase 1C seeds for commit-level behavior tests. The
synthetic `tb_trace_top_unit` regression still drives logical trace inputs
directly to verify tap RTL first; `sim:cva6-smoke` separately instantiates the
CVA6 core and executes the direct-core `cva6_*` DRAM images.

`sim/programs/cva6_*/cva6_*.mem` are minimal hand-encoded DRAM images for the
direct-core CVA6 xsim matrix. They cover smoke, taken branch, jump, ecall,
illegal-instruction trap, and ebreak trap behavior, and each program reaches the
tohost store after the expected committed events have been observed. The older
full `ariane_testharness` smoke path remains available for the SoC harness once
the local Vivado runtime blocker is resolved.

Runtime files under `sim/programs/common/` provide:

- `_start` and stack setup.
- `mtvec` initialization.
- `rvmt_trap_vector`, which advances past expected `illegal`, `ebreak`, and
  `ecall` traps.
- `rvmt_finish`, which writes the MMIO tohost address `0x10000000`.

The direct-core `cva6_*` golden files are hand-authored against the current RVFI
trace adapter output. Regenerate source-built program golden files from objdump
once the Docker bare-metal toolchain is available locally and the full source
program matrix is moved onto the CVA6 direct-core harness.
