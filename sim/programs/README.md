# Bare-metal Program Seeds

These programs are the Phase 1C source seeds for CVA6 execution tests. The
current `tb_trace_top_unit` regression does not instantiate CVA6 or execute
these binaries; it directly drives the logical trace inputs to verify the tap
RTL first.

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

Once committed instruction and CSR address plumbing into CVA6 is complete, the
program golden files should be regenerated from objdump and the real CVA6 trace.
