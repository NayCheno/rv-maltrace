# Bare-metal Program Seeds

These programs are the Phase 1C source seeds for the future CVA6 execution
testbench. The current `tb_trace_top_unit` regression does not instantiate CVA6
or execute these binaries; it directly drives the logical trace inputs to verify
the tap RTL first.

Runtime files under `sim/programs/common/` provide:

- `_start` and stack setup.
- `mtvec` initialization.
- `rvmt_trap_vector`, which advances past expected `illegal`, `ebreak`, and
  `ecall` traps.
- `rvmt_finish`, which writes the MMIO tohost address `0x10000000`.

Once committed instruction and CSR address plumbing into CVA6 is complete, the
program golden files should be regenerated from objdump and the real CVA6 trace.
