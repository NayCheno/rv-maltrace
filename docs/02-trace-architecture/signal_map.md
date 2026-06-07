# CVA6 Signal Map

This map records the first RTL-level attachment points for the commit-level
trace tap. Signal paths are based on the local CVA6 checkout locked in
`docs/10-process/version_lock.md`.

## Commit Signals

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | ---: | --- |
| `commit_valid` | `cva6_rvfi.rvfi_instr_o[i].valid[0]` plus `rvfi_instr_o[i].trap[0]` for non-ECALL traps | `NrCommitPorts` | The RVFI adapter treats `valid || trap` as an event boundary because CVA6 RVFI marks only ECALL exceptions as valid committed instructions. |
| `commit_pc` | `cva6_rvfi.rvfi_instr_o[i].pc_rdata` | `VLEN` | PC for each committed RVFI port. |
| `commit_instr` | `cva6_rvfi.rvfi_instr_o[i].insn` | `ILEN` | The adapter zero-extends the low 32 bits for JSONL and decodes compressed control flow using `rvfi_to_iti.is_compressed[i]`. |
| `commit_next_pc` | `trace_top.next_pc_i` / `rvfi_instr_o[i].pc_wdata` when connected | `VLEN` | Used as `SYSCALL_RET.target`. The RVFI adapter requires an explicit `rvfi_sret_to_user_i` qualifier before emitting a syscall return. |
| `commit_exception` | `cva6_rvfi.rvfi_instr_o[i].trap[0]` | 1 | Used to emit `EVT_TRAP` while suppressing normal retire/branch events. |
| `commit_kill` | `commit_stage.commit_drop_i[i]` | `NrCommitPorts` | Scoreboard cancellation/flush marker. |
| `commit_csr` | `commit_stage.commit_csr_o` | 1 | Indicates a committed CSR instruction accepted by the CSR file. |

## Register Writeback

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | ---: | --- |
| `wb_valid` | `cva6_rvfi.rvfi_instr_o[i].valid[0] && !rvfi_instr_o[i].trap[0] && rd_addr != 0` | `NrCommitPorts` | The RVFI adapter updates a0-a7 in commit-port order so a port-0 arg write is visible to a same-cycle port-1 ECALL. |
| `wb_rd` | `cva6_rvfi.rvfi_instr_o[i].rd_addr` | 5 | Destination register. |
| `wb_data` | `cva6_rvfi.rvfi_instr_o[i].rd_wdata` | `XLEN` | Committed register write data. |
| `wb_kill` | `commit_stage.commit_drop_i[i]` | 1 | Ignore killed/cancelled writes. |

## Trap Signals

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | ---: | --- |
| `trap_valid` | `cva6_rvfi.rvfi_instr_o[i].trap[0]` | `NrCommitPorts` | Captures ECALL and non-ECALL synchronous traps even when `rvfi.valid` is low. |
| `trap_pc` | `cva6_rvfi.rvfi_instr_o[i].pc_rdata` | `VLEN` | Trap PC for synchronous exceptions. |
| `trap_cause` | `cva6_rvfi.rvfi_instr_o[i].cause` | `XLEN` | Exception or interrupt cause. |
| `trap_tval` | `rvfi_to_iti.tval` | `XLEN` | Trap value, implementation dependent for some causes. |

## CSR / Context

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | ---: | --- |
| `priv_lvl` | `cva6_rvfi.rvfi_instr_o[i].mode` | 2 | Effective privilege mode associated with each RVFI entry. |
| `satp` | `rvfi_csr_o.satp.wdata` | `XLEN` | RVFI CSR mirror used by the simulation hook. |
| `csr_we` | `rvfi_csr_o.<watched>.wmask != 0` | 1 | The guarded testharness maps watched CSR deltas to one CSR/SATP event. |
| `csr_addr` | testharness watched-CSR priority encoder | 12 | Maps `satp`, `mstatus`, `sstatus`, `stvec`, `sepc`, `scause`, `stval`, `medeleg`, and `mideleg`. |
| `csr_wdata` | `rvfi_csr_o.<watched>.wdata` | `XLEN` | Data for the watched CSR selected by the testharness hook. |

## Syscall Pointer Snapshot Signals

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | ---: | --- |
| `trace_mem_mode` | `TRACE_MEM_MODE_DEFAULT` / later board CSR | 2 | Defaults to `TRACE_MEM_MODE_NONE`; synthetic tests explicitly select `TRACE_MEM_MODE_RANGE`. |
| `mem_load_valid` | synthetic testbench driver; CVA6 LSU hook TBD | 1 | Qualifies S-mode load data for default-disabled `ARG_MEM` snapshots. |
| `mem_load_pc` | synthetic testbench driver; CVA6 LSU hook TBD | `XLEN` | PC associated with the load that copied from a watched user pointer. |
| `mem_load_addr` | synthetic testbench driver; CVA6 LSU virtual address hook TBD | `XLEN` | Address compared against the active syscall pointer watch range. |
| `mem_load_data` | synthetic testbench driver; CVA6 LSU data hook TBD | `XLEN` | Data emitted only for non-default `TRACE_MEM_MODE_RANGE`. |
| `mem_load_size` | synthetic testbench driver; CVA6 LSU size hook TBD | 3 | Number of valid bytes in `mem_load_data`. |

## Integration Notes

- The MVP trace RTL is written as a sideband tap and does not alter CVA6 state.
- `sim:cva6-smoke` currently runs the direct-core CVA6 xsim matrix through both
  trace-enabled and no-trace snapshots from `sim/tb/tb_cva6_direct_xsim_smoke.sv`.
  The trace-enabled snapshot drives `cva6_rvfi`, the RVFI trace adapter, and
  `tb_trace_sink`; the no-trace snapshot must reach the same tohost PASS result.
- `RV_MALTRACE_TRACE=1` also enables the simulation-only CVA6 RVFI hook in
  `corev_apu/tb/ariane_testharness.sv`; that full SoC harness path now has a
  reproducible `uv run rvmt sim:cva6-full-soc` probe that boots from DRAM and
  reaches a breakpoint-terminated PASS in Vivado v2025.2.
- The synthetic testbench still drives logical tap signals directly. The
  `rvfi_adapter` regression separately checks the CVA6 RVFI committed-stream
  translation, including dual commit ports and compressed control flow.
- The retire tap must use `commit_ack_o && !commit_drop_i && !exception` as
  its logical valid expression; exception paths are emitted by the trap tap.
- `EVT_SYSCALL_ENTRY` is emitted only for U-mode ECALL with U_ECALL cause; S/M
  ECALL remains a `TRAP` and does not create outstanding syscall state.
- `EVT_SYSCALL_RET` is emitted only when SRET is qualified as returning to
  U-mode and a U-mode syscall is outstanding. Synthetic `trace_top` tests drive
  `sret_to_user_i`; the RVFI adapter exposes `rvfi_sret_to_user_i` so a CVA6
  integration must connect the actual privilege-transition predicate rather
  than treating every S-mode SRET as a syscall return.
