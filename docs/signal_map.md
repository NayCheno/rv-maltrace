# CVA6 Signal Map

This map records the first RTL-level attachment points for the commit-level
trace tap. Signal paths are based on the local CVA6 checkout locked in
`docs/version_lock.md`.

## Commit Signals

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | ---: | --- |
| `commit_valid` | `commit_stage.commit_ack_o[i] && !commit_stage.commit_drop_i[i] && !commit_stage.commit_instr_i[i].ex.valid` | `NrCommitPorts` | Normal retire event gate for committed non-exception instructions. Raw `commit_ack_o` alone is not enough because dropped entries may still be acknowledged. |
| `commit_pc` | `commit_stage.commit_instr_i[i].pc` | `VLEN` | PC for the committing scoreboard entry. |
| `commit_instr` | TBD integration tap | 32 | `scoreboard.sv` tracks `orig_instr_i/o`, but `commit_stage.sv` does not currently receive the 32-bit instruction word. The trace wrapper must plumb this from the scoreboard/orig-instr queue or RVFI path. |
| `commit_exception` | `commit_stage.commit_instr_i[i].ex.valid` and `commit_stage.csr_exception_i.valid` | 1 | Used to suppress normal retire events and feed trap events. |
| `commit_kill` | `commit_stage.commit_drop_i[i]` | `NrCommitPorts` | Scoreboard cancellation/flush marker. |
| `commit_csr` | `commit_stage.commit_csr_o` | 1 | Indicates a committed CSR instruction accepted by the CSR file. |

## Register Writeback

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | ---: | --- |
| `wb_valid` | `commit_stage.we_gpr_o[i]` | `NrCommitPorts` | GPR write enable at commit. |
| `wb_rd` | `commit_stage.waddr_o[i]` / `commit_stage.commit_instr_i[i].rd` | 5 | Destination register. |
| `wb_data` | `commit_stage.wdata_o[i]` | `XLEN` | Committed register write data. |
| `wb_kill` | `commit_stage.commit_drop_i[i]` | 1 | Ignore killed/cancelled writes. |

## Trap Signals

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | ---: | --- |
| `trap_valid` | `commit_stage.exception_o.valid` | 1 | Final exception/interrupt selected at commit. |
| `trap_pc` | `commit_stage.commit_instr_i[0].pc` | `VLEN` | Trap PC for synchronous exceptions. |
| `trap_cause` | `commit_stage.exception_o.cause` | `XLEN` | Exception or interrupt cause. |
| `trap_tval` | `commit_stage.exception_o.tval` | `XLEN` | Trap value, implementation dependent for some causes. |

## CSR / Context

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | ---: | --- |
| `priv_lvl` | `csr_regfile.priv_lvl_o` | 2 | Current effective privilege level. |
| `satp` | `csr_regfile.satp_q` or `rvfi_csr_o.satp_q` | `XLEN` | Direct `satp_q` is internal; RVFI CSR mirror is useful for verification builds. |
| `csr_we` | `commit_stage.commit_csr_o` | 1 | Committed CSR write gate. |
| `csr_addr` | CSR instruction decode path | 12 | `commit_stage` exposes `csr_op_o`/`csr_wdata_o` but not the CSR address; the first integration must plumb the decoded address. |
| `csr_wdata` | `commit_stage.csr_wdata_o` | `XLEN` | Data presented to CSR file for committed CSR writes. |

## Integration Notes

- The MVP trace RTL is written as a sideband tap and does not alter CVA6 state.
- Two integration gaps remain before wiring directly into CVA6: committed
  32-bit instruction bits and committed CSR address.
- The synthetic testbench drives these logical signals directly so tap behavior
  can be verified before intrusive CVA6 plumbing.
- The retire tap must use `commit_ack_o && !commit_drop_i && !exception` as
  its logical valid expression; exception paths are emitted by the trap tap.
