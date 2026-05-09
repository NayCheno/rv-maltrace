module tb_trace_scoreboard
  import trace_pkg::*;
(
    input logic          clk_i,
    input logic          rst_ni,
    input trace_packet_t trace_packet_i,
    input logic          trace_valid_i,
    input logic          finish_i,
    input logic          pass_i
);

  int retire_count;
  int branch_count;
  int jump_count;
  int syscall_entry_count;
  int syscall_ret_count;
  int arg_mem_count;
  int trap_count;
  int csr_count;
  int satp_count;
  int priv_count;
  int drop_count;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      retire_count <= 0;
      branch_count <= 0;
      jump_count   <= 0;
      syscall_entry_count <= 0;
      syscall_ret_count   <= 0;
      arg_mem_count       <= 0;
      trap_count   <= 0;
      csr_count    <= 0;
      satp_count   <= 0;
      priv_count   <= 0;
      drop_count   <= 0;
    end else if (trace_valid_i && trace_packet_i.valid) begin
      unique case (trace_packet_i.evt)
        EVT_RETIRE: retire_count <= retire_count + 1;
        EVT_BRANCH: branch_count <= branch_count + 1;
        EVT_JUMP:   jump_count   <= jump_count + 1;
        EVT_SYSCALL_ENTRY: syscall_entry_count <= syscall_entry_count + 1;
        EVT_SYSCALL_RET:   syscall_ret_count   <= syscall_ret_count + 1;
        EVT_ARG_MEM:       arg_mem_count       <= arg_mem_count + 1;
        EVT_TRAP:          trap_count          <= trap_count + 1;
        EVT_CSR:           csr_count           <= csr_count + 1;
        EVT_SATP:          satp_count          <= satp_count + 1;
        EVT_PRIV:          priv_count          <= priv_count + 1;
        EVT_DROP:          drop_count          <= drop_count + 1;
        default: begin
        end
      endcase
    end
  end

  final begin
    $display("[RVMT] retire=%0d branch=%0d jump=%0d syscall_entry=%0d syscall_ret=%0d arg_mem=%0d trap=%0d csr=%0d satp=%0d priv=%0d drop=%0d",
             retire_count, branch_count, jump_count, syscall_entry_count, syscall_ret_count, arg_mem_count, trap_count, csr_count, satp_count, priv_count, drop_count);
    if (finish_i && pass_i) begin
      $display("[PASS] synthetic trace test finished");
    end else begin
      $display("[FAIL] synthetic trace test did not finish cleanly");
      $fatal(1, "synthetic trace test did not finish cleanly");
    end
  end

endmodule
