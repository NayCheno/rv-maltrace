`timescale 1ns/1ps

module syscall_tap
  import trace_pkg::*;
(
    input  logic          clk_i,
    input  logic          rst_ni,
    input  logic [63:0]   cycle_i,
    input  logic          commit_valid_i,
    input  logic [63:0]   commit_pc_i,
    input  logic [31:0]   commit_instr_i,
    input  logic [63:0]   next_pc_i,
    input  logic          sret_to_user_i,
    input  logic          commit_exception_i,
    input  logic          commit_kill_i,
    input  logic [63:0]   trap_cause_i,
    input  logic [ 1:0]   priv_lvl_i,
    input  logic [63:0]   satp_i,
    input  logic [7:0][63:0] args_i,
    output logic          trace_valid_o,
    output trace_packet_t trace_packet_o
);

  localparam logic [31:0] INSTR_ECALL = 32'h0000_0073;
  localparam logic [31:0] INSTR_SRET  = 32'h1020_0073;
  localparam logic [63:0] CAUSE_U_ECALL = 64'd8;

  logic outstanding_q;
  logic [63:0] next_syscall_id_q;
  logic [63:0] active_syscall_id_q;
  logic [63:0] entry_cycle_q;
  logic syscall_entry_valid;
  logic syscall_ret_valid;
  logic user_ecall_valid;

  assign user_ecall_valid = commit_exception_i &&
                            commit_instr_i == INSTR_ECALL &&
                            priv_lvl_i == TRACE_PRIV_U &&
                            trap_cause_i == CAUSE_U_ECALL;
  assign syscall_entry_valid = !commit_kill_i &&
                               (commit_valid_i || commit_exception_i) &&
                               user_ecall_valid;
  assign syscall_ret_valid = commit_valid_i &&
                             !commit_exception_i &&
                             !commit_kill_i &&
                             commit_instr_i == INSTR_SRET &&
                             priv_lvl_i == TRACE_PRIV_S &&
                             sret_to_user_i &&
                             outstanding_q;
  assign trace_valid_o = syscall_entry_valid || syscall_ret_valid;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      outstanding_q      <= 1'b0;
      next_syscall_id_q  <= 64'd0;
      active_syscall_id_q <= 64'd0;
      entry_cycle_q      <= 64'd0;
    end else begin
      if (syscall_entry_valid) begin
        outstanding_q       <= 1'b1;
        active_syscall_id_q <= next_syscall_id_q;
        entry_cycle_q       <= cycle_i;
        next_syscall_id_q   <= next_syscall_id_q + 64'd1;
      end else if (syscall_ret_valid) begin
        outstanding_q <= 1'b0;
      end
    end
  end

  always_comb begin
    trace_packet_o = trace_null_packet();
    trace_packet_o.valid = trace_valid_o;
    trace_packet_o.evt   = syscall_entry_valid ? EVT_SYSCALL_ENTRY :
                           syscall_ret_valid ? EVT_SYSCALL_RET : EVT_NONE;
    trace_packet_o.cycle = cycle_i;
    trace_packet_o.pc    = commit_pc_i;
    trace_packet_o.instr = commit_instr_i;
    trace_packet_o.target = syscall_ret_valid ? next_pc_i : 64'd0;
    trace_packet_o.priv  = priv_lvl_i;
    trace_packet_o.satp  = satp_i;
    trace_packet_o.syscall_id = syscall_entry_valid ? next_syscall_id_q : active_syscall_id_q;
    trace_packet_o.duration   = syscall_ret_valid ? cycle_i - entry_cycle_q : 64'd0;
    trace_packet_o.a0    = args_i[0];
    trace_packet_o.a1    = args_i[1];
    trace_packet_o.a2    = args_i[2];
    trace_packet_o.a3    = args_i[3];
    trace_packet_o.a4    = args_i[4];
    trace_packet_o.a5    = args_i[5];
    trace_packet_o.a6    = args_i[6];
    trace_packet_o.a7    = args_i[7];
  end

endmodule
