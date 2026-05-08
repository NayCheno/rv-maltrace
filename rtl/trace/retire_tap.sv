module retire_tap
  import trace_pkg::*;
(
    input  logic          clk_i,
    input  logic          rst_ni,
    input  logic [63:0]   cycle_i,
    input  logic          commit_valid_i,
    input  logic [63:0]   commit_pc_i,
    input  logic [31:0]   commit_instr_i,
    input  logic          commit_exception_i,
    input  logic          commit_kill_i,
    input  logic [ 1:0]   priv_lvl_i,
    input  logic [63:0]   satp_i,
    output logic          trace_valid_o,
    output trace_packet_t trace_packet_o
);

  assign trace_valid_o = commit_valid_i && !commit_exception_i && !commit_kill_i;

  always_comb begin
    trace_packet_o = trace_null_packet();
    trace_packet_o.valid = trace_valid_o;
    trace_packet_o.evt   = trace_valid_o ? EVT_RETIRE : EVT_NONE;
    trace_packet_o.cycle = cycle_i;
    trace_packet_o.pc    = commit_pc_i;
    trace_packet_o.instr = commit_instr_i;
    trace_packet_o.priv  = priv_lvl_i;
    trace_packet_o.satp  = satp_i;
  end

endmodule
