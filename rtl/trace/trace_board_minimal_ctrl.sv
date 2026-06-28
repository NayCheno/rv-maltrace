`timescale 1ns/1ps

module trace_board_minimal_ctrl #(
    parameter logic        PC_FILTER_ENABLE = 1'b0,
    parameter logic [63:0] PC_START = 64'd0,
    parameter logic [63:0] PC_END = 64'hffff_ffff_ffff_ffff,
    parameter logic        PRIV_FILTER_ENABLE = 1'b0,
    parameter logic [ 3:0] PRIV_MASK = 4'hf
) (
    output logic        trace_enable_retire_o,
    output logic        trace_enable_branch_o,
    output logic        trace_enable_jump_o,
    output logic        trace_enable_syscall_o,
    output logic        trace_enable_trap_o,
    output logic        trace_enable_context_o,
    output logic        trace_enable_marker_o,
    output logic        trace_enable_drop_o,
    output logic        trace_pc_filter_enable_o,
    output logic [63:0] trace_pc_start_o,
    output logic [63:0] trace_pc_end_o,
    output logic        trace_priv_filter_enable_o,
    output logic [ 3:0] trace_priv_mask_o
);

`ifdef RV_MALTRACE_FPGA_TRACE_SOURCE_LINES
  assign trace_enable_retire_o = 1'b1;
  assign trace_enable_branch_o = 1'b0;
  assign trace_enable_jump_o = 1'b0;
  assign trace_enable_syscall_o = 1'b0;
  assign trace_enable_trap_o = 1'b0;
  assign trace_enable_context_o = 1'b0;
  assign trace_enable_marker_o = 1'b1;
  assign trace_enable_drop_o = 1'b1;

  assign trace_pc_filter_enable_o = 1'b1;
  assign trace_pc_start_o = 64'h0000_0000_0001_0574;
  assign trace_pc_end_o = 64'h0000_0000_0001_05ae;
`else
  assign trace_enable_retire_o = 1'b0;
`ifdef RV_MALTRACE_FPGA_TRACE_SYSCALL_MARKER_SCOPE
  assign trace_enable_branch_o = 1'b0;
`elsif RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE
  assign trace_enable_branch_o = 1'b0;
`else
  assign trace_enable_branch_o = 1'b1;
`endif
  assign trace_enable_jump_o = 1'b0;
  assign trace_enable_syscall_o = 1'b1;
`ifdef RV_MALTRACE_FPGA_TRACE_SYSCALL_MARKER_SCOPE
  assign trace_enable_trap_o = 1'b0;
  assign trace_enable_context_o = 1'b0;
`else
  assign trace_enable_trap_o = 1'b1;
  assign trace_enable_context_o = 1'b1;
`endif
`ifdef RV_MALTRACE_FPGA_TRACE_SYSCALL_MARKER_SCOPE
  assign trace_enable_marker_o = 1'b1;
`elsif RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE
  assign trace_enable_marker_o = 1'b1;
`else
  assign trace_enable_marker_o = 1'b0;
`endif
  assign trace_enable_drop_o = 1'b1;

  assign trace_pc_filter_enable_o = PC_FILTER_ENABLE;
  assign trace_pc_start_o = PC_START;
  assign trace_pc_end_o = PC_END;
`endif
  assign trace_priv_filter_enable_o = PRIV_FILTER_ENABLE;
  assign trace_priv_mask_o = PRIV_MASK;

endmodule
