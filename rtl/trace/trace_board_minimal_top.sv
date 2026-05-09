module trace_board_minimal_top
  import trace_pkg::*;
#(
    parameter int WB_PORTS = 1,
    parameter int EVENT_QUEUE_DEPTH = 8,
    parameter int PIPELINE_INPUTS = 1,
    parameter logic        PC_FILTER_ENABLE = 1'b0,
    parameter logic [63:0] PC_START = 64'd0,
    parameter logic [63:0] PC_END = 64'hffff_ffff_ffff_ffff,
    parameter logic        PRIV_FILTER_ENABLE = 1'b0,
    parameter logic [ 3:0] PRIV_MASK = 4'hf
) (
    input  logic                      clk_i,
    input  logic                      rst_ni,

    input  logic                      commit_valid_i,
    input  logic [63:0]               commit_pc_i,
    input  logic [31:0]               commit_instr_i,
    input  logic [63:0]               next_pc_i,
    input  logic                      sret_to_user_i,
    input  logic                      jalr_target_valid_i,
    input  logic [63:0]               jalr_target_i,
    input  logic                      commit_exception_i,
    input  logic                      commit_kill_i,

    input  logic [WB_PORTS-1:0]       wb_valid_i,
    input  logic [WB_PORTS-1:0]       wb_kill_i,
    input  logic [WB_PORTS-1:0][4:0]  wb_rd_i,
    input  logic [WB_PORTS-1:0][63:0] wb_data_i,

    input  logic                      trap_valid_i,
    input  logic [63:0]               trap_pc_i,
    input  logic [63:0]               trap_cause_i,
    input  logic [63:0]               trap_tval_i,

    input  logic                      csr_valid_i,
    input  logic [11:0]               csr_addr_i,
    input  logic [63:0]               csr_wdata_i,
    input  logic [ 1:0]               priv_lvl_i,
    input  logic [63:0]               satp_i,

    output logic                      trace_valid_o,
    output trace_packet_t             trace_packet_o
);

  logic        trace_enable_retire;
  logic        trace_enable_branch;
  logic        trace_enable_jump;
  logic        trace_enable_syscall;
  logic        trace_enable_trap;
  logic        trace_enable_context;
  logic        trace_enable_marker;
  logic        trace_enable_drop;
  logic        trace_pc_filter_enable;
  logic [63:0] trace_pc_start;
  logic [63:0] trace_pc_end;
  logic        trace_priv_filter_enable;
  logic [ 3:0] trace_priv_mask;

  trace_board_minimal_ctrl #(
      .PC_FILTER_ENABLE(PC_FILTER_ENABLE),
      .PC_START(PC_START),
      .PC_END(PC_END),
      .PRIV_FILTER_ENABLE(PRIV_FILTER_ENABLE),
      .PRIV_MASK(PRIV_MASK)
  ) i_board_minimal_ctrl (
      .trace_enable_retire_o(trace_enable_retire),
      .trace_enable_branch_o(trace_enable_branch),
      .trace_enable_jump_o(trace_enable_jump),
      .trace_enable_syscall_o(trace_enable_syscall),
      .trace_enable_trap_o(trace_enable_trap),
      .trace_enable_context_o(trace_enable_context),
      .trace_enable_marker_o(trace_enable_marker),
      .trace_enable_drop_o(trace_enable_drop),
      .trace_pc_filter_enable_o(trace_pc_filter_enable),
      .trace_pc_start_o(trace_pc_start),
      .trace_pc_end_o(trace_pc_end),
      .trace_priv_filter_enable_o(trace_priv_filter_enable),
      .trace_priv_mask_o(trace_priv_mask)
  );

  trace_top #(
      .WB_PORTS(WB_PORTS),
      .EVENT_QUEUE_DEPTH(EVENT_QUEUE_DEPTH),
      .PIPELINE_INPUTS(PIPELINE_INPUTS)
  ) i_trace_top (
      .clk_i,
      .rst_ni,
      .commit_valid_i,
      .commit_pc_i,
      .commit_instr_i,
      .next_pc_i,
      .sret_to_user_i,
      .jalr_target_valid_i,
      .jalr_target_i,
      .commit_exception_i,
      .commit_kill_i,
      .wb_valid_i,
      .wb_kill_i,
      .wb_rd_i,
      .wb_data_i,
      .trap_valid_i,
      .trap_pc_i,
      .trap_cause_i,
      .trap_tval_i,
      .csr_valid_i,
      .csr_addr_i,
      .csr_wdata_i,
      .priv_lvl_i,
      .satp_i,
      .trace_mem_mode_i(TRACE_MEM_MODE_NONE),
      .mem_load_valid_i(1'b0),
      .mem_load_pc_i(64'd0),
      .mem_load_addr_i(64'd0),
      .mem_load_data_i(64'd0),
      .mem_load_size_i(3'd0),
      .trace_enable_retire_i(trace_enable_retire),
      .trace_enable_branch_i(trace_enable_branch),
      .trace_enable_jump_i(trace_enable_jump),
      .trace_enable_syscall_i(trace_enable_syscall),
      .trace_enable_trap_i(trace_enable_trap),
      .trace_enable_context_i(trace_enable_context),
      .trace_enable_marker_i(trace_enable_marker),
      .trace_enable_drop_i(trace_enable_drop),
      .trace_pc_filter_enable_i(trace_pc_filter_enable),
      .trace_pc_start_i(trace_pc_start),
      .trace_pc_end_i(trace_pc_end),
      .trace_priv_filter_enable_i(trace_priv_filter_enable),
      .trace_priv_mask_i(trace_priv_mask),
      .trace_valid_o,
      .trace_packet_o
  );

endmodule
