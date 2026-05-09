module trace_top
  import trace_pkg::*;
#(
    parameter int WB_PORTS = 1,
    parameter int EVENT_QUEUE_DEPTH = 8,
    parameter int PIPELINE_INPUTS = 1,
    parameter int MAX_ARG_MEM_CAPTURE_BYTES = 256,
    parameter int MAX_ARG_MEM_WATCH_CYCLES = 64
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

    input  trace_mem_mode_e           trace_mem_mode_i,
    input  logic                      mem_load_valid_i,
    input  logic [63:0]               mem_load_pc_i,
    input  logic [63:0]               mem_load_addr_i,
    input  logic [63:0]               mem_load_data_i,
    input  logic [ 2:0]               mem_load_size_i,

    input  logic                      trace_enable_retire_i,
    input  logic                      trace_enable_branch_i,
    input  logic                      trace_enable_jump_i,
    input  logic                      trace_enable_syscall_i,
    input  logic                      trace_enable_trap_i,
    input  logic                      trace_enable_context_i,
    input  logic                      trace_enable_marker_i,
    input  logic                      trace_enable_drop_i,
    input  logic                      trace_pc_filter_enable_i,
    input  logic [63:0]               trace_pc_start_i,
    input  logic [63:0]               trace_pc_end_i,
    input  logic                      trace_priv_filter_enable_i,
    input  logic [ 3:0]               trace_priv_mask_i,

    output logic                      trace_valid_o,
    output trace_packet_t             trace_packet_o
);

  logic [63:0] cycle_q;
  logic [63:0] sample_cycle;
  logic        commit_valid_s;
  logic [63:0] commit_pc_s;
  logic [31:0] commit_instr_s;
  logic [63:0] next_pc_s;
  logic        sret_to_user_s;
  logic        jalr_target_valid_s;
  logic [63:0] jalr_target_s;
  logic        commit_exception_s;
  logic        commit_kill_s;
  logic [WB_PORTS-1:0]       wb_valid_s;
  logic [WB_PORTS-1:0]       wb_kill_s;
  logic [WB_PORTS-1:0][4:0]  wb_rd_s;
  logic [WB_PORTS-1:0][63:0] wb_data_s;
  logic        trap_valid_s;
  logic [63:0] trap_pc_s;
  logic [63:0] trap_cause_s;
  logic [63:0] trap_tval_s;
  logic        csr_valid_s;
  logic [11:0] csr_addr_s;
  logic [63:0] csr_wdata_s;
  logic [1:0]  priv_lvl_s;
  logic [63:0] satp_s;
  trace_mem_mode_e trace_mem_mode_s;
  logic        mem_load_valid_s;
  logic [63:0] mem_load_pc_s;
  logic [63:0] mem_load_addr_s;
  logic [63:0] mem_load_data_s;
  logic [2:0]  mem_load_size_s;
  logic        trace_enable_retire_s;
  logic        trace_enable_branch_s;
  logic        trace_enable_jump_s;
  logic        trace_enable_syscall_s;
  logic        trace_enable_trap_s;
  logic        trace_enable_context_s;
  logic        trace_enable_marker_s;
  logic        trace_enable_drop_s;
  logic        trace_pc_filter_enable_s;
  logic [63:0] trace_pc_start_s;
  logic [63:0] trace_pc_end_s;
  logic        trace_priv_filter_enable_s;
  logic [3:0]  trace_priv_mask_s;
  logic [7:0][63:0] args;

  logic retire_valid;
  logic branch_valid;
  logic syscall_valid;
  logic arg_mem_valid;
  logic trap_valid;
  logic context_valid;

  trace_packet_t retire_packet;
  trace_packet_t branch_packet;
  trace_packet_t syscall_packet;
  trace_packet_t arg_mem_packet;
  trace_packet_t trap_packet;
  trace_packet_t context_packet;
  logic filtered_retire_valid;
  logic filtered_branch_valid;
  logic filtered_syscall_valid;
  logic filtered_arg_mem_valid;
  logic filtered_trap_valid;
  logic filtered_context_valid;
  trace_packet_t filtered_retire_packet;
  trace_packet_t filtered_branch_packet;
  trace_packet_t filtered_syscall_packet;
  trace_packet_t filtered_arg_mem_packet;
  trace_packet_t filtered_trap_packet;
  trace_packet_t filtered_context_packet;

  localparam int NUM_SOURCES = 6;
  localparam int QUEUE_COUNT_WIDTH = $clog2(EVENT_QUEUE_DEPTH + 1);

  logic [NUM_SOURCES-1:0] source_valid;
  trace_packet_t source_packet [NUM_SOURCES];
  int unsigned current_selected_idx;
  logic        drop_output;
  logic        drop_defer_q;
  logic [63:0] dropped_this_cycle;
  logic [63:0] drop_count_q;
  trace_packet_t drop_packet;

  trace_packet_t pending_q [EVENT_QUEUE_DEPTH];
  trace_packet_t pending_n [EVENT_QUEUE_DEPTH];
  logic [QUEUE_COUNT_WIDTH-1:0] pending_count_q;
  logic [QUEUE_COUNT_WIDTH-1:0] pending_count_n;

  generate
    if (PIPELINE_INPUTS != 0) begin : g_input_pipeline
      always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
          sample_cycle <= 64'd0;
          commit_valid_s <= 1'b0;
          commit_pc_s <= 64'd0;
          commit_instr_s <= 32'd0;
          next_pc_s <= 64'd0;
          sret_to_user_s <= 1'b0;
          jalr_target_valid_s <= 1'b0;
          jalr_target_s <= 64'd0;
          commit_exception_s <= 1'b0;
          commit_kill_s <= 1'b0;
          wb_valid_s <= '0;
          wb_kill_s <= '0;
          wb_rd_s <= '0;
          wb_data_s <= '0;
          trap_valid_s <= 1'b0;
          trap_pc_s <= 64'd0;
          trap_cause_s <= 64'd0;
          trap_tval_s <= 64'd0;
          csr_valid_s <= 1'b0;
          csr_addr_s <= 12'd0;
          csr_wdata_s <= 64'd0;
          priv_lvl_s <= TRACE_PRIV_M;
          satp_s <= 64'd0;
          trace_mem_mode_s <= TRACE_MEM_MODE_NONE;
          mem_load_valid_s <= 1'b0;
          mem_load_pc_s <= 64'd0;
          mem_load_addr_s <= 64'd0;
          mem_load_data_s <= 64'd0;
          mem_load_size_s <= 3'd0;
          trace_enable_retire_s <= 1'b0;
          trace_enable_branch_s <= 1'b0;
          trace_enable_jump_s <= 1'b0;
          trace_enable_syscall_s <= 1'b0;
          trace_enable_trap_s <= 1'b0;
          trace_enable_context_s <= 1'b0;
          trace_enable_marker_s <= 1'b0;
          trace_enable_drop_s <= 1'b0;
          trace_pc_filter_enable_s <= 1'b0;
          trace_pc_start_s <= 64'd0;
          trace_pc_end_s <= 64'd0;
          trace_priv_filter_enable_s <= 1'b0;
          trace_priv_mask_s <= 4'hf;
        end else begin
          sample_cycle <= cycle_q;
          commit_valid_s <= commit_valid_i;
          commit_pc_s <= commit_pc_i;
          commit_instr_s <= commit_instr_i;
          next_pc_s <= next_pc_i;
          sret_to_user_s <= sret_to_user_i;
          jalr_target_valid_s <= jalr_target_valid_i;
          jalr_target_s <= jalr_target_i;
          commit_exception_s <= commit_exception_i;
          commit_kill_s <= commit_kill_i;
          wb_valid_s <= wb_valid_i;
          wb_kill_s <= wb_kill_i;
          wb_rd_s <= wb_rd_i;
          wb_data_s <= wb_data_i;
          trap_valid_s <= trap_valid_i;
          trap_pc_s <= trap_pc_i;
          trap_cause_s <= trap_cause_i;
          trap_tval_s <= trap_tval_i;
          csr_valid_s <= csr_valid_i;
          csr_addr_s <= csr_addr_i;
          csr_wdata_s <= csr_wdata_i;
          priv_lvl_s <= priv_lvl_i;
          satp_s <= satp_i;
          trace_mem_mode_s <= trace_mem_mode_i;
          mem_load_valid_s <= mem_load_valid_i;
          mem_load_pc_s <= mem_load_pc_i;
          mem_load_addr_s <= mem_load_addr_i;
          mem_load_data_s <= mem_load_data_i;
          mem_load_size_s <= mem_load_size_i;
          trace_enable_retire_s <= trace_enable_retire_i;
          trace_enable_branch_s <= trace_enable_branch_i;
          trace_enable_jump_s <= trace_enable_jump_i;
          trace_enable_syscall_s <= trace_enable_syscall_i;
          trace_enable_trap_s <= trace_enable_trap_i;
          trace_enable_context_s <= trace_enable_context_i;
          trace_enable_marker_s <= trace_enable_marker_i;
          trace_enable_drop_s <= trace_enable_drop_i;
          trace_pc_filter_enable_s <= trace_pc_filter_enable_i;
          trace_pc_start_s <= trace_pc_start_i;
          trace_pc_end_s <= trace_pc_end_i;
          trace_priv_filter_enable_s <= trace_priv_filter_enable_i;
          trace_priv_mask_s <= trace_priv_mask_i;
        end
      end
    end else begin : g_no_input_pipeline
      assign sample_cycle = cycle_q;
      assign commit_valid_s = commit_valid_i;
      assign commit_pc_s = commit_pc_i;
      assign commit_instr_s = commit_instr_i;
      assign next_pc_s = next_pc_i;
      assign sret_to_user_s = sret_to_user_i;
      assign jalr_target_valid_s = jalr_target_valid_i;
      assign jalr_target_s = jalr_target_i;
      assign commit_exception_s = commit_exception_i;
      assign commit_kill_s = commit_kill_i;
      assign wb_valid_s = wb_valid_i;
      assign wb_kill_s = wb_kill_i;
      assign wb_rd_s = wb_rd_i;
      assign wb_data_s = wb_data_i;
      assign trap_valid_s = trap_valid_i;
      assign trap_pc_s = trap_pc_i;
      assign trap_cause_s = trap_cause_i;
      assign trap_tval_s = trap_tval_i;
      assign csr_valid_s = csr_valid_i;
      assign csr_addr_s = csr_addr_i;
      assign csr_wdata_s = csr_wdata_i;
      assign priv_lvl_s = priv_lvl_i;
      assign satp_s = satp_i;
      assign trace_mem_mode_s = trace_mem_mode_i;
      assign mem_load_valid_s = mem_load_valid_i;
      assign mem_load_pc_s = mem_load_pc_i;
      assign mem_load_addr_s = mem_load_addr_i;
      assign mem_load_data_s = mem_load_data_i;
      assign mem_load_size_s = mem_load_size_i;
      assign trace_enable_retire_s = trace_enable_retire_i;
      assign trace_enable_branch_s = trace_enable_branch_i;
      assign trace_enable_jump_s = trace_enable_jump_i;
      assign trace_enable_syscall_s = trace_enable_syscall_i;
      assign trace_enable_trap_s = trace_enable_trap_i;
      assign trace_enable_context_s = trace_enable_context_i;
      assign trace_enable_marker_s = trace_enable_marker_i;
      assign trace_enable_drop_s = trace_enable_drop_i;
      assign trace_pc_filter_enable_s = trace_pc_filter_enable_i;
      assign trace_pc_start_s = trace_pc_start_i;
      assign trace_pc_end_s = trace_pc_end_i;
      assign trace_priv_filter_enable_s = trace_priv_filter_enable_i;
      assign trace_priv_mask_s = trace_priv_mask_i;
    end
  endgenerate

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cycle_q <= 64'd0;
      drop_count_q <= 64'd0;
      drop_defer_q <= 1'b0;
    end else begin
      cycle_q <= cycle_q + 64'd1;
      if (drop_output) begin
        drop_count_q <= dropped_this_cycle;
        drop_defer_q <= 1'b1;
      end else begin
        drop_count_q <= drop_count_q + dropped_this_cycle;
        drop_defer_q <= 1'b0;
      end
    end
  end

  arg_shadow #(
      .WB_PORTS(WB_PORTS)
  ) i_arg_shadow (
      .clk_i,
      .rst_ni,
      .wb_valid_i(wb_valid_s),
      .wb_kill_i(wb_kill_s),
      .wb_rd_i(wb_rd_s),
      .wb_data_i(wb_data_s),
      .args_o(args)
  );

  retire_tap i_retire_tap (
      .clk_i,
      .rst_ni,
      .cycle_i(sample_cycle),
      .commit_valid_i(commit_valid_s),
      .commit_pc_i(commit_pc_s),
      .commit_instr_i(commit_instr_s),
      .commit_exception_i(commit_exception_s),
      .commit_kill_i(commit_kill_s),
      .priv_lvl_i(priv_lvl_s),
      .satp_i(satp_s),
      .trace_valid_o(retire_valid),
      .trace_packet_o(retire_packet)
  );

  branch_tap i_branch_tap (
      .clk_i,
      .rst_ni,
      .cycle_i(sample_cycle),
      .commit_valid_i(commit_valid_s),
      .commit_pc_i(commit_pc_s),
      .commit_instr_i(commit_instr_s),
      .next_pc_i(next_pc_s),
      .jalr_target_valid_i(jalr_target_valid_s),
      .jalr_target_i(jalr_target_s),
      .commit_exception_i(commit_exception_s),
      .commit_kill_i(commit_kill_s),
      .priv_lvl_i(priv_lvl_s),
      .satp_i(satp_s),
      .trace_valid_o(branch_valid),
      .trace_packet_o(branch_packet)
  );

  syscall_tap i_syscall_tap (
      .clk_i,
      .rst_ni,
      .cycle_i(sample_cycle),
      .commit_valid_i(commit_valid_s),
      .commit_pc_i(commit_pc_s),
      .commit_instr_i(commit_instr_s),
      .next_pc_i(next_pc_s),
      .sret_to_user_i(sret_to_user_s),
      .commit_exception_i(commit_exception_s),
      .commit_kill_i(commit_kill_s),
      .trap_cause_i(trap_cause_s),
      .priv_lvl_i(priv_lvl_s),
      .satp_i(satp_s),
      .args_i(args),
      .trace_valid_o(syscall_valid),
      .trace_packet_o(syscall_packet)
  );

  arg_mem_tap #(
      .MAX_CAPTURE_BYTES(MAX_ARG_MEM_CAPTURE_BYTES),
      .MAX_WATCH_CYCLES(MAX_ARG_MEM_WATCH_CYCLES)
  ) i_arg_mem_tap (
      .clk_i,
      .rst_ni,
      .cycle_i(sample_cycle),
      .mem_mode_i(trace_mem_mode_s),
      .syscall_valid_i(filtered_syscall_valid),
      .syscall_packet_i(filtered_syscall_packet),
      .mem_load_valid_i(mem_load_valid_s),
      .mem_load_pc_i(mem_load_pc_s),
      .mem_load_addr_i(mem_load_addr_s),
      .mem_load_data_i(mem_load_data_s),
      .mem_load_size_i(mem_load_size_s),
      .priv_lvl_i(priv_lvl_s),
      .satp_i(satp_s),
      .trace_valid_o(arg_mem_valid),
      .trace_packet_o(arg_mem_packet)
  );

  trap_tap i_trap_tap (
      .clk_i,
      .rst_ni,
      .cycle_i(sample_cycle),
      .trap_valid_i(trap_valid_s),
      .trap_pc_i(trap_pc_s),
      .trap_cause_i(trap_cause_s),
      .trap_tval_i(trap_tval_s),
      .priv_lvl_i(priv_lvl_s),
      .satp_i(satp_s),
      .trace_valid_o(trap_valid),
      .trace_packet_o(trap_packet)
  );

  context_tap i_context_tap (
      .clk_i,
      .rst_ni,
      .cycle_i(sample_cycle),
      .commit_valid_i(commit_valid_s),
      .commit_pc_i(commit_pc_s),
      .commit_instr_i(commit_instr_s),
      .commit_exception_i(commit_exception_s),
      .commit_kill_i(commit_kill_s),
      .trap_valid_i(trap_valid_s),
      .trap_pc_i(trap_pc_s),
      .csr_valid_i(csr_valid_s),
      .csr_addr_i(csr_addr_s),
      .csr_wdata_i(csr_wdata_s),
      .priv_lvl_i(priv_lvl_s),
      .satp_i(satp_s),
      .trace_valid_o(context_valid),
      .trace_packet_o(context_packet)
  );

  trace_filter i_retire_filter (
      .trace_valid_i(retire_valid),
      .trace_packet_i(retire_packet),
      .enable_retire_i(trace_enable_retire_s),
      .enable_branch_i(trace_enable_branch_s),
      .enable_jump_i(trace_enable_jump_s),
      .enable_syscall_i(trace_enable_syscall_s),
      .enable_trap_i(trace_enable_trap_s),
      .enable_context_i(trace_enable_context_s),
      .enable_marker_i(trace_enable_marker_s),
      .enable_drop_i(trace_enable_drop_s),
      .pc_filter_enable_i(trace_pc_filter_enable_s),
      .pc_start_i(trace_pc_start_s),
      .pc_end_i(trace_pc_end_s),
      .priv_filter_enable_i(trace_priv_filter_enable_s),
      .priv_mask_i(trace_priv_mask_s),
      .trace_valid_o(filtered_retire_valid),
      .trace_packet_o(filtered_retire_packet)
  );

  trace_filter i_branch_filter (
      .trace_valid_i(branch_valid),
      .trace_packet_i(branch_packet),
      .enable_retire_i(trace_enable_retire_s),
      .enable_branch_i(trace_enable_branch_s),
      .enable_jump_i(trace_enable_jump_s),
      .enable_syscall_i(trace_enable_syscall_s),
      .enable_trap_i(trace_enable_trap_s),
      .enable_context_i(trace_enable_context_s),
      .enable_marker_i(trace_enable_marker_s),
      .enable_drop_i(trace_enable_drop_s),
      .pc_filter_enable_i(trace_pc_filter_enable_s),
      .pc_start_i(trace_pc_start_s),
      .pc_end_i(trace_pc_end_s),
      .priv_filter_enable_i(trace_priv_filter_enable_s),
      .priv_mask_i(trace_priv_mask_s),
      .trace_valid_o(filtered_branch_valid),
      .trace_packet_o(filtered_branch_packet)
  );

  trace_filter i_syscall_filter (
      .trace_valid_i(syscall_valid),
      .trace_packet_i(syscall_packet),
      .enable_retire_i(trace_enable_retire_s),
      .enable_branch_i(trace_enable_branch_s),
      .enable_jump_i(trace_enable_jump_s),
      .enable_syscall_i(trace_enable_syscall_s),
      .enable_trap_i(trace_enable_trap_s),
      .enable_context_i(trace_enable_context_s),
      .enable_marker_i(trace_enable_marker_s),
      .enable_drop_i(trace_enable_drop_s),
      .pc_filter_enable_i(trace_pc_filter_enable_s),
      .pc_start_i(trace_pc_start_s),
      .pc_end_i(trace_pc_end_s),
      .priv_filter_enable_i(trace_priv_filter_enable_s),
      .priv_mask_i(trace_priv_mask_s),
      .trace_valid_o(filtered_syscall_valid),
      .trace_packet_o(filtered_syscall_packet)
  );

  trace_filter i_arg_mem_filter (
      .trace_valid_i(arg_mem_valid),
      .trace_packet_i(arg_mem_packet),
      .enable_retire_i(trace_enable_retire_s),
      .enable_branch_i(trace_enable_branch_s),
      .enable_jump_i(trace_enable_jump_s),
      .enable_syscall_i(trace_enable_syscall_s),
      .enable_trap_i(trace_enable_trap_s),
      .enable_context_i(trace_enable_context_s),
      .enable_marker_i(trace_enable_marker_s),
      .enable_drop_i(trace_enable_drop_s),
      .pc_filter_enable_i(trace_pc_filter_enable_s),
      .pc_start_i(trace_pc_start_s),
      .pc_end_i(trace_pc_end_s),
      .priv_filter_enable_i(trace_priv_filter_enable_s),
      .priv_mask_i(trace_priv_mask_s),
      .trace_valid_o(filtered_arg_mem_valid),
      .trace_packet_o(filtered_arg_mem_packet)
  );

  trace_filter i_trap_filter (
      .trace_valid_i(trap_valid),
      .trace_packet_i(trap_packet),
      .enable_retire_i(trace_enable_retire_s),
      .enable_branch_i(trace_enable_branch_s),
      .enable_jump_i(trace_enable_jump_s),
      .enable_syscall_i(trace_enable_syscall_s),
      .enable_trap_i(trace_enable_trap_s),
      .enable_context_i(trace_enable_context_s),
      .enable_marker_i(trace_enable_marker_s),
      .enable_drop_i(trace_enable_drop_s),
      .pc_filter_enable_i(trace_pc_filter_enable_s),
      .pc_start_i(trace_pc_start_s),
      .pc_end_i(trace_pc_end_s),
      .priv_filter_enable_i(trace_priv_filter_enable_s),
      .priv_mask_i(trace_priv_mask_s),
      .trace_valid_o(filtered_trap_valid),
      .trace_packet_o(filtered_trap_packet)
  );

  trace_filter i_context_filter (
      .trace_valid_i(context_valid),
      .trace_packet_i(context_packet),
      .enable_retire_i(trace_enable_retire_s),
      .enable_branch_i(trace_enable_branch_s),
      .enable_jump_i(trace_enable_jump_s),
      .enable_syscall_i(trace_enable_syscall_s),
      .enable_trap_i(trace_enable_trap_s),
      .enable_context_i(trace_enable_context_s),
      .enable_marker_i(trace_enable_marker_s),
      .enable_drop_i(trace_enable_drop_s),
      .pc_filter_enable_i(trace_pc_filter_enable_s),
      .pc_start_i(trace_pc_start_s),
      .pc_end_i(trace_pc_end_s),
      .priv_filter_enable_i(trace_priv_filter_enable_s),
      .priv_mask_i(trace_priv_mask_s),
      .trace_valid_o(filtered_context_valid),
      .trace_packet_o(filtered_context_packet)
  );

  always_comb begin
    source_valid[0]  = filtered_trap_valid;
    source_valid[1]  = filtered_syscall_valid;
    source_valid[2]  = filtered_arg_mem_valid;
    source_valid[3]  = filtered_context_valid;
    source_valid[4]  = filtered_branch_valid;
    source_valid[5]  = filtered_retire_valid;
    source_packet[0] = filtered_trap_packet;
    source_packet[1] = filtered_syscall_packet;
    source_packet[2] = filtered_arg_mem_packet;
    source_packet[3] = filtered_context_packet;
    source_packet[4] = filtered_branch_packet;
    source_packet[5] = filtered_retire_packet;
    drop_packet = trace_null_packet();
    drop_packet.valid = drop_count_q != 64'd0;
    drop_packet.evt   = drop_count_q != 64'd0 ? EVT_DROP : EVT_NONE;
    drop_packet.cycle = cycle_q;
    drop_packet.value = drop_count_q;

    trace_valid_o  = 1'b0;
    trace_packet_o = trace_null_packet();
    current_selected_idx = NUM_SOURCES;
    drop_output = 1'b0;

    if (drop_count_q != 64'd0 && !drop_defer_q) begin
      trace_valid_o  = trace_enable_drop_s;
      trace_packet_o = trace_enable_drop_s ? drop_packet : trace_null_packet();
      drop_output    = 1'b1;
    end else if (pending_count_q != '0) begin
      trace_valid_o  = 1'b1;
      trace_packet_o = pending_q[0];
    end else begin
      for (int unsigned i = 0; i < NUM_SOURCES; i++) begin
        if (!trace_valid_o && source_valid[i]) begin
          trace_valid_o = 1'b1;
          trace_packet_o = source_packet[i];
          current_selected_idx = i;
        end
      end
    end
  end

  always_comb begin
    pending_count_n = '0;
    dropped_this_cycle = 64'd0;
    for (int unsigned i = 0; i < EVENT_QUEUE_DEPTH; i++) begin
      pending_n[i] = trace_null_packet();
    end

    if (pending_count_q != '0) begin
      if (drop_output) begin
        for (int unsigned i = 0; i < EVENT_QUEUE_DEPTH; i++) begin
          if (i < pending_count_q) begin
            pending_n[pending_count_n] = pending_q[i];
            pending_count_n = pending_count_n + 1'b1;
          end
        end
      end else begin
        for (int unsigned i = 1; i < EVENT_QUEUE_DEPTH; i++) begin
          if (i < pending_count_q) begin
            pending_n[pending_count_n] = pending_q[i];
            pending_count_n = pending_count_n + 1'b1;
          end
        end
      end
    end

    for (int unsigned i = 0; i < NUM_SOURCES; i++) begin
      if (source_valid[i] && !(pending_count_q == '0 && current_selected_idx == i)) begin
        if (pending_count_n < EVENT_QUEUE_DEPTH) begin
          pending_n[pending_count_n] = source_packet[i];
          pending_count_n = pending_count_n + 1'b1;
        end else begin
          dropped_this_cycle = dropped_this_cycle + 64'd1;
        end
      end
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      pending_count_q <= '0;
      for (int unsigned i = 0; i < EVENT_QUEUE_DEPTH; i++) begin
        pending_q[i] <= trace_null_packet();
      end
    end else begin
      pending_count_q <= pending_count_n;
      for (int unsigned i = 0; i < EVENT_QUEUE_DEPTH; i++) begin
        pending_q[i] <= pending_n[i];
      end
    end
  end

endmodule
