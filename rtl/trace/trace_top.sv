module trace_top
  import trace_pkg::*;
#(
    parameter int WB_PORTS = 1,
    parameter int EVENT_QUEUE_DEPTH = 8
) (
    input  logic                      clk_i,
    input  logic                      rst_ni,

    input  logic                      commit_valid_i,
    input  logic [63:0]               commit_pc_i,
    input  logic [31:0]               commit_instr_i,
    input  logic [63:0]               next_pc_i,
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

  logic [63:0] cycle_q;
  logic [7:0][63:0] args;

  logic retire_valid;
  logic branch_valid;
  logic syscall_valid;
  logic trap_valid;
  logic context_valid;

  trace_packet_t retire_packet;
  trace_packet_t branch_packet;
  trace_packet_t syscall_packet;
  trace_packet_t trap_packet;
  trace_packet_t context_packet;

  localparam int NUM_SOURCES = 5;
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
      .wb_valid_i,
      .wb_kill_i,
      .wb_rd_i,
      .wb_data_i,
      .args_o(args)
  );

  retire_tap i_retire_tap (
      .clk_i,
      .rst_ni,
      .cycle_i(cycle_q),
      .commit_valid_i,
      .commit_pc_i,
      .commit_instr_i,
      .commit_exception_i,
      .commit_kill_i,
      .priv_lvl_i,
      .satp_i,
      .trace_valid_o(retire_valid),
      .trace_packet_o(retire_packet)
  );

  branch_tap i_branch_tap (
      .clk_i,
      .rst_ni,
      .cycle_i(cycle_q),
      .commit_valid_i,
      .commit_pc_i,
      .commit_instr_i,
      .next_pc_i,
      .jalr_target_valid_i,
      .jalr_target_i,
      .commit_exception_i,
      .commit_kill_i,
      .priv_lvl_i,
      .satp_i,
      .trace_valid_o(branch_valid),
      .trace_packet_o(branch_packet)
  );

  syscall_tap i_syscall_tap (
      .clk_i,
      .rst_ni,
      .cycle_i(cycle_q),
      .commit_valid_i,
      .commit_pc_i,
      .commit_instr_i,
      .commit_exception_i,
      .commit_kill_i,
      .priv_lvl_i,
      .satp_i,
      .args_i(args),
      .trace_valid_o(syscall_valid),
      .trace_packet_o(syscall_packet)
  );

  trap_tap i_trap_tap (
      .clk_i,
      .rst_ni,
      .cycle_i(cycle_q),
      .trap_valid_i,
      .trap_pc_i,
      .trap_cause_i,
      .trap_tval_i,
      .priv_lvl_i,
      .satp_i,
      .trace_valid_o(trap_valid),
      .trace_packet_o(trap_packet)
  );

  context_tap i_context_tap (
      .clk_i,
      .rst_ni,
      .cycle_i(cycle_q),
      .commit_valid_i,
      .commit_pc_i,
      .commit_instr_i,
      .commit_exception_i,
      .commit_kill_i,
      .trap_valid_i,
      .trap_pc_i,
      .csr_valid_i,
      .csr_addr_i,
      .csr_wdata_i,
      .priv_lvl_i,
      .satp_i,
      .trace_valid_o(context_valid),
      .trace_packet_o(context_packet)
  );

  always_comb begin
    source_valid[0]  = trap_valid;
    source_valid[1]  = syscall_valid;
    source_valid[2]  = context_valid;
    source_valid[3]  = branch_valid;
    source_valid[4]  = retire_valid;
    source_packet[0] = trap_packet;
    source_packet[1] = syscall_packet;
    source_packet[2] = context_packet;
    source_packet[3] = branch_packet;
    source_packet[4] = retire_packet;
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
      trace_valid_o  = 1'b1;
      trace_packet_o = drop_packet;
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
