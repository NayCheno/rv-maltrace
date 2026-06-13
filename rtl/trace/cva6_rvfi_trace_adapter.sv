`timescale 1ns/1ps

module cva6_rvfi_trace_adapter
  import trace_pkg::*;
#(
    parameter int COMMIT_PORTS = 1,
    parameter int XLEN = 64,
    parameter int ILEN = 32,
    parameter int VLEN = 64,
    parameter int EVENT_QUEUE_DEPTH = 16,
    parameter int PIPELINE_INPUTS = 1,
    parameter bit RELAX_SRET_TO_USER_CHECK = 1'b0,
    parameter logic [63:0] MARKER_SYSCALL_NR = 64'd1023,
    parameter bit ENABLE_USER_POINTER_SNAPSHOT = 1'b0,
    parameter int MAX_POINTER_SNAPSHOT_BYTES = 64,
    parameter int MAX_POINTER_WATCH_CYCLES = 512,
    parameter logic [63:0] USER_POINTER_MAX = 64'h0000_4000_0000_0000
) (
    input  logic                                clk_i,
    input  logic                                rst_ni,

    input  logic [COMMIT_PORTS-1:0]             rvfi_valid_i,
    input  logic [COMMIT_PORTS-1:0][ILEN-1:0]   rvfi_insn_i,
    input  logic [COMMIT_PORTS-1:0]             rvfi_trap_i,
    input  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_cause_i,
    input  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_tval_i,
    input  logic [COMMIT_PORTS-1:0][1:0]        rvfi_mode_i,
    input  logic [COMMIT_PORTS-1:0]             rvfi_compressed_i,
    input  logic [COMMIT_PORTS-1:0][VLEN-1:0]   rvfi_pc_rdata_i,
    input  logic [COMMIT_PORTS-1:0][VLEN-1:0]   rvfi_pc_wdata_i,
    input  logic [COMMIT_PORTS-1:0]             rvfi_sret_to_user_i,
    input  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_rs1_rdata_i,
    input  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_rs2_rdata_i,
    input  logic [COMMIT_PORTS-1:0][4:0]        rvfi_rd_addr_i,
    input  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_rd_wdata_i,
    input  trace_mem_mode_e                      trace_mem_mode_i,
    input  logic [COMMIT_PORTS-1:0][VLEN-1:0]   rvfi_mem_addr_i,
    input  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_mem_rdata_i,
    input  logic [COMMIT_PORTS-1:0][(XLEN/8)-1:0] rvfi_mem_rmask_i,

    input  logic                                csr_valid_i,
    input  logic [11:0]                         csr_addr_i,
    input  logic [XLEN-1:0]                     csr_wdata_i,
    input  logic [XLEN-1:0]                     satp_i,
    input  logic                                trace_enable_retire_i,
    input  logic                                trace_enable_branch_i,
    input  logic                                trace_enable_jump_i,
    input  logic                                trace_enable_syscall_i,
    input  logic                                trace_enable_trap_i,
    input  logic                                trace_enable_context_i,
    input  logic                                trace_enable_marker_i,
    input  logic                                trace_enable_drop_i,
    input  logic                                trace_pc_filter_enable_i,
    input  logic [63:0]                         trace_pc_start_i,
    input  logic [63:0]                         trace_pc_end_i,

    output logic                                trace_valid_o,
    output trace_packet_t                       trace_packet_o
);

  localparam logic [6:0] OPCODE_BRANCH = 7'b1100011;
  localparam logic [6:0] OPCODE_JAL    = 7'b1101111;
  localparam logic [6:0] OPCODE_JALR   = 7'b1100111;
  localparam logic [31:0] INSTR_ECALL  = 32'h0000_0073;
  localparam logic [31:0] INSTR_SRET   = 32'h1020_0073;
  localparam logic [63:0] CAUSE_U_ECALL = 64'd8;
  localparam logic [63:0] MARKER_TAG_MASK = 64'h0000_0000_f000_0000;
  localparam logic [63:0] MARKER_BEGIN_TAG = 64'h0000_0000_b000_0000;
  localparam logic [63:0] MARKER_END_TAG = 64'h0000_0000_e000_0000;
  localparam int INTERNAL_EVENT_QUEUE_DEPTH = EVENT_QUEUE_DEPTH + 1;
  localparam int QUEUE_COUNT_WIDTH = $clog2(INTERNAL_EVENT_QUEUE_DEPTH + 1);
  localparam int MEM_LANES = XLEN / 8;
  localparam logic [63:0] MAX_POINTER_SNAPSHOT_BYTES_64 = MAX_POINTER_SNAPSHOT_BYTES;
  localparam logic [63:0] MAX_POINTER_WATCH_CYCLES_64 = MAX_POINTER_WATCH_CYCLES;
  localparam logic [63:0] SYS_OPENAT = 64'd56;
  localparam logic [63:0] SYS_WRITE  = 64'd64;
  localparam logic [63:0] SYS_EXECVE = 64'd221;

  logic [7:0][63:0] args_q;
  logic [7:0][63:0] args_n;
  logic [COMMIT_PORTS-1:0][7:0][63:0] args_at_port;
  logic pointer_watch_active_q;
  logic pointer_watch_active_n;
  logic [63:0] pointer_watch_base_q;
  logic [63:0] pointer_watch_base_n;
  logic [63:0] pointer_watch_limit_q;
  logic [63:0] pointer_watch_limit_n;
  logic [63:0] pointer_watch_syscall_id_q;
  logic [63:0] pointer_watch_syscall_id_n;
  logic [2:0] pointer_watch_arg_index_q;
  logic [2:0] pointer_watch_arg_index_n;
  logic [63:0] pointer_watch_age_q;
  logic [63:0] pointer_watch_age_n;
  logic [1:0] priv_shadow_q;
  logic syscall_outstanding_q;
  logic syscall_outstanding_n;
  logic [63:0] next_syscall_id_q;
  logic [63:0] next_syscall_id_n;
  logic [63:0] active_syscall_id_q;
  logic [63:0] active_syscall_id_n;
  logic [63:0] syscall_entry_cycle_q;
  logic [63:0] syscall_entry_cycle_n;

  int unsigned candidate_count;
  int unsigned accepted_candidate_count;

  trace_packet_t pending_q [INTERNAL_EVENT_QUEUE_DEPTH];
  logic [QUEUE_COUNT_WIDTH-1:0] pending_count_q;
  logic [QUEUE_COUNT_WIDTH-1:0] pending_count_after_pop;
  logic [QUEUE_COUNT_WIDTH-1:0] pending_count_next;
  logic                         pop_pending;
  logic                         enqueue_candidate;

  logic [63:0] cycle_q;
  logic [63:0] sample_cycle;
  logic [63:0] drop_count_q;
  logic [63:0] dropped_this_cycle;
  logic        drop_defer_q;
  logic        drop_output;
  logic [1:0]  priv_shadow_n;
  trace_packet_t drop_packet;

  logic [COMMIT_PORTS-1:0]             rvfi_valid_s;
  logic [COMMIT_PORTS-1:0][ILEN-1:0]   rvfi_insn_s;
  logic [COMMIT_PORTS-1:0]             rvfi_trap_s;
  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_cause_s;
  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_tval_s;
  logic [COMMIT_PORTS-1:0][1:0]        rvfi_mode_s;
  logic [COMMIT_PORTS-1:0]             rvfi_compressed_s;
  logic [COMMIT_PORTS-1:0][VLEN-1:0]   rvfi_pc_rdata_s;
  logic [COMMIT_PORTS-1:0][VLEN-1:0]   rvfi_pc_wdata_s;
  logic [COMMIT_PORTS-1:0]             rvfi_sret_to_user_s;
  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_rs1_rdata_s;
  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_rs2_rdata_s;
  logic [COMMIT_PORTS-1:0][4:0]        rvfi_rd_addr_s;
  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_rd_wdata_s;
  trace_mem_mode_e                      trace_mem_mode_s;
  logic [COMMIT_PORTS-1:0][VLEN-1:0]   rvfi_mem_addr_s;
  logic [COMMIT_PORTS-1:0][XLEN-1:0]   rvfi_mem_rdata_s;
  logic [COMMIT_PORTS-1:0][MEM_LANES-1:0] rvfi_mem_rmask_s;
  logic                                csr_valid_s;
  logic [11:0]                         csr_addr_s;
  logic [XLEN-1:0]                     csr_wdata_s;
  logic [XLEN-1:0]                     satp_s;
  logic [COMMIT_PORTS-1:0]             pointer_capture_valid;
  logic [COMMIT_PORTS-1:0]             pointer_capture_last;
  trace_packet_t                       pointer_capture_packet [COMMIT_PORTS];

  generate
    if (PIPELINE_INPUTS != 0) begin : g_input_pipeline
      always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
          sample_cycle <= 64'd0;
          rvfi_valid_s <= '0;
          rvfi_insn_s <= '0;
          rvfi_trap_s <= '0;
          rvfi_cause_s <= '0;
          rvfi_tval_s <= '0;
          rvfi_mode_s <= '0;
          rvfi_compressed_s <= '0;
          rvfi_pc_rdata_s <= '0;
          rvfi_pc_wdata_s <= '0;
          rvfi_sret_to_user_s <= '0;
          rvfi_rs1_rdata_s <= '0;
          rvfi_rs2_rdata_s <= '0;
          rvfi_rd_addr_s <= '0;
          rvfi_rd_wdata_s <= '0;
          trace_mem_mode_s <= TRACE_MEM_MODE_NONE;
          rvfi_mem_addr_s <= '0;
          rvfi_mem_rdata_s <= '0;
          rvfi_mem_rmask_s <= '0;
          csr_valid_s <= 1'b0;
          csr_addr_s <= 12'd0;
          csr_wdata_s <= '0;
          satp_s <= '0;
        end else begin
          sample_cycle <= cycle_q;
          rvfi_valid_s <= rvfi_valid_i;
          rvfi_insn_s <= rvfi_insn_i;
          rvfi_trap_s <= rvfi_trap_i;
          rvfi_cause_s <= rvfi_cause_i;
          rvfi_tval_s <= rvfi_tval_i;
          rvfi_mode_s <= rvfi_mode_i;
          rvfi_compressed_s <= rvfi_compressed_i;
          rvfi_pc_rdata_s <= rvfi_pc_rdata_i;
          rvfi_pc_wdata_s <= rvfi_pc_wdata_i;
          rvfi_sret_to_user_s <= rvfi_sret_to_user_i;
          rvfi_rs1_rdata_s <= rvfi_rs1_rdata_i;
          rvfi_rs2_rdata_s <= rvfi_rs2_rdata_i;
          rvfi_rd_addr_s <= rvfi_rd_addr_i;
          rvfi_rd_wdata_s <= rvfi_rd_wdata_i;
          trace_mem_mode_s <= trace_mem_mode_i;
          rvfi_mem_addr_s <= rvfi_mem_addr_i;
          rvfi_mem_rdata_s <= rvfi_mem_rdata_i;
          rvfi_mem_rmask_s <= rvfi_mem_rmask_i;
          csr_valid_s <= csr_valid_i;
          csr_addr_s <= csr_addr_i;
          csr_wdata_s <= csr_wdata_i;
          satp_s <= satp_i;
        end
      end
    end else begin : g_no_input_pipeline
      assign sample_cycle = cycle_q;
      assign rvfi_valid_s = rvfi_valid_i;
      assign rvfi_insn_s = rvfi_insn_i;
      assign rvfi_trap_s = rvfi_trap_i;
      assign rvfi_cause_s = rvfi_cause_i;
      assign rvfi_tval_s = rvfi_tval_i;
      assign rvfi_mode_s = rvfi_mode_i;
      assign rvfi_compressed_s = rvfi_compressed_i;
      assign rvfi_pc_rdata_s = rvfi_pc_rdata_i;
      assign rvfi_pc_wdata_s = rvfi_pc_wdata_i;
      assign rvfi_sret_to_user_s = rvfi_sret_to_user_i;
      assign rvfi_rs1_rdata_s = rvfi_rs1_rdata_i;
      assign rvfi_rs2_rdata_s = rvfi_rs2_rdata_i;
      assign rvfi_rd_addr_s = rvfi_rd_addr_i;
      assign rvfi_rd_wdata_s = rvfi_rd_wdata_i;
      assign trace_mem_mode_s = trace_mem_mode_i;
      assign rvfi_mem_addr_s = rvfi_mem_addr_i;
      assign rvfi_mem_rdata_s = rvfi_mem_rdata_i;
      assign rvfi_mem_rmask_s = rvfi_mem_rmask_i;
      assign csr_valid_s = csr_valid_i;
      assign csr_addr_s = csr_addr_i;
      assign csr_wdata_s = csr_wdata_i;
      assign satp_s = satp_i;
    end
  endgenerate

  function automatic logic [63:0] xlen_to_64(input logic [XLEN-1:0] value);
    xlen_to_64 = '0;
    xlen_to_64[XLEN-1:0] = value;
  endfunction

  function automatic logic [63:0] vlen_to_64(input logic [VLEN-1:0] value);
    vlen_to_64 = '0;
    vlen_to_64[VLEN-1:0] = value;
  endfunction

  function automatic logic [31:0] insn_to_32(input logic [ILEN-1:0] value);
    insn_to_32 = '0;
    if (ILEN >= 32) begin
      insn_to_32 = value[31:0];
    end else begin
      insn_to_32[ILEN-1:0] = value;
    end
  endfunction

  function automatic logic branch_condition(
      input logic [2:0] funct3,
      input logic [XLEN-1:0] lhs,
      input logic [XLEN-1:0] rhs
  );
    unique case (funct3)
      3'b000:  branch_condition = lhs == rhs;
      3'b001:  branch_condition = lhs != rhs;
      3'b100:  branch_condition = $signed(lhs) < $signed(rhs);
      3'b101:  branch_condition = $signed(lhs) >= $signed(rhs);
      3'b110:  branch_condition = lhs < rhs;
      3'b111:  branch_condition = lhs >= rhs;
      default: branch_condition = 1'b0;
    endcase
  endfunction

  function automatic logic [63:0] b_imm(input logic [31:0] instr);
    b_imm = {{51{instr[31]}}, instr[31], instr[7], instr[30:25], instr[11:8], 1'b0};
  endfunction

  function automatic logic [63:0] j_imm(input logic [31:0] instr);
    j_imm = {{43{instr[31]}}, instr[31], instr[19:12], instr[20], instr[30:21], 1'b0};
  endfunction

  function automatic logic [63:0] i_imm(input logic [31:0] instr);
    i_imm = {{52{instr[31]}}, instr[31:20]};
  endfunction

  function automatic logic [63:0] cj_imm(input logic [31:0] instr);
    cj_imm = {
      {52{instr[12]}},
      instr[12],
      instr[8],
      instr[10:9],
      instr[6],
      instr[7],
      instr[2],
      instr[11],
      instr[5:3],
      1'b0
    };
  endfunction

  function automatic logic [63:0] cb_imm(input logic [31:0] instr);
    cb_imm = {
      {55{instr[12]}},
      instr[12],
      instr[6:5],
      instr[2],
      instr[11:10],
      instr[4:3],
      1'b0
    };
  endfunction

  function automatic logic is_c_branch(input logic [31:0] instr);
    is_c_branch = instr[1:0] == 2'b01 && (instr[15:13] == 3'b110 || instr[15:13] == 3'b111);
  endfunction

  function automatic logic is_c_jump(input logic [31:0] instr);
    is_c_jump = instr[1:0] == 2'b01 &&
                (instr[15:13] == 3'b101 || (XLEN == 32 && instr[15:13] == 3'b001));
  endfunction

  function automatic logic is_c_jr_jalr(input logic [31:0] instr);
    is_c_jr_jalr = instr[1:0] == 2'b10 && instr[15:13] == 3'b100 &&
                   instr[6:2] == 5'd0 && instr[11:7] != 5'd0;
  endfunction

  function automatic logic c_branch_taken(input logic [31:0] instr, input logic [XLEN-1:0] rs1);
    c_branch_taken = instr[15:13] == 3'b110 ? rs1 == '0 : rs1 != '0;
  endfunction

  function automatic trace_packet_t base_packet(
      input logic [63:0] cycle,
      input logic [63:0] pc,
      input logic [31:0] instr,
      input logic [1:0] priv,
      input logic [63:0] satp
  );
    base_packet = trace_null_packet();
    base_packet.valid = 1'b1;
    base_packet.cycle = cycle;
    base_packet.pc    = pc;
    base_packet.instr = instr;
    base_packet.priv  = priv;
    base_packet.satp  = satp;
  endfunction

  function automatic logic trace_pc_pass(input logic [63:0] pc);
    trace_pc_pass = !trace_pc_filter_enable_i ||
                    (pc >= trace_pc_start_i && pc < trace_pc_end_i);
  endfunction

  function automatic logic [63:0] bounded_pointer_len(input logic [63:0] requested_len);
    if (requested_len == 64'd0 || requested_len > MAX_POINTER_SNAPSHOT_BYTES_64) begin
      bounded_pointer_len = MAX_POINTER_SNAPSHOT_BYTES_64;
    end else begin
      bounded_pointer_len = requested_len;
    end
  endfunction

  function automatic logic user_pointer_range_ok(input logic [63:0] base, input logic [63:0] length);
    logic [63:0] limit;
    begin
      limit = base + length;
      user_pointer_range_ok = ENABLE_USER_POINTER_SNAPSHOT &&
                              trace_mem_mode_s != TRACE_MEM_MODE_NONE &&
                              base != 64'd0 &&
                              length != 64'd0 &&
                              limit > base &&
                              base < USER_POINTER_MAX &&
                              limit <= USER_POINTER_MAX;
    end
  endfunction

  function automatic logic [3:0] rmask_capture_size(input logic [MEM_LANES-1:0] mask);
    logic [3:0] count;
    begin
      count = 4'd0;
      for (int unsigned i = 0; i < MEM_LANES; i++) begin
        if (mask[i] && count < 4'd8) begin
          count = count + 4'd1;
        end
      end
      rmask_capture_size = count;
    end
  endfunction

  function automatic logic [63:0] mask_data_to_size(input logic [63:0] data, input logic [3:0] size);
    mask_data_to_size = 64'd0;
    for (int unsigned i = 0; i < 8; i++) begin
      if (i < size) begin
        mask_data_to_size[i*8+:8] = data[i*8+:8];
      end
    end
  endfunction

  function automatic logic data_has_zero_byte(input logic [63:0] data, input logic [3:0] size);
    data_has_zero_byte = 1'b0;
    for (int unsigned i = 0; i < 8; i++) begin
      if (i < size && data[i*8+:8] == 8'd0) begin
        data_has_zero_byte = 1'b1;
      end
    end
  endfunction

  task automatic offer_candidate(
      input trace_packet_t packet,
      input logic [QUEUE_COUNT_WIDTH-1:0] base_count,
      inout int unsigned append_count
  );
    int unsigned write_index;

    if (packet.valid) begin
      write_index = base_count + append_count;
      if (write_index < INTERNAL_EVENT_QUEUE_DEPTH) begin
        pending_q[write_index] <= packet;
      end
      append_count++;
    end
  endtask

  always_comb begin
    args_n = args_q;
    for (int unsigned port = 0; port < COMMIT_PORTS; port++) begin
      args_at_port[port] = args_n;
      if ((rvfi_valid_s[port] || rvfi_trap_s[port]) && !rvfi_trap_s[port] &&
          rvfi_rd_addr_s[port] inside {[5'd10 : 5'd17]}) begin
        args_n[rvfi_rd_addr_s[port] - 5'd10] = xlen_to_64(rvfi_rd_wdata_s[port]);
      end
    end
  end

  always_comb begin
    for (int unsigned port = 0; port < COMMIT_PORTS; port++) begin
      logic [63:0] mem_addr64;
      logic [63:0] mem_data64;
      logic [63:0] remaining;
      logic [3:0]  capture_size;

      mem_addr64 = vlen_to_64(rvfi_mem_addr_s[port]);
      mem_data64 = xlen_to_64(rvfi_mem_rdata_s[port]);
      remaining = pointer_watch_limit_q - mem_addr64;
      capture_size = rmask_capture_size(rvfi_mem_rmask_s[port]);
      if (capture_size != 4'd0 && remaining < {60'd0, capture_size}) begin
        capture_size = remaining[3:0];
      end

      pointer_capture_valid[port] = ENABLE_USER_POINTER_SNAPSHOT &&
                                    trace_mem_mode_s != TRACE_MEM_MODE_NONE &&
                                    pointer_watch_active_q &&
                                    rvfi_valid_s[port] &&
                                    !rvfi_trap_s[port] &&
                                    rvfi_mode_s[port] == TRACE_PRIV_S &&
                                    rvfi_mem_rmask_s[port] != '0 &&
                                    capture_size != 4'd0 &&
                                    mem_addr64 >= pointer_watch_base_q &&
                                    mem_addr64 < pointer_watch_limit_q;
      pointer_capture_last[port] = pointer_capture_valid[port] &&
                                   (data_has_zero_byte(mask_data_to_size(mem_data64, capture_size), capture_size) ||
                                    (mem_addr64 + {60'd0, capture_size}) >= pointer_watch_limit_q);
      pointer_capture_packet[port] = base_packet(
          sample_cycle,
          vlen_to_64(rvfi_pc_rdata_s[port]),
          insn_to_32(rvfi_insn_s[port]),
          rvfi_mode_s[port],
          xlen_to_64(satp_s)
      );
      pointer_capture_packet[port].evt = pointer_capture_valid[port] ? EVT_ARG_MEM : EVT_NONE;
      pointer_capture_packet[port].valid = pointer_capture_valid[port];
      pointer_capture_packet[port].syscall_id = pointer_watch_syscall_id_q;
      pointer_capture_packet[port].arg_index = pointer_watch_arg_index_q;
      pointer_capture_packet[port].mem_base = pointer_watch_base_q;
      pointer_capture_packet[port].mem_addr = mem_addr64;
      pointer_capture_packet[port].mem_data = trace_mem_mode_s == TRACE_MEM_MODE_RANGE ?
                                              mask_data_to_size(mem_data64, capture_size) : 64'd0;
      pointer_capture_packet[port].mem_size = capture_size;
      pointer_capture_packet[port].mem_last = pointer_capture_last[port];
    end
  end

  always_comb begin
    trace_packet_t packet;
    logic [1:0] priv_view;
    logic syscall_outstanding_view;
    logic [63:0] next_syscall_id_view;
    logic [63:0] active_syscall_id_view;
    logic [63:0] syscall_entry_cycle_view;
    logic pointer_watch_active_view;
    logic [63:0] pointer_watch_base_view;
    logic [63:0] pointer_watch_limit_view;
    logic [63:0] pointer_watch_syscall_id_view;
    logic [2:0] pointer_watch_arg_index_view;
    logic [63:0] pointer_watch_age_view;

    candidate_count = 0;
    priv_view = priv_shadow_q;
    syscall_outstanding_view = syscall_outstanding_q;
    next_syscall_id_view = next_syscall_id_q;
    active_syscall_id_view = active_syscall_id_q;
    syscall_entry_cycle_view = syscall_entry_cycle_q;
    pointer_watch_active_view = pointer_watch_active_q;
    pointer_watch_base_view = pointer_watch_base_q;
    pointer_watch_limit_view = pointer_watch_limit_q;
    pointer_watch_syscall_id_view = pointer_watch_syscall_id_q;
    pointer_watch_arg_index_view = pointer_watch_arg_index_q;
    pointer_watch_age_view = pointer_watch_active_q ? pointer_watch_age_q + 64'd1 : 64'd0;
    if (pointer_watch_active_q && MAX_POINTER_WATCH_CYCLES_64 != 64'd0 &&
        pointer_watch_age_q >= MAX_POINTER_WATCH_CYCLES_64) begin
      pointer_watch_active_view = 1'b0;
      pointer_watch_age_view = 64'd0;
    end

    for (int unsigned port = 0; port < COMMIT_PORTS; port++) begin
      logic        event_valid;
      logic [31:0] instr;
      logic [63:0] pc;
      logic [63:0] satp64;
      logic [63:0] fallthrough_pc;
      logic        compressed;
      logic        branch_evt;
      logic        jump_evt;
      logic        branch_taken;
      logic [63:0] branch_target;
      logic [63:0] jump_target;
      logic        syscall_entry_evt;
      logic        syscall_ret_evt;
      logic        marker_evt;
      logic [63:0] marker_tag;
      logic        pointer_entry_supported;
      logic [63:0] pointer_entry_base;
      logic [63:0] pointer_entry_len;
      logic [2:0]  pointer_entry_arg_index;
      logic        pc_pass;

      event_valid = rvfi_valid_s[port] || rvfi_trap_s[port];
      instr       = insn_to_32(rvfi_insn_s[port]);
      pc          = vlen_to_64(rvfi_pc_rdata_s[port]);
      pc_pass     = trace_pc_pass(pc);
      satp64      = xlen_to_64(satp_s);
      compressed  = rvfi_compressed_s[port] || instr[1:0] != 2'b11;
      fallthrough_pc = pc + (compressed ? 64'd2 : 64'd4);
      branch_evt = (!compressed && instr[6:0] == OPCODE_BRANCH) || (compressed && is_c_branch(instr));
      jump_evt = (!compressed && (instr[6:0] == OPCODE_JAL || instr[6:0] == OPCODE_JALR)) ||
                 (compressed && (is_c_jump(instr) || is_c_jr_jalr(instr)));
      branch_taken = compressed ? c_branch_taken(instr, rvfi_rs1_rdata_s[port]) :
                     branch_condition(instr[14:12], rvfi_rs1_rdata_s[port], rvfi_rs2_rdata_s[port]);
      branch_target = compressed ? pc + cb_imm(instr) : pc + b_imm(instr);
      jump_target = compressed && is_c_jump(instr) ? pc + cj_imm(instr) :
                    (!compressed && instr[6:0] == OPCODE_JAL) ? pc + j_imm(instr) :
                    (xlen_to_64(rvfi_rs1_rdata_s[port]) +
                     (compressed ? 64'd0 : i_imm(instr))) & ~64'd1;
      syscall_entry_evt = event_valid && rvfi_trap_s[port] &&
                           instr == INSTR_ECALL &&
                           rvfi_mode_s[port] == TRACE_PRIV_U &&
                           xlen_to_64(rvfi_cause_s[port]) == CAUSE_U_ECALL;
      marker_tag = args_at_port[port][0] & MARKER_TAG_MASK;
      marker_evt = syscall_entry_evt && trace_enable_marker_i &&
                   args_at_port[port][7] == MARKER_SYSCALL_NR &&
                   (marker_tag == MARKER_BEGIN_TAG || marker_tag == MARKER_END_TAG);
      // The FPGA RVFI export path does not currently provide explicit
      // sret-to-user metadata. When opted in, treat an S-mode SRET with an
      // outstanding user syscall as the return edge.
      syscall_ret_evt = event_valid && !rvfi_trap_s[port] && instr == INSTR_SRET &&
                          rvfi_mode_s[port] == TRACE_PRIV_S &&
                          (rvfi_sret_to_user_s[port] || RELAX_SRET_TO_USER_CHECK) &&
                          syscall_outstanding_view;
      pointer_entry_supported = 1'b0;
      pointer_entry_base = 64'd0;
      pointer_entry_len = MAX_POINTER_SNAPSHOT_BYTES_64;
      pointer_entry_arg_index = 3'd0;
      unique case (args_at_port[port][7])
        SYS_OPENAT: begin
          pointer_entry_supported = args_at_port[port][1] != 64'd0;
          pointer_entry_base = args_at_port[port][1];
          pointer_entry_arg_index = 3'd1;
        end
        SYS_WRITE: begin
          pointer_entry_supported = args_at_port[port][1] != 64'd0;
          pointer_entry_base = args_at_port[port][1];
          pointer_entry_len = bounded_pointer_len(args_at_port[port][2]);
          pointer_entry_arg_index = 3'd1;
        end
        SYS_EXECVE: begin
          pointer_entry_supported = args_at_port[port][0] != 64'd0;
          pointer_entry_base = args_at_port[port][0];
          pointer_entry_arg_index = 3'd0;
        end
        default: begin
        end
      endcase

      if (event_valid && rvfi_trap_s[port] && trace_enable_trap_i && pc_pass) begin
        packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
        packet.evt   = EVT_TRAP;
        packet.cause = xlen_to_64(rvfi_cause_s[port]);
        packet.tval  = xlen_to_64(rvfi_tval_s[port]);
        candidate_count++;
      end

      if (marker_evt) begin
        packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
        packet.evt = EVT_MARKER;
        packet.value = args_at_port[port][0];
        candidate_count++;
      end

      if (syscall_entry_evt && !marker_evt) begin
        if (trace_enable_syscall_i && pc_pass) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt = EVT_SYSCALL_ENTRY;
          packet.syscall_id = next_syscall_id_view;
          packet.a0  = args_at_port[port][0];
          packet.a1  = args_at_port[port][1];
          packet.a2  = args_at_port[port][2];
          packet.a3  = args_at_port[port][3];
          packet.a4  = args_at_port[port][4];
          packet.a5  = args_at_port[port][5];
          packet.a6  = args_at_port[port][6];
          packet.a7  = args_at_port[port][7];
          candidate_count++;
        end
        syscall_outstanding_view = 1'b1;
        active_syscall_id_view = next_syscall_id_view;
        syscall_entry_cycle_view = sample_cycle;
        if (pointer_entry_supported && user_pointer_range_ok(pointer_entry_base, pointer_entry_len)) begin
          pointer_watch_active_view = 1'b1;
          pointer_watch_base_view = pointer_entry_base;
          pointer_watch_limit_view = pointer_entry_base + pointer_entry_len;
          pointer_watch_syscall_id_view = next_syscall_id_view;
          pointer_watch_arg_index_view = pointer_entry_arg_index;
          pointer_watch_age_view = 64'd0;
        end
        next_syscall_id_view = next_syscall_id_view + 64'd1;
      end

      if (syscall_ret_evt) begin
        if (trace_enable_syscall_i && pc_pass) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt = EVT_SYSCALL_RET;
          packet.target = vlen_to_64(rvfi_pc_wdata_s[port]);
          packet.syscall_id = active_syscall_id_view;
          packet.duration = sample_cycle - syscall_entry_cycle_view;
          packet.a0 = args_at_port[port][0];
          candidate_count++;
        end
        syscall_outstanding_view = 1'b0;
        pointer_watch_active_view = 1'b0;
        pointer_watch_age_view = 64'd0;
      end

      if (pointer_capture_valid[port] && trace_enable_syscall_i &&
          trace_pc_pass(pointer_capture_packet[port].pc)) begin
        candidate_count++;
        pointer_watch_age_view = 64'd0;
        if (pointer_capture_last[port]) begin
          pointer_watch_active_view = 1'b0;
        end
      end

      if (event_valid && port == 0 && csr_valid_s && trace_is_watched_csr(csr_addr_s) &&
          trace_enable_context_i && pc_pass) begin
        packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
        packet.evt   = csr_addr_s == TRACE_CSR_SATP ? EVT_SATP : EVT_CSR;
        packet.csr   = csr_addr_s;
        packet.value = xlen_to_64(csr_wdata_s);
        packet.satp  = csr_addr_s == TRACE_CSR_SATP ? xlen_to_64(csr_wdata_s) : satp64;
        candidate_count++;
      end

      if (event_valid && rvfi_mode_s[port] != priv_view) begin
        if (trace_enable_context_i && pc_pass) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt      = EVT_PRIV;
          packet.old_priv = priv_view;
          packet.new_priv = rvfi_mode_s[port];
          packet.value    = {62'd0, rvfi_mode_s[port]};
          candidate_count++;
        end
        priv_view = rvfi_mode_s[port];
      end

      if (event_valid && !rvfi_trap_s[port] && branch_evt) begin
        if (trace_enable_branch_i && pc_pass) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt    = EVT_BRANCH;
          packet.taken  = branch_taken;
          packet.target = branch_taken ? branch_target : fallthrough_pc;
          candidate_count++;
        end
      end else if (event_valid && !rvfi_trap_s[port] && jump_evt) begin
        if (trace_enable_jump_i && pc_pass) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt    = EVT_JUMP;
          packet.taken  = 1'b1;
          packet.target = jump_target;
          candidate_count++;
        end
      end

      if (event_valid && rvfi_valid_s[port] && !rvfi_trap_s[port] && trace_enable_retire_i && pc_pass) begin
        packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
        packet.evt = EVT_RETIRE;
        candidate_count++;
      end
    end
    priv_shadow_n = priv_view;
    syscall_outstanding_n = syscall_outstanding_view;
    next_syscall_id_n = next_syscall_id_view;
    active_syscall_id_n = active_syscall_id_view;
    syscall_entry_cycle_n = syscall_entry_cycle_view;
    pointer_watch_active_n = pointer_watch_active_view;
    pointer_watch_base_n = pointer_watch_base_view;
    pointer_watch_limit_n = pointer_watch_limit_view;
    pointer_watch_syscall_id_n = pointer_watch_syscall_id_view;
    pointer_watch_arg_index_n = pointer_watch_arg_index_view;
    pointer_watch_age_n = pointer_watch_age_view;
  end

  always_comb begin
    pop_pending = (pending_count_q != '0) && !drop_output;
    pending_count_after_pop = pending_count_q;
    if (pop_pending) begin
      pending_count_after_pop = pending_count_q - 1'b1;
    end

    if (candidate_count <= INTERNAL_EVENT_QUEUE_DEPTH - pending_count_after_pop) begin
      accepted_candidate_count = candidate_count;
      dropped_this_cycle = 64'd0;
    end else begin
      accepted_candidate_count = INTERNAL_EVENT_QUEUE_DEPTH - pending_count_after_pop;
      dropped_this_cycle = candidate_count - accepted_candidate_count;
    end
    enqueue_candidate = accepted_candidate_count != 0;
    pending_count_next = pending_count_after_pop + accepted_candidate_count;
  end

  always_comb begin
    drop_packet = trace_null_packet();
    drop_packet.valid = drop_count_q != 64'd0 && trace_enable_drop_i;
    drop_packet.evt   = drop_packet.valid ? EVT_DROP : EVT_NONE;
    drop_packet.cycle = cycle_q;
    drop_packet.value = drop_count_q;

    trace_valid_o  = 1'b0;
    trace_packet_o = trace_null_packet();
    drop_output    = 1'b0;

    if (drop_packet.valid && !drop_defer_q) begin
      trace_valid_o  = 1'b1;
      trace_packet_o = drop_packet;
      drop_output    = 1'b1;
    end else if (pending_count_q != '0) begin
      trace_valid_o  = 1'b1;
      trace_packet_o = pending_q[0];
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cycle_q <= 64'd0;
      drop_count_q <= 64'd0;
      drop_defer_q <= 1'b0;
      priv_shadow_q <= TRACE_PRIV_M;
      syscall_outstanding_q <= 1'b0;
      next_syscall_id_q <= 64'd0;
      active_syscall_id_q <= 64'd0;
      syscall_entry_cycle_q <= 64'd0;
      pointer_watch_active_q <= 1'b0;
      pointer_watch_base_q <= 64'd0;
      pointer_watch_limit_q <= 64'd0;
      pointer_watch_syscall_id_q <= 64'd0;
      pointer_watch_arg_index_q <= 3'd0;
      pointer_watch_age_q <= 64'd0;
      args_q <= '0;
      pending_count_q <= '0;
      for (int unsigned i = 0; i < INTERNAL_EVENT_QUEUE_DEPTH; i++) begin
        pending_q[i] <= trace_null_packet();
      end
    end else begin
      int unsigned append_count;
      trace_packet_t packet;
      logic [1:0] priv_view;
      logic syscall_outstanding_view;
      logic [63:0] next_syscall_id_view;
      logic [63:0] active_syscall_id_view;
      logic [63:0] syscall_entry_cycle_view;

      append_count = 0;
      priv_view = priv_shadow_q;
      syscall_outstanding_view = syscall_outstanding_q;
      next_syscall_id_view = next_syscall_id_q;
      active_syscall_id_view = active_syscall_id_q;
      syscall_entry_cycle_view = syscall_entry_cycle_q;

      cycle_q <= cycle_q + 64'd1;
      args_q <= args_n;
      priv_shadow_q <= priv_shadow_n;
      syscall_outstanding_q <= syscall_outstanding_n;
      next_syscall_id_q <= next_syscall_id_n;
      active_syscall_id_q <= active_syscall_id_n;
      syscall_entry_cycle_q <= syscall_entry_cycle_n;
      pointer_watch_active_q <= pointer_watch_active_n;
      pointer_watch_base_q <= pointer_watch_base_n;
      pointer_watch_limit_q <= pointer_watch_limit_n;
      pointer_watch_syscall_id_q <= pointer_watch_syscall_id_n;
      pointer_watch_arg_index_q <= pointer_watch_arg_index_n;
      pointer_watch_age_q <= pointer_watch_age_n;

      if (drop_output) begin
        drop_count_q <= dropped_this_cycle;
        drop_defer_q <= 1'b1;
      end else begin
        drop_count_q <= drop_count_q + dropped_this_cycle;
        drop_defer_q <= 1'b0;
      end

      pending_count_q <= pending_count_next;
      if (pop_pending) begin
        for (int unsigned i = 0; i < INTERNAL_EVENT_QUEUE_DEPTH; i++) begin
          if (i + 1 < INTERNAL_EVENT_QUEUE_DEPTH) begin
            pending_q[i] <= pending_q[i + 1];
          end else begin
            pending_q[i] <= trace_null_packet();
          end
        end
      end

      for (int unsigned port = 0; port < COMMIT_PORTS; port++) begin
        logic        event_valid;
        logic [31:0] instr;
        logic [63:0] pc;
        logic [63:0] satp64;
        logic [63:0] fallthrough_pc;
        logic        compressed;
        logic        branch_evt;
        logic        jump_evt;
        logic        branch_taken;
        logic [63:0] branch_target;
        logic [63:0] jump_target;
        logic        syscall_entry_evt;
        logic        syscall_ret_evt;
        logic        marker_evt;
        logic [63:0] marker_tag;
        logic        pc_pass;

        event_valid = rvfi_valid_s[port] || rvfi_trap_s[port];
        instr       = insn_to_32(rvfi_insn_s[port]);
        pc          = vlen_to_64(rvfi_pc_rdata_s[port]);
        pc_pass     = trace_pc_pass(pc);
        satp64      = xlen_to_64(satp_s);
        compressed  = rvfi_compressed_s[port] || instr[1:0] != 2'b11;
        fallthrough_pc = pc + (compressed ? 64'd2 : 64'd4);
        branch_evt = (!compressed && instr[6:0] == OPCODE_BRANCH) || (compressed && is_c_branch(instr));
        jump_evt = (!compressed && (instr[6:0] == OPCODE_JAL || instr[6:0] == OPCODE_JALR)) ||
                   (compressed && (is_c_jump(instr) || is_c_jr_jalr(instr)));
        branch_taken = compressed ? c_branch_taken(instr, rvfi_rs1_rdata_s[port]) :
                       branch_condition(instr[14:12], rvfi_rs1_rdata_s[port], rvfi_rs2_rdata_s[port]);
        branch_target = compressed ? pc + cb_imm(instr) : pc + b_imm(instr);
        jump_target = compressed && is_c_jump(instr) ? pc + cj_imm(instr) :
                      (!compressed && instr[6:0] == OPCODE_JAL) ? pc + j_imm(instr) :
                      (xlen_to_64(rvfi_rs1_rdata_s[port]) +
                       (compressed ? 64'd0 : i_imm(instr))) & ~64'd1;
        syscall_entry_evt = event_valid && rvfi_trap_s[port] &&
                             instr == INSTR_ECALL &&
                             rvfi_mode_s[port] == TRACE_PRIV_U &&
                             xlen_to_64(rvfi_cause_s[port]) == CAUSE_U_ECALL;
        marker_tag = args_at_port[port][0] & MARKER_TAG_MASK;
        marker_evt = syscall_entry_evt && trace_enable_marker_i &&
                     args_at_port[port][7] == MARKER_SYSCALL_NR &&
                     (marker_tag == MARKER_BEGIN_TAG || marker_tag == MARKER_END_TAG);
        syscall_ret_evt = event_valid && !rvfi_trap_s[port] && instr == INSTR_SRET &&
                           rvfi_mode_s[port] == TRACE_PRIV_S &&
                           (rvfi_sret_to_user_s[port] || RELAX_SRET_TO_USER_CHECK) &&
                           syscall_outstanding_view;

        if (event_valid && rvfi_trap_s[port] && trace_enable_trap_i && pc_pass) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt   = EVT_TRAP;
          packet.cause = xlen_to_64(rvfi_cause_s[port]);
          packet.tval  = xlen_to_64(rvfi_tval_s[port]);
          offer_candidate(packet, pending_count_after_pop, append_count);
        end

        if (marker_evt) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt = EVT_MARKER;
          packet.value = args_at_port[port][0];
          offer_candidate(packet, pending_count_after_pop, append_count);
        end

        if (syscall_entry_evt && !marker_evt) begin
          if (trace_enable_syscall_i && pc_pass) begin
            packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
            packet.evt = EVT_SYSCALL_ENTRY;
            packet.syscall_id = next_syscall_id_view;
            packet.a0  = args_at_port[port][0];
            packet.a1  = args_at_port[port][1];
            packet.a2  = args_at_port[port][2];
            packet.a3  = args_at_port[port][3];
            packet.a4  = args_at_port[port][4];
            packet.a5  = args_at_port[port][5];
            packet.a6  = args_at_port[port][6];
            packet.a7  = args_at_port[port][7];
            offer_candidate(packet, pending_count_after_pop, append_count);
          end
          syscall_outstanding_view = 1'b1;
          active_syscall_id_view = next_syscall_id_view;
          syscall_entry_cycle_view = sample_cycle;
          next_syscall_id_view = next_syscall_id_view + 64'd1;
        end

        if (syscall_ret_evt) begin
          if (trace_enable_syscall_i && pc_pass) begin
            packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
            packet.evt = EVT_SYSCALL_RET;
            packet.target = vlen_to_64(rvfi_pc_wdata_s[port]);
            packet.syscall_id = active_syscall_id_view;
            packet.duration = sample_cycle - syscall_entry_cycle_view;
            packet.a0 = args_at_port[port][0];
            offer_candidate(packet, pending_count_after_pop, append_count);
          end
          syscall_outstanding_view = 1'b0;
        end

        if (pointer_capture_valid[port] && trace_enable_syscall_i &&
            trace_pc_pass(pointer_capture_packet[port].pc)) begin
          offer_candidate(pointer_capture_packet[port], pending_count_after_pop, append_count);
        end

        if (event_valid && port == 0 && csr_valid_s && trace_is_watched_csr(csr_addr_s) &&
            trace_enable_context_i && pc_pass) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt   = csr_addr_s == TRACE_CSR_SATP ? EVT_SATP : EVT_CSR;
          packet.csr   = csr_addr_s;
          packet.value = xlen_to_64(csr_wdata_s);
          packet.satp  = csr_addr_s == TRACE_CSR_SATP ? xlen_to_64(csr_wdata_s) : satp64;
          offer_candidate(packet, pending_count_after_pop, append_count);
        end

        if (event_valid && rvfi_mode_s[port] != priv_view) begin
          if (trace_enable_context_i && pc_pass) begin
            packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
            packet.evt      = EVT_PRIV;
            packet.old_priv = priv_view;
            packet.new_priv = rvfi_mode_s[port];
            packet.value    = {62'd0, rvfi_mode_s[port]};
            offer_candidate(packet, pending_count_after_pop, append_count);
          end
          priv_view = rvfi_mode_s[port];
        end

        if (event_valid && !rvfi_trap_s[port] && branch_evt) begin
          if (trace_enable_branch_i && pc_pass) begin
            packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
            packet.evt    = EVT_BRANCH;
            packet.taken  = branch_taken;
            packet.target = branch_taken ? branch_target : fallthrough_pc;
            offer_candidate(packet, pending_count_after_pop, append_count);
          end
        end else if (event_valid && !rvfi_trap_s[port] && jump_evt) begin
          if (trace_enable_jump_i && pc_pass) begin
            packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
            packet.evt    = EVT_JUMP;
            packet.taken  = 1'b1;
            packet.target = jump_target;
            offer_candidate(packet, pending_count_after_pop, append_count);
          end
        end

        if (event_valid && rvfi_valid_s[port] && !rvfi_trap_s[port] && trace_enable_retire_i && pc_pass) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt = EVT_RETIRE;
          offer_candidate(packet, pending_count_after_pop, append_count);
        end
      end
    end
  end

endmodule
