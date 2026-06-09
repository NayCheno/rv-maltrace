module cva6_rvfi_trace_adapter
  import trace_pkg::*;
#(
    parameter int COMMIT_PORTS = 1,
    parameter int XLEN = 64,
    parameter int ILEN = 32,
    parameter int VLEN = 64,
    parameter int EVENT_QUEUE_DEPTH = 16,
    parameter int PIPELINE_INPUTS = 1
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

    output logic                                trace_valid_o,
    output trace_packet_t                       trace_packet_o
);

  localparam logic [6:0] OPCODE_BRANCH = 7'b1100011;
  localparam logic [6:0] OPCODE_JAL    = 7'b1101111;
  localparam logic [6:0] OPCODE_JALR   = 7'b1100111;
  localparam logic [31:0] INSTR_ECALL  = 32'h0000_0073;
  localparam logic [31:0] INSTR_SRET   = 32'h1020_0073;
  localparam logic [63:0] CAUSE_U_ECALL = 64'd8;

  localparam int MAX_CANDIDATES = COMMIT_PORTS * 6 + 1;
  localparam int QUEUE_COUNT_WIDTH = $clog2(EVENT_QUEUE_DEPTH + 1);

  logic [7:0][63:0] args_q;
  logic [7:0][63:0] args_n;
  logic [COMMIT_PORTS-1:0][7:0][63:0] args_at_port;
  logic [1:0] priv_shadow_q;
  logic syscall_outstanding_q;
  logic syscall_outstanding_n;
  logic [63:0] next_syscall_id_q;
  logic [63:0] next_syscall_id_n;
  logic [63:0] active_syscall_id_q;
  logic [63:0] active_syscall_id_n;
  logic [63:0] syscall_entry_cycle_q;
  logic [63:0] syscall_entry_cycle_n;

  trace_packet_t candidates [MAX_CANDIDATES];
  int unsigned candidate_count;

  trace_packet_t pending_q [EVENT_QUEUE_DEPTH];
  trace_packet_t pending_n [EVENT_QUEUE_DEPTH];
  logic [QUEUE_COUNT_WIDTH-1:0] pending_count_q;
  logic [QUEUE_COUNT_WIDTH-1:0] pending_count_n;

  logic [63:0] cycle_q;
  logic [63:0] sample_cycle;
  logic [63:0] drop_count_q;
  logic [63:0] dropped_this_cycle;
  logic        drop_defer_q;
  logic        drop_output;
  logic        direct_candidate_output;
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
  logic                                csr_valid_s;
  logic [11:0]                         csr_addr_s;
  logic [XLEN-1:0]                     csr_wdata_s;
  logic [XLEN-1:0]                     satp_s;

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
    trace_packet_t packet;
    logic [1:0] priv_view;
    logic syscall_outstanding_view;
    logic [63:0] next_syscall_id_view;
    logic [63:0] active_syscall_id_view;
    logic [63:0] syscall_entry_cycle_view;

    candidate_count = 0;
    priv_view = priv_shadow_q;
    syscall_outstanding_view = syscall_outstanding_q;
    next_syscall_id_view = next_syscall_id_q;
    active_syscall_id_view = active_syscall_id_q;
    syscall_entry_cycle_view = syscall_entry_cycle_q;
    for (int unsigned i = 0; i < MAX_CANDIDATES; i++) begin
      candidates[i] = trace_null_packet();
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

      event_valid = rvfi_valid_s[port] || rvfi_trap_s[port];
      instr       = insn_to_32(rvfi_insn_s[port]);
      pc          = vlen_to_64(rvfi_pc_rdata_s[port]);
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
      syscall_ret_evt = event_valid && !rvfi_trap_s[port] && instr == INSTR_SRET &&
                          rvfi_mode_s[port] == TRACE_PRIV_S &&
                          rvfi_sret_to_user_s[port] &&
                          syscall_outstanding_view;

      if (event_valid && rvfi_trap_s[port] && trace_enable_trap_i) begin
        packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
        packet.evt   = EVT_TRAP;
        packet.cause = xlen_to_64(rvfi_cause_s[port]);
        packet.tval  = xlen_to_64(rvfi_tval_s[port]);
        candidates[candidate_count] = packet;
        candidate_count++;
      end

      if (syscall_entry_evt) begin
        if (trace_enable_syscall_i) begin
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
          candidates[candidate_count] = packet;
          candidate_count++;
        end
        syscall_outstanding_view = 1'b1;
        active_syscall_id_view = next_syscall_id_view;
        syscall_entry_cycle_view = sample_cycle;
        next_syscall_id_view = next_syscall_id_view + 64'd1;
      end

      if (syscall_ret_evt) begin
        if (trace_enable_syscall_i) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt = EVT_SYSCALL_RET;
          packet.target = vlen_to_64(rvfi_pc_wdata_s[port]);
          packet.syscall_id = active_syscall_id_view;
          packet.duration = sample_cycle - syscall_entry_cycle_view;
          packet.a0 = args_at_port[port][0];
          candidates[candidate_count] = packet;
          candidate_count++;
        end
        syscall_outstanding_view = 1'b0;
      end

      if (event_valid && port == 0 && csr_valid_s && trace_is_watched_csr(csr_addr_s) &&
          trace_enable_context_i) begin
        packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
        packet.evt   = csr_addr_s == TRACE_CSR_SATP ? EVT_SATP : EVT_CSR;
        packet.csr   = csr_addr_s;
        packet.value = xlen_to_64(csr_wdata_s);
        packet.satp  = csr_addr_s == TRACE_CSR_SATP ? xlen_to_64(csr_wdata_s) : satp64;
        candidates[candidate_count] = packet;
        candidate_count++;
      end

      if (event_valid && rvfi_mode_s[port] != priv_view) begin
        if (trace_enable_context_i) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt      = EVT_PRIV;
          packet.old_priv = priv_view;
          packet.new_priv = rvfi_mode_s[port];
          packet.value    = {62'd0, rvfi_mode_s[port]};
          candidates[candidate_count] = packet;
          candidate_count++;
        end
        priv_view = rvfi_mode_s[port];
      end

      if (event_valid && !rvfi_trap_s[port] && branch_evt) begin
        if (trace_enable_branch_i) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt    = EVT_BRANCH;
          packet.taken  = branch_taken;
          packet.target = branch_taken ? branch_target : fallthrough_pc;
          candidates[candidate_count] = packet;
          candidate_count++;
        end
      end else if (event_valid && !rvfi_trap_s[port] && jump_evt) begin
        if (trace_enable_jump_i) begin
          packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
          packet.evt    = EVT_JUMP;
          packet.taken  = 1'b1;
          packet.target = jump_target;
          candidates[candidate_count] = packet;
          candidate_count++;
        end
      end

      if (event_valid && rvfi_valid_s[port] && !rvfi_trap_s[port] && trace_enable_retire_i) begin
        packet = base_packet(sample_cycle, pc, instr, rvfi_mode_s[port], satp64);
        packet.evt = EVT_RETIRE;
        candidates[candidate_count] = packet;
        candidate_count++;
      end
    end
    priv_shadow_n = priv_view;
    syscall_outstanding_n = syscall_outstanding_view;
    next_syscall_id_n = next_syscall_id_view;
    active_syscall_id_n = active_syscall_id_view;
    syscall_entry_cycle_n = syscall_entry_cycle_view;
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

    for (int unsigned i = 0; i < MAX_CANDIDATES; i++) begin
      if (i < candidate_count) begin
        if (direct_candidate_output && i == 0) begin
          // The first candidate can be emitted directly when there is no queued work.
        end else if (pending_count_n < EVENT_QUEUE_DEPTH) begin
          pending_n[pending_count_n] = candidates[i];
          pending_count_n = pending_count_n + 1'b1;
        end else begin
          dropped_this_cycle = dropped_this_cycle + 64'd1;
        end
      end
    end
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
    direct_candidate_output = 1'b0;

    if (drop_packet.valid && !drop_defer_q) begin
      trace_valid_o  = 1'b1;
      trace_packet_o = drop_packet;
      drop_output    = 1'b1;
    end else if (pending_count_q != '0) begin
      trace_valid_o  = 1'b1;
      trace_packet_o = pending_q[0];
    end else if (candidate_count != 0) begin
      trace_valid_o  = 1'b1;
      trace_packet_o = candidates[0];
      direct_candidate_output = 1'b1;
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
      args_q <= '0;
      pending_count_q <= '0;
      for (int unsigned i = 0; i < EVENT_QUEUE_DEPTH; i++) begin
        pending_q[i] <= trace_null_packet();
      end
    end else begin
      cycle_q <= cycle_q + 64'd1;
      args_q <= args_n;
      priv_shadow_q <= priv_shadow_n;
      syscall_outstanding_q <= syscall_outstanding_n;
      next_syscall_id_q <= next_syscall_id_n;
      active_syscall_id_q <= active_syscall_id_n;
      syscall_entry_cycle_q <= syscall_entry_cycle_n;

      if (drop_output) begin
        drop_count_q <= dropped_this_cycle;
        drop_defer_q <= 1'b1;
      end else begin
        drop_count_q <= drop_count_q + dropped_this_cycle;
        drop_defer_q <= 1'b0;
      end

      pending_count_q <= pending_count_n;
      for (int unsigned i = 0; i < EVENT_QUEUE_DEPTH; i++) begin
        pending_q[i] <= pending_n[i];
      end
    end
  end

endmodule
