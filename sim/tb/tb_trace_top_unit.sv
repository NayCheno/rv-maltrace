module tb_trace_top_unit
  import trace_pkg::*;
;

  logic clk;
  logic rst_n;
  string test_name;

  logic commit_valid;
  logic [63:0] commit_pc;
  logic [31:0] commit_instr;
  logic [63:0] next_pc;
  logic sret_to_user;
  logic jalr_target_valid;
  logic [63:0] jalr_target;
  logic commit_exception;
  logic commit_kill;

  logic [0:0] wb_valid;
  logic [0:0] wb_kill;
  logic [0:0][4:0] wb_rd;
  logic [0:0][63:0] wb_data;

  logic trap_valid;
  logic [63:0] trap_pc;
  logic [63:0] trap_cause;
  logic [63:0] trap_tval;

  logic csr_valid;
  logic [11:0] csr_addr;
  logic [63:0] csr_wdata;
  logic [1:0] priv_lvl;
  logic [63:0] satp;
  trace_mem_mode_e trace_mem_mode;
  logic trace_mem_load_valid;
  logic [63:0] trace_mem_load_pc;
  logic [63:0] trace_mem_load_addr;
  logic [63:0] trace_mem_load_data;
  logic [2:0] trace_mem_load_size;
  logic trace_enable_retire;
  logic trace_enable_branch;
  logic trace_enable_jump;
  logic trace_enable_syscall;
  logic trace_enable_trap;
  logic trace_enable_context;
  logic trace_enable_marker;
  logic trace_enable_drop;
  logic trace_pc_filter_enable;
  logic [63:0] trace_pc_start;
  logic [63:0] trace_pc_end;
  logic trace_priv_filter_enable;
  logic [3:0] trace_priv_mask;
  logic board_minimal_profile_active;
  logic board_trace_enable_retire;
  logic board_trace_enable_branch;
  logic board_trace_enable_jump;
  logic board_trace_enable_syscall;
  logic board_trace_enable_trap;
  logic board_trace_enable_context;
  logic board_trace_enable_marker;
  logic board_trace_enable_drop;
  logic board_trace_pc_filter_enable;
  logic [63:0] board_trace_pc_start;
  logic [63:0] board_trace_pc_end;
  logic board_trace_priv_filter_enable;
  logic [3:0] board_trace_priv_mask;
  logic trace_enable_retire_to_dut;
  logic trace_enable_branch_to_dut;
  logic trace_enable_jump_to_dut;
  logic trace_enable_syscall_to_dut;
  logic trace_enable_trap_to_dut;
  logic trace_enable_context_to_dut;
  logic trace_enable_marker_to_dut;
  logic trace_enable_drop_to_dut;
  logic trace_pc_filter_enable_to_dut;
  logic [63:0] trace_pc_start_to_dut;
  logic [63:0] trace_pc_end_to_dut;
  logic trace_priv_filter_enable_to_dut;
  logic [3:0] trace_priv_mask_to_dut;

  logic trace_valid;
  trace_packet_t trace_packet;

  logic mem_req;
  logic mem_we;
  logic [63:0] mem_addr;
  logic [63:0] mem_wdata;
  logic [63:0] mem_rdata;
  logic finish;
  logic pass;

  trace_board_minimal_ctrl board_minimal_profile (
      .trace_enable_retire_o(board_trace_enable_retire),
      .trace_enable_branch_o(board_trace_enable_branch),
      .trace_enable_jump_o(board_trace_enable_jump),
      .trace_enable_syscall_o(board_trace_enable_syscall),
      .trace_enable_trap_o(board_trace_enable_trap),
      .trace_enable_context_o(board_trace_enable_context),
      .trace_enable_marker_o(board_trace_enable_marker),
      .trace_enable_drop_o(board_trace_enable_drop),
      .trace_pc_filter_enable_o(board_trace_pc_filter_enable),
      .trace_pc_start_o(board_trace_pc_start),
      .trace_pc_end_o(board_trace_pc_end),
      .trace_priv_filter_enable_o(board_trace_priv_filter_enable),
      .trace_priv_mask_o(board_trace_priv_mask)
  );

  assign trace_enable_retire_to_dut = board_minimal_profile_active ? board_trace_enable_retire : trace_enable_retire;
  assign trace_enable_branch_to_dut = board_minimal_profile_active ? board_trace_enable_branch : trace_enable_branch;
  assign trace_enable_jump_to_dut = board_minimal_profile_active ? board_trace_enable_jump : trace_enable_jump;
  assign trace_enable_syscall_to_dut = board_minimal_profile_active ? board_trace_enable_syscall : trace_enable_syscall;
  assign trace_enable_trap_to_dut = board_minimal_profile_active ? board_trace_enable_trap : trace_enable_trap;
  assign trace_enable_context_to_dut = board_minimal_profile_active ? board_trace_enable_context : trace_enable_context;
  assign trace_enable_marker_to_dut = board_minimal_profile_active ? board_trace_enable_marker : trace_enable_marker;
  assign trace_enable_drop_to_dut = board_minimal_profile_active ? board_trace_enable_drop : trace_enable_drop;
  assign trace_pc_filter_enable_to_dut = board_minimal_profile_active ? board_trace_pc_filter_enable : trace_pc_filter_enable;
  assign trace_pc_start_to_dut = board_minimal_profile_active ? board_trace_pc_start : trace_pc_start;
  assign trace_pc_end_to_dut = board_minimal_profile_active ? board_trace_pc_end : trace_pc_end;
  assign trace_priv_filter_enable_to_dut = board_minimal_profile_active ? board_trace_priv_filter_enable : trace_priv_filter_enable;
  assign trace_priv_mask_to_dut = board_minimal_profile_active ? board_trace_priv_mask : trace_priv_mask;

  trace_top #(
      .WB_PORTS(1),
      .EVENT_QUEUE_DEPTH(8),
      .MAX_ARG_MEM_CAPTURE_BYTES(8),
      .MAX_ARG_MEM_WATCH_CYCLES(8)
  ) dut (
      .clk_i(clk),
      .rst_ni(rst_n),
      .commit_valid_i(commit_valid),
      .commit_pc_i(commit_pc),
      .commit_instr_i(commit_instr),
      .next_pc_i(next_pc),
      .sret_to_user_i(sret_to_user),
      .jalr_target_valid_i(jalr_target_valid),
      .jalr_target_i(jalr_target),
      .commit_exception_i(commit_exception),
      .commit_kill_i(commit_kill),
      .wb_valid_i(wb_valid),
      .wb_kill_i(wb_kill),
      .wb_rd_i(wb_rd),
      .wb_data_i(wb_data),
      .trap_valid_i(trap_valid),
      .trap_pc_i(trap_pc),
      .trap_cause_i(trap_cause),
      .trap_tval_i(trap_tval),
      .csr_valid_i(csr_valid),
      .csr_addr_i(csr_addr),
      .csr_wdata_i(csr_wdata),
      .priv_lvl_i(priv_lvl),
      .satp_i(satp),
      .trace_mem_mode_i(trace_mem_mode),
      .mem_load_valid_i(trace_mem_load_valid),
      .mem_load_pc_i(trace_mem_load_pc),
      .mem_load_addr_i(trace_mem_load_addr),
      .mem_load_data_i(trace_mem_load_data),
      .mem_load_size_i(trace_mem_load_size),
      .trace_enable_retire_i(trace_enable_retire_to_dut),
      .trace_enable_branch_i(trace_enable_branch_to_dut),
      .trace_enable_jump_i(trace_enable_jump_to_dut),
      .trace_enable_syscall_i(trace_enable_syscall_to_dut),
      .trace_enable_trap_i(trace_enable_trap_to_dut),
      .trace_enable_context_i(trace_enable_context_to_dut),
      .trace_enable_marker_i(trace_enable_marker_to_dut),
      .trace_enable_drop_i(trace_enable_drop_to_dut),
      .trace_pc_filter_enable_i(trace_pc_filter_enable_to_dut),
      .trace_pc_start_i(trace_pc_start_to_dut),
      .trace_pc_end_i(trace_pc_end_to_dut),
      .trace_priv_filter_enable_i(trace_priv_filter_enable_to_dut),
      .trace_priv_mask_i(trace_priv_mask_to_dut),
      .trace_valid_o(trace_valid),
      .trace_packet_o(trace_packet)
  );

  tb_trace_sink sink (
      .clk_i(clk),
      .rst_ni(rst_n),
      .trace_valid_i(trace_valid),
      .trace_packet_i(trace_packet)
  );

  tb_trace_scoreboard scoreboard (
      .clk_i(clk),
      .rst_ni(rst_n),
      .trace_packet_i(trace_packet),
      .trace_valid_i(trace_valid),
      .finish_i(finish),
      .pass_i(pass)
  );

  tb_mem_model mem_model (
      .clk_i(clk),
      .rst_ni(rst_n),
      .req_i(mem_req),
      .we_i(mem_we),
      .addr_i(mem_addr),
      .wdata_i(mem_wdata),
      .rdata_o(mem_rdata),
      .finish_o(finish),
      .pass_o(pass)
  );

  initial begin
    clk = 1'b0;
    forever #5 clk = ~clk;
  end

  task automatic set_filter_defaults();
    begin
      trace_enable_retire      = 1'b1;
      trace_enable_branch      = 1'b1;
      trace_enable_jump        = 1'b1;
      trace_enable_syscall     = 1'b1;
      trace_enable_trap        = 1'b1;
      trace_enable_context     = 1'b1;
      trace_enable_marker      = 1'b1;
      trace_enable_drop        = 1'b1;
      board_minimal_profile_active = 1'b0;
      trace_pc_filter_enable   = 1'b0;
      trace_pc_start           = 64'd0;
      trace_pc_end             = 64'hffff_ffff_ffff_ffff;
      trace_priv_filter_enable = 1'b0;
      trace_priv_mask          = 4'hf;
    end
  endtask

  task automatic clear_inputs();
    begin
      commit_valid      = 1'b0;
      commit_pc         = 64'd0;
      commit_instr      = 32'd0;
      next_pc           = 64'd0;
      sret_to_user      = 1'b0;
      jalr_target_valid = 1'b0;
      jalr_target       = 64'd0;
      commit_exception  = 1'b0;
      commit_kill       = 1'b0;
      wb_valid          = '0;
      wb_kill           = '0;
      wb_rd             = '0;
      wb_data           = '0;
      trap_valid        = 1'b0;
      trap_pc           = 64'd0;
      trap_cause        = 64'd0;
      trap_tval         = 64'd0;
      csr_valid         = 1'b0;
      csr_addr          = 12'd0;
      csr_wdata         = 64'd0;
      trace_mem_load_valid = 1'b0;
      trace_mem_load_pc    = 64'd0;
      trace_mem_load_addr  = 64'd0;
      trace_mem_load_data  = 64'd0;
      trace_mem_load_size  = 3'd0;
      mem_req           = 1'b0;
      mem_we            = 1'b0;
      mem_addr          = 64'd0;
      mem_wdata         = 64'd0;
    end
  endtask

  task automatic tick();
    begin
      @(posedge clk);
      #1;
      clear_inputs();
    end
  endtask

  task automatic commit_instr_event(
      input logic [63:0] pc,
      input logic [31:0] instr,
      input logic [63:0] npc
  );
    begin
      commit_valid = 1'b1;
      commit_pc    = pc;
      commit_instr = instr;
      next_pc      = npc;
      tick();
    end
  endtask

  task automatic write_arg(input logic [4:0] rd, input logic [63:0] data);
    begin
      wb_valid[0] = 1'b1;
      wb_rd[0]    = rd;
      wb_data[0]  = data;
      tick();
    end
  endtask

  task automatic trace_load_byte(
      input logic [63:0] pc,
      input logic [63:0] addr,
      input logic [ 7:0] data
  );
    begin
      trace_mem_load_valid = 1'b1;
      trace_mem_load_pc    = pc;
      trace_mem_load_addr  = addr;
      trace_mem_load_data  = {56'd0, data};
      trace_mem_load_size  = 3'd1;
      tick();
    end
  endtask

  task automatic trace_load_multi(
      input logic [63:0] pc,
      input logic [63:0] addr,
      input logic [63:0] data,
      input logic [ 2:0] size
  );
    begin
      trace_mem_load_valid = 1'b1;
      trace_mem_load_pc    = pc;
      trace_mem_load_addr  = addr;
      trace_mem_load_data  = data;
      trace_mem_load_size  = size;
      tick();
    end
  endtask

  task automatic finish_test();
    begin
      mem_req   = 1'b1;
      mem_we    = 1'b1;
      mem_addr  = 64'h0000_0000_1000_0000;
      mem_wdata = 64'd1;
      tick();
      repeat (12) tick();
      $finish;
    end
  endtask

  task automatic run_smoke();
    begin
      commit_instr_event(64'h8000_0000, 32'h0000_0513, 64'h8000_0004);
      commit_instr_event(64'h8000_0004, 32'h0010_0593, 64'h8000_0008);
      finish_test();
    end
  endtask

  task automatic run_branch();
    begin
      commit_instr_event(64'h8000_0010, 32'h0005_0863, 64'h8000_0020);
      finish_test();
    end
  endtask

  task automatic run_jump();
    begin
      commit_instr_event(64'h8000_0030, 32'h0100_00ef, 64'h8000_0040);
      commit_valid      = 1'b1;
      commit_pc         = 64'h8000_0040;
      commit_instr      = 32'h0000_8067;
      next_pc           = 64'h8000_0080;
      jalr_target_valid = 1'b1;
      jalr_target       = 64'h8000_0081;
      tick();
      finish_test();
    end
  endtask

  task automatic run_ecall();
    begin
      priv_lvl = TRACE_PRIV_U;
      write_arg(5'd17, 64'd64);
      write_arg(5'd10, 64'd1);
      write_arg(5'd11, 64'h8000_1000);
      write_arg(5'd12, 64'd5);
      commit_valid     = 1'b1;
      commit_exception = 1'b1;
      commit_pc        = 64'h8000_0040;
      commit_instr     = 32'h0000_0073;
      trap_valid       = 1'b1;
      trap_pc          = 64'h8000_0040;
      trap_cause       = 64'd8;
      trap_tval        = 64'd0;
      tick();
      finish_test();
    end
  endtask

  task automatic run_syscall_ret();
    begin
      priv_lvl = TRACE_PRIV_U;
      write_arg(5'd17, 64'd64);
      write_arg(5'd10, 64'd1);
      write_arg(5'd11, 64'h8000_1000);
      write_arg(5'd12, 64'd5);

      commit_valid     = 1'b1;
      commit_exception = 1'b1;
      commit_pc        = 64'h8000_0040;
      commit_instr     = 32'h0000_0073;
      trap_valid       = 1'b1;
      trap_pc          = 64'h8000_0040;
      trap_cause       = 64'd8;
      trap_tval        = 64'd0;
      tick();

      priv_lvl = TRACE_PRIV_S;
      write_arg(5'd10, 64'd5);

      commit_valid = 1'b1;
      commit_pc    = 64'h8000_0080;
      commit_instr = 32'h1020_0073;
      next_pc      = 64'h8000_0044;
      sret_to_user = 1'b1;
      tick();

      priv_lvl = TRACE_PRIV_U;
      commit_instr_event(64'h8000_0044, 32'h0000_0013, 64'h8000_0048);
      finish_test();
    end
  endtask

  task automatic run_pointer_string();
    begin
      trace_mem_mode = TRACE_MEM_MODE_RANGE;
      priv_lvl = TRACE_PRIV_U;
      write_arg(5'd17, 64'd56);
      write_arg(5'd10, 64'hffff_ffff_ffff_ff9c);
      write_arg(5'd11, 64'h8000_2000);
      write_arg(5'd12, 64'd0);

      commit_valid     = 1'b1;
      commit_exception = 1'b1;
      commit_pc        = 64'h8000_0100;
      commit_instr     = 32'h0000_0073;
      trap_valid       = 1'b1;
      trap_pc          = 64'h8000_0100;
      trap_cause       = 64'd8;
      trap_tval        = 64'd0;
      tick();

      priv_lvl = TRACE_PRIV_S;
      trace_load_byte(64'h8000_0200, 64'h8000_2000, 8'h2f);
      trace_load_byte(64'h8000_0204, 64'h8000_2001, 8'h74);
      trace_load_byte(64'h8000_0208, 64'h8000_2002, 8'h6d);
      trace_load_byte(64'h8000_020c, 64'h8000_2003, 8'h70);
      trace_load_byte(64'h8000_0210, 64'h8000_2004, 8'h00);

      write_arg(5'd10, 64'd3);
      commit_valid = 1'b1;
      commit_pc    = 64'h8000_0220;
      commit_instr = 32'h1020_0073;
      next_pc      = 64'h8000_0104;
      sret_to_user = 1'b1;
      tick();

      priv_lvl = TRACE_PRIV_U;
      commit_instr_event(64'h8000_0104, 32'h0000_0013, 64'h8000_0108);
      finish_test();
    end
  endtask

  task automatic run_pointer_guardrails();
    logic [63:0] offset;
    begin
      trace_mem_mode = TRACE_MEM_MODE_RANGE;

      priv_lvl = TRACE_PRIV_U;
      write_arg(5'd17, 64'd56);
      write_arg(5'd10, 64'hffff_ffff_ffff_ff9c);
      write_arg(5'd11, 64'h8000_2ffc);
      write_arg(5'd12, 64'd0);
      commit_valid     = 1'b1;
      commit_exception = 1'b1;
      commit_pc        = 64'h8000_0300;
      commit_instr     = 32'h0000_0073;
      trap_valid       = 1'b1;
      trap_pc          = 64'h8000_0300;
      trap_cause       = 64'd8;
      trap_tval        = 64'd0;
      tick();

      priv_lvl = TRACE_PRIV_S;
      trace_load_byte(64'h8000_0400, 64'h8000_2ffc, 8'h2f);
      trace_load_byte(64'h8000_0404, 64'h8000_2ffd, 8'h65);
      trace_load_byte(64'h8000_0408, 64'h8000_2ffe, 8'h74);
      trace_load_byte(64'h8000_040c, 64'h8000_2fff, 8'h63);
      trace_load_byte(64'h8000_0410, 64'h8000_3000, 8'h00);
      write_arg(5'd10, 64'd3);
      commit_valid = 1'b1;
      commit_pc    = 64'h8000_0420;
      commit_instr = 32'h1020_0073;
      next_pc      = 64'h8000_0304;
      sret_to_user = 1'b1;
      tick();

      priv_lvl = TRACE_PRIV_U;
      write_arg(5'd17, 64'd64);
      write_arg(5'd10, 64'd1);
      write_arg(5'd11, 64'h8000_4000);
      write_arg(5'd12, 64'd16);
      commit_valid     = 1'b1;
      commit_exception = 1'b1;
      commit_pc        = 64'h8000_0500;
      commit_instr     = 32'h0000_0073;
      trap_valid       = 1'b1;
      trap_pc          = 64'h8000_0500;
      trap_cause       = 64'd8;
      trap_tval        = 64'd0;
      tick();

      priv_lvl = TRACE_PRIV_S;
      for (int unsigned i = 0; i < 12; i++) begin
        offset = i;
        trace_load_byte(64'h8000_0600 + (offset << 2), 64'h8000_4000 + offset, 8'h41);
      end
      write_arg(5'd10, 64'd12);
      commit_valid = 1'b1;
      commit_pc    = 64'h8000_0640;
      commit_instr = 32'h1020_0073;
      next_pc      = 64'h8000_0504;
      sret_to_user = 1'b1;
      tick();

      priv_lvl = TRACE_PRIV_U;
      write_arg(5'd17, 64'd56);
      write_arg(5'd10, 64'hffff_ffff_ffff_ff9c);
      write_arg(5'd11, 64'h8000_6000);
      write_arg(5'd12, 64'd0);
      commit_valid     = 1'b1;
      commit_exception = 1'b1;
      commit_pc        = 64'h8000_0700;
      commit_instr     = 32'h0000_0073;
      trap_valid       = 1'b1;
      trap_pc          = 64'h8000_0700;
      trap_cause       = 64'd8;
      trap_tval        = 64'd0;
      tick();

      priv_lvl = TRACE_PRIV_S;
      trace_load_byte(64'h8000_0800, 64'h8000_7000, 8'h55);
      write_arg(5'd10, 64'd4);
      commit_valid = 1'b1;
      commit_pc    = 64'h8000_0810;
      commit_instr = 32'h1020_0073;
      next_pc      = 64'h8000_0704;
      sret_to_user = 1'b1;
      tick();

      priv_lvl = TRACE_PRIV_U;
      write_arg(5'd17, 64'd64);
      write_arg(5'd10, 64'd1);
      write_arg(5'd11, 64'h8000_5000);
      write_arg(5'd12, 64'd8);
      commit_valid     = 1'b1;
      commit_exception = 1'b1;
      commit_pc        = 64'h8000_0880;
      commit_instr     = 32'h0000_0073;
      trap_valid       = 1'b1;
      trap_pc          = 64'h8000_0880;
      trap_cause       = 64'd8;
      trap_tval        = 64'd0;
      tick();

      priv_lvl = TRACE_PRIV_S;
      trace_load_multi(64'h8000_08c0, 64'h8000_5006, 64'h0000_0000_5a59_5857, 3'd4);
      write_arg(5'd10, 64'd4);
      commit_valid = 1'b1;
      commit_pc    = 64'h8000_08d0;
      commit_instr = 32'h1020_0073;
      next_pc      = 64'h8000_0884;
      sret_to_user = 1'b1;
      tick();

      priv_lvl = TRACE_PRIV_U;
      write_arg(5'd17, 64'd56);
      write_arg(5'd10, 64'hffff_ffff_ffff_ff9c);
      write_arg(5'd11, 64'h8000_8000);
      write_arg(5'd12, 64'd0);
      commit_valid     = 1'b1;
      commit_exception = 1'b1;
      commit_pc        = 64'h8000_0900;
      commit_instr     = 32'h0000_0073;
      trap_valid       = 1'b1;
      trap_pc          = 64'h8000_0900;
      trap_cause       = 64'd8;
      trap_tval        = 64'd0;
      tick();

      priv_lvl = TRACE_PRIV_S;
      repeat (12) tick();
      trace_load_byte(64'h8000_0a00, 64'h8000_8000, 8'h78);
      write_arg(5'd10, 64'd5);
      commit_valid = 1'b1;
      commit_pc    = 64'h8000_0a10;
      commit_instr = 32'h1020_0073;
      next_pc      = 64'h8000_0904;
      sret_to_user = 1'b1;
      tick();

      priv_lvl = TRACE_PRIV_U;
      commit_instr_event(64'h8000_0b00, 32'h0000_0013, 64'h8000_0b04);
      finish_test();
    end
  endtask

  task automatic run_trap_illegal();
    begin
      commit_valid     = 1'b1;
      commit_exception = 1'b1;
      commit_pc        = 64'h8000_0050;
      commit_instr     = 32'hffff_ffff;
      trap_valid       = 1'b1;
      trap_pc          = 64'h8000_0050;
      trap_cause       = 64'd2;
      trap_tval        = 64'hffff_ffff;
      tick();
      finish_test();
    end
  endtask

  task automatic run_ebreak();
    begin
      commit_valid     = 1'b1;
      commit_exception = 1'b1;
      commit_pc        = 64'h8000_0060;
      commit_instr     = 32'h0010_0073;
      trap_valid       = 1'b1;
      trap_pc          = 64'h8000_0060;
      trap_cause       = 64'd3;
      trap_tval        = 64'd0;
      tick();
      finish_test();
    end
  endtask

  task automatic run_csr();
    begin
      commit_valid = 1'b1;
      commit_pc    = 64'h8000_0070;
      commit_instr = 32'h1800_1073;
      csr_valid    = 1'b1;
      csr_addr     = TRACE_CSR_SATP;
      csr_wdata    = 64'h0000_0000_1234_5000;
      satp         = 64'h0000_0000_1234_5000;
      tick();
      finish_test();
    end
  endtask

  task automatic run_context();
    begin
      priv_lvl = TRACE_PRIV_M;
      commit_instr_event(64'h8000_0080, 32'h0000_0013, 64'h8000_0084);
      priv_lvl = TRACE_PRIV_S;
      tick();
      commit_instr_event(64'h8000_0084, 32'h0000_0013, 64'h8000_0088);
      finish_test();
    end
  endtask

  task automatic run_backpressure();
    begin
      priv_lvl = TRACE_PRIV_U;
      write_arg(5'd17, 64'd64);
      write_arg(5'd10, 64'd1);
      repeat (20) begin
        commit_valid     = 1'b1;
        commit_exception = 1'b1;
        commit_pc        = 64'h8000_0100;
        commit_instr     = 32'h0000_0073;
        trap_valid       = 1'b1;
        trap_pc          = 64'h8000_0100;
        trap_cause       = 64'd8;
        trap_tval        = 64'd0;
        tick();
      end
      finish_test();
    end
  endtask

  task automatic run_filter();
    begin
      trace_enable_retire      = 1'b0;
      trace_enable_context     = 1'b0;
      trace_pc_filter_enable   = 1'b1;
      trace_pc_start           = 64'h8000_0200;
      trace_pc_end             = 64'h8000_02ff;
      trace_priv_filter_enable = 1'b1;
      trace_priv_mask          = 4'b0010;

      priv_lvl = TRACE_PRIV_S;
      commit_valid = 1'b1;
      commit_pc    = 64'h8000_0208;
      commit_instr = 32'h1800_1073;
      csr_valid    = 1'b1;
      csr_addr     = TRACE_CSR_SATP;
      csr_wdata    = 64'h0000_0000_0000_1234;
      satp         = 64'h0000_0000_0000_1234;
      tick();

      commit_instr_event(64'h8000_0200, 32'h0000_0013, 64'h8000_0204);
      commit_instr_event(64'h8000_0100, 32'h0005_0863, 64'h8000_0110);

      priv_lvl = TRACE_PRIV_M;
      commit_instr_event(64'h8000_0210, 32'h0005_0863, 64'h8000_0220);

      priv_lvl = TRACE_PRIV_S;
      commit_instr_event(64'h8000_0220, 32'h0005_0863, 64'h8000_0230);
      finish_test();
    end
  endtask

  task automatic run_board_minimal();
    begin
      board_minimal_profile_active = 1'b1;

      commit_instr_event(64'h8000_0300, 32'h0000_0013, 64'h8000_0304);
      commit_instr_event(64'h8000_0310, 32'h0100_00ef, 64'h8000_0320);

      commit_instr_event(64'h8000_0320, 32'h0005_0863, 64'h8000_0330);

      priv_lvl = TRACE_PRIV_U;
      write_arg(5'd17, 64'd64);
      write_arg(5'd10, 64'd1);
      commit_valid     = 1'b1;
      commit_exception = 1'b1;
      commit_pc        = 64'h8000_0340;
      commit_instr     = 32'h0000_0073;
      trap_valid       = 1'b1;
      trap_pc          = 64'h8000_0340;
      trap_cause       = 64'd8;
      trap_tval        = 64'd0;
      tick();

      priv_lvl = TRACE_PRIV_S;
      commit_instr_event(64'h8000_0350, 32'h0000_0013, 64'h8000_0354);
      finish_test();
    end
  endtask

  initial begin
    if (!$value$plusargs("TEST_NAME=%s", test_name)) begin
      test_name = "smoke";
    end
    if (TRACE_MEM_MODE_DEFAULT != TRACE_MEM_MODE_NONE) begin
      $fatal(1, "TRACE_MEM_MODE_DEFAULT must stay TRACE_MEM_MODE_NONE until memory trace is enabled");
    end

    rst_n = 1'b0;
    priv_lvl = TRACE_PRIV_M;
    satp = 64'd0;
    trace_mem_mode = TRACE_MEM_MODE_NONE;
    set_filter_defaults();
    clear_inputs();
    repeat (5) @(posedge clk);
    rst_n = 1'b1;
    #1;

    if (test_name == "smoke") run_smoke();
    else if (test_name == "branch") run_branch();
    else if (test_name == "jump") run_jump();
    else if (test_name == "ecall") run_ecall();
    else if (test_name == "syscall_ret") run_syscall_ret();
    else if (test_name == "pointer_string") run_pointer_string();
    else if (test_name == "pointer_guardrails") run_pointer_guardrails();
    else if (test_name == "trap_illegal") run_trap_illegal();
    else if (test_name == "ebreak") run_ebreak();
    else if (test_name == "csr") run_csr();
    else if (test_name == "context") run_context();
    else if (test_name == "backpressure") run_backpressure();
    else if (test_name == "filter") run_filter();
    else if (test_name == "board_minimal") run_board_minimal();
    else $fatal(1, "Unknown TEST_NAME=%s", test_name);
  end

endmodule
