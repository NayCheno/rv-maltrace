module tb_cva6_rvfi_trace_adapter
  import trace_pkg::*;
;

  localparam int COMMIT_PORTS = 2;

  logic clk;
  logic rst_n;

  logic [COMMIT_PORTS-1:0]        rvfi_valid;
  logic [COMMIT_PORTS-1:0][31:0]  rvfi_insn;
  logic [COMMIT_PORTS-1:0]        rvfi_trap;
  logic [COMMIT_PORTS-1:0][63:0]  rvfi_cause;
  logic [COMMIT_PORTS-1:0][63:0]  rvfi_tval;
  logic [COMMIT_PORTS-1:0][1:0]   rvfi_mode;
  logic [COMMIT_PORTS-1:0]        rvfi_compressed;
  logic [COMMIT_PORTS-1:0][63:0]  rvfi_pc;
  logic [COMMIT_PORTS-1:0][63:0]  rvfi_pc_wdata;
  logic [COMMIT_PORTS-1:0]        rvfi_sret_to_user;
  logic [COMMIT_PORTS-1:0][63:0]  rvfi_rs1;
  logic [COMMIT_PORTS-1:0][63:0]  rvfi_rs2;
  logic [COMMIT_PORTS-1:0][4:0]   rvfi_rd;
  logic [COMMIT_PORTS-1:0][63:0]  rvfi_rd_wdata;
  logic                           csr_valid;
  logic [11:0]                    csr_addr;
  logic [63:0]                    csr_wdata;
  logic [63:0]                    satp;
  logic                           trace_valid;
  trace_packet_t                  trace_packet;

  cva6_rvfi_trace_adapter #(
      .COMMIT_PORTS(COMMIT_PORTS),
      .XLEN(64),
      .ILEN(32),
      .VLEN(64),
      .EVENT_QUEUE_DEPTH(16),
      .RELAX_SRET_TO_USER_CHECK(1'b1)
  ) dut (
      .clk_i(clk),
      .rst_ni(rst_n),
      .rvfi_valid_i(rvfi_valid),
      .rvfi_insn_i(rvfi_insn),
      .rvfi_trap_i(rvfi_trap),
      .rvfi_cause_i(rvfi_cause),
      .rvfi_tval_i(rvfi_tval),
      .rvfi_mode_i(rvfi_mode),
      .rvfi_compressed_i(rvfi_compressed),
      .rvfi_pc_rdata_i(rvfi_pc),
      .rvfi_pc_wdata_i(rvfi_pc_wdata),
      .rvfi_sret_to_user_i(rvfi_sret_to_user),
      .rvfi_rs1_rdata_i(rvfi_rs1),
      .rvfi_rs2_rdata_i(rvfi_rs2),
      .rvfi_rd_addr_i(rvfi_rd),
      .rvfi_rd_wdata_i(rvfi_rd_wdata),
      .csr_valid_i(csr_valid),
      .csr_addr_i(csr_addr),
      .csr_wdata_i(csr_wdata),
      .satp_i(satp),
      .trace_enable_retire_i(1'b1),
      .trace_enable_branch_i(1'b1),
      .trace_enable_jump_i(1'b1),
      .trace_enable_syscall_i(1'b1),
      .trace_enable_trap_i(1'b1),
      .trace_enable_context_i(1'b1),
      .trace_enable_marker_i(1'b1),
      .trace_enable_drop_i(1'b1),
      .trace_valid_o(trace_valid),
      .trace_packet_o(trace_packet)
  );

  tb_trace_sink sink (
      .clk_i(clk),
      .rst_ni(rst_n),
      .trace_valid_i(trace_valid),
      .trace_packet_i(trace_packet)
  );

  always #5 clk = ~clk;

  task automatic clear_inputs();
    rvfi_valid      = '0;
    rvfi_insn       = '0;
    rvfi_trap       = '0;
    rvfi_cause      = '0;
    rvfi_tval       = '0;
    rvfi_mode       = '0;
    rvfi_compressed = '0;
    rvfi_pc         = '0;
    rvfi_pc_wdata   = '0;
    rvfi_sret_to_user = '0;
    rvfi_rs1        = '0;
    rvfi_rs2        = '0;
    rvfi_rd         = '0;
    rvfi_rd_wdata   = '0;
    csr_valid       = 1'b0;
    csr_addr        = 12'h000;
    csr_wdata       = 64'd0;
    satp            = 64'd0;
  endtask

  initial begin
    clk = 1'b0;
    rst_n = 1'b0;
    clear_inputs();
    repeat (4) @(posedge clk);
    rst_n = 1'b1;
    @(posedge clk);

    clear_inputs();
    rvfi_valid[0] = 1'b1;
    rvfi_insn[0] = 32'h0010_0513;  // addi a0, zero, 1
    rvfi_mode[0] = TRACE_PRIV_M;
    rvfi_pc[0] = 64'h0000_0000_8000_0000;
    rvfi_rd[0] = 5'd10;
    rvfi_rd_wdata[0] = 64'd1;
    rvfi_valid[1] = 1'b1;
    rvfi_trap[1] = 1'b1;
    rvfi_insn[1] = 32'h0000_0073;  // ecall
    rvfi_cause[1] = 64'd8;
    rvfi_mode[1] = TRACE_PRIV_U;
    rvfi_pc[1] = 64'h0000_0000_8000_0004;
    @(posedge clk);

    clear_inputs();
    rvfi_trap[0] = 1'b1;
    rvfi_insn[0] = 32'hffff_ffff;
    rvfi_cause[0] = 64'd2;
    rvfi_tval[0] = 64'h0000_0000_ffff_ffff;
    rvfi_mode[0] = TRACE_PRIV_M;
    rvfi_pc[0] = 64'h0000_0000_8000_0010;
    @(posedge clk);

    clear_inputs();
    rvfi_valid[0] = 1'b1;
    rvfi_compressed[0] = 1'b1;
    rvfi_insn[0] = 32'h0000_c011;  // c.beqz x8, +4
    rvfi_rs1[0] = 64'd0;
    rvfi_mode[0] = TRACE_PRIV_M;
    rvfi_pc[0] = 64'h0000_0000_8000_0020;
    @(posedge clk);

    clear_inputs();
    rvfi_valid[0] = 1'b1;
    rvfi_compressed[0] = 1'b1;
    rvfi_insn[0] = 32'h0000_a011;  // c.j +4
    rvfi_mode[0] = TRACE_PRIV_M;
    rvfi_pc[0] = 64'h0000_0000_8000_0030;
    @(posedge clk);

    clear_inputs();
    rvfi_valid[0] = 1'b1;
    rvfi_compressed[0] = 1'b1;
    rvfi_insn[0] = 32'h0000_2505;  // c.addiw a0, 1; RV64C must not look like c.jal
    rvfi_mode[0] = TRACE_PRIV_M;
    rvfi_pc[0] = 64'h0000_0000_8000_0040;
    rvfi_rd[0] = 5'd10;
    rvfi_rd_wdata[0] = 64'd2;
    @(posedge clk);

    clear_inputs();
    rvfi_valid[0] = 1'b1;
    rvfi_insn[0] = 32'h0050_0513;  // addi a0, zero, 5
    rvfi_mode[0] = TRACE_PRIV_S;
    rvfi_pc[0] = 64'h0000_0000_8000_0050;
    rvfi_rd[0] = 5'd10;
    rvfi_rd_wdata[0] = 64'd5;
    rvfi_valid[1] = 1'b1;
    rvfi_insn[1] = 32'h1020_0073;  // sret
    rvfi_mode[1] = TRACE_PRIV_S;
    rvfi_pc[1] = 64'h0000_0000_8000_0054;
    rvfi_pc_wdata[1] = 64'h0000_0000_8000_0008;
    rvfi_sret_to_user[1] = 1'b0;
    @(posedge clk);

    clear_inputs();
    repeat (40) @(posedge clk);
    $finish;
  end

endmodule
