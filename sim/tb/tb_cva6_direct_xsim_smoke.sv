`include "axi/assign.svh"
`include "rvfi_types.svh"
`include "iti_types.svh"

module tb_cva6_direct_xsim_smoke;
  import ariane_pkg::*;

`ifndef RVMT_CVA6_MAX_CYCLES
`define RVMT_CVA6_MAX_CYCLES 50000
`endif

  localparam config_pkg::cva6_cfg_t CVA6Cfg = build_config_pkg::build_config(cva6_config_pkg::cva6_cfg);
  localparam int unsigned CLOCK_PERIOD = 20ns;
  localparam int unsigned NUM_WORDS = 2**18;
  localparam logic [CVA6Cfg.VLEN-1:0] BOOT_ADDR = 64'h0000_0000_8000_0000;
  localparam logic [CVA6Cfg.XLEN-1:0] HART_ID = '0;

  localparam type rvfi_instr_t = `RVFI_INSTR_T(CVA6Cfg);
  localparam type rvfi_csr_elmt_t = `RVFI_CSR_ELMT_T(CVA6Cfg);
  localparam type rvfi_csr_t = `RVFI_CSR_T(CVA6Cfg, rvfi_csr_elmt_t);
  localparam type rvfi_to_iti_t = `RVFI_TO_ITI_T(CVA6Cfg);
  localparam type rvfi_probes_instr_t = `RVFI_PROBES_INSTR_T(CVA6Cfg);
  localparam type rvfi_probes_csr_t = `RVFI_PROBES_CSR_T(CVA6Cfg);
  localparam type rvfi_probes_t = struct packed {
    rvfi_probes_csr_t csr;
    rvfi_probes_instr_t instr;
  };

  logic clk_i;
  logic rst_ni;
  logic req;
  logic we;
  logic [ariane_axi::AddrWidth-1:0] addr;
  logic [ariane_axi::DataWidth/8-1:0] be;
  logic [ariane_axi::UserWidth-1:0] wuser;
  logic [ariane_axi::UserWidth-1:0] ruser;
  logic [ariane_axi::DataWidth-1:0] wdata;
  logic [ariane_axi::DataWidth-1:0] rdata;
  logic [31:0] tohost_q;
  longint unsigned cycles;
  int unsigned max_cycles;
  string smoke_mem;

  ariane_axi::req_t axi_ariane_req;
  ariane_axi::resp_t axi_ariane_resp;
  rvfi_probes_t rvfi_probes;
  rvfi_instr_t [CVA6Cfg.NrCommitPorts-1:0] rvfi_instr;
  rvfi_to_iti_t rvfi_to_iti;
  rvfi_csr_t rvfi_csr;

  logic [CVA6Cfg.NrCommitPorts-1:0] rvmt_rvfi_valid;
  logic [CVA6Cfg.NrCommitPorts-1:0][config_pkg::ILEN-1:0] rvmt_rvfi_insn;
  logic [CVA6Cfg.NrCommitPorts-1:0] rvmt_rvfi_trap;
  logic [CVA6Cfg.NrCommitPorts-1:0][CVA6Cfg.XLEN-1:0] rvmt_rvfi_cause;
  logic [CVA6Cfg.NrCommitPorts-1:0][CVA6Cfg.XLEN-1:0] rvmt_rvfi_tval;
  logic [CVA6Cfg.NrCommitPorts-1:0][1:0] rvmt_rvfi_mode;
  logic [CVA6Cfg.NrCommitPorts-1:0] rvmt_rvfi_compressed;
  logic [CVA6Cfg.NrCommitPorts-1:0][CVA6Cfg.VLEN-1:0] rvmt_rvfi_pc;
  logic [CVA6Cfg.NrCommitPorts-1:0][CVA6Cfg.XLEN-1:0] rvmt_rvfi_rs1;
  logic [CVA6Cfg.NrCommitPorts-1:0][CVA6Cfg.XLEN-1:0] rvmt_rvfi_rs2;
  logic [CVA6Cfg.NrCommitPorts-1:0][4:0] rvmt_rvfi_rd;
  logic [CVA6Cfg.NrCommitPorts-1:0][CVA6Cfg.XLEN-1:0] rvmt_rvfi_rd_wdata;
  trace_pkg::trace_packet_t rvmt_trace_packet;
  logic rvmt_trace_valid;

  AXI_BUS #(
    .AXI_ADDR_WIDTH ( ariane_axi::AddrWidth ),
    .AXI_DATA_WIDTH ( ariane_axi::DataWidth ),
    .AXI_ID_WIDTH   ( ariane_axi::IdWidth   ),
    .AXI_USER_WIDTH ( ariane_axi::UserWidth )
  ) mem_bus();

  `AXI_ASSIGN_FROM_REQ(mem_bus, axi_ariane_req)
  `AXI_ASSIGN_TO_RESP(axi_ariane_resp, mem_bus)

  ariane #(
    .CVA6Cfg(CVA6Cfg),
    .rvfi_probes_instr_t(rvfi_probes_instr_t),
    .rvfi_probes_csr_t(rvfi_probes_csr_t),
    .rvfi_probes_t(rvfi_probes_t)
  ) i_ariane (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .boot_addr_i(BOOT_ADDR),
    .hart_id_i(HART_ID),
    .irq_i('0),
    .ipi_i('0),
    .time_irq_i('0),
    .debug_req_i('0),
    .rvfi_probes_o(rvfi_probes),
    .noc_req_o(axi_ariane_req),
    .noc_resp_i(axi_ariane_resp)
  );

  axi2mem #(
    .AXI_ID_WIDTH(ariane_axi::IdWidth),
    .AXI_ADDR_WIDTH(ariane_axi::AddrWidth),
    .AXI_DATA_WIDTH(ariane_axi::DataWidth),
    .AXI_USER_WIDTH(ariane_axi::UserWidth)
  ) i_axi2mem (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .slave(mem_bus),
    .req_o(req),
    .we_o(we),
    .addr_o(addr),
    .be_o(be),
    .user_o(wuser),
    .data_o(wdata),
    .user_i(ruser),
    .data_i(rdata)
  );

  sram #(
    .DATA_WIDTH(ariane_axi::DataWidth),
    .USER_WIDTH(ariane_axi::UserWidth),
    .USER_EN(CVA6Cfg.AXI_USER_EN),
    .SIM_INIT("zeros"),
    .NUM_WORDS(NUM_WORDS)
  ) i_sram (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .req_i(req),
    .we_i(we),
    .addr_i(addr[$clog2(NUM_WORDS)-1+$clog2(ariane_axi::DataWidth/8):$clog2(ariane_axi::DataWidth/8)]),
    .wuser_i(wuser),
    .wdata_i(wdata),
    .be_i(be),
    .ruser_o(ruser),
    .rdata_o(rdata)
  );

  cva6_rvfi #(
    .CVA6Cfg(CVA6Cfg),
    .rvfi_instr_t(rvfi_instr_t),
    .rvfi_csr_t(rvfi_csr_t),
    .rvfi_probes_instr_t(rvfi_probes_instr_t),
    .rvfi_probes_csr_t(rvfi_probes_csr_t),
    .rvfi_probes_t(rvfi_probes_t),
    .rvfi_to_iti_t(rvfi_to_iti_t)
  ) i_cva6_rvfi (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .rvfi_probes_i(rvfi_probes),
    .rvfi_instr_o(rvfi_instr),
    .rvfi_to_iti_o(rvfi_to_iti),
    .rvfi_csr_o(rvfi_csr)
  );

  for (genvar port = 0; port < CVA6Cfg.NrCommitPorts; port++) begin : gen_rvfi_map
    assign rvmt_rvfi_valid[port] = rvfi_instr[port].valid[0];
    assign rvmt_rvfi_insn[port] = rvfi_instr[port].insn[config_pkg::ILEN-1:0];
    assign rvmt_rvfi_trap[port] = rvfi_instr[port].trap[0];
    assign rvmt_rvfi_cause[port] = rvfi_instr[port].cause[CVA6Cfg.XLEN-1:0];
    assign rvmt_rvfi_tval[port] = rvfi_to_iti.tval;
    assign rvmt_rvfi_mode[port] = rvfi_instr[port].mode[1:0];
    assign rvmt_rvfi_compressed[port] = rvfi_to_iti.is_compressed[port];
    assign rvmt_rvfi_pc[port] = rvfi_instr[port].pc_rdata[CVA6Cfg.VLEN-1:0];
    assign rvmt_rvfi_rs1[port] = rvfi_instr[port].rs1_rdata[CVA6Cfg.XLEN-1:0];
    assign rvmt_rvfi_rs2[port] = rvfi_instr[port].rs2_rdata[CVA6Cfg.XLEN-1:0];
    assign rvmt_rvfi_rd[port] = rvfi_instr[port].rd_addr[4:0];
    assign rvmt_rvfi_rd_wdata[port] = rvfi_instr[port].rd_wdata[CVA6Cfg.XLEN-1:0];
  end

  cva6_rvfi_trace_adapter #(
    .COMMIT_PORTS(CVA6Cfg.NrCommitPorts),
    .XLEN(CVA6Cfg.XLEN),
    .ILEN(config_pkg::ILEN),
    .VLEN(CVA6Cfg.VLEN)
  ) i_trace_adapter (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .rvfi_valid_i(rvmt_rvfi_valid),
    .rvfi_insn_i(rvmt_rvfi_insn),
    .rvfi_trap_i(rvmt_rvfi_trap),
    .rvfi_cause_i(rvmt_rvfi_cause),
    .rvfi_tval_i(rvmt_rvfi_tval),
    .rvfi_mode_i(rvmt_rvfi_mode),
    .rvfi_compressed_i(rvmt_rvfi_compressed),
    .rvfi_pc_rdata_i(rvmt_rvfi_pc),
    .rvfi_rs1_rdata_i(rvmt_rvfi_rs1),
    .rvfi_rs2_rdata_i(rvmt_rvfi_rs2),
    .rvfi_rd_addr_i(rvmt_rvfi_rd),
    .rvfi_rd_wdata_i(rvmt_rvfi_rd_wdata),
    .csr_valid_i(|rvfi_csr.satp.wmask),
    .csr_addr_i(12'h180),
    .csr_wdata_i(rvfi_csr.satp.wdata),
    .satp_i(rvfi_csr.satp.wdata),
    .trace_valid_o(rvmt_trace_valid),
    .trace_packet_o(rvmt_trace_packet)
  );

  tb_trace_sink i_trace_sink (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .trace_valid_i(rvmt_trace_valid),
    .trace_packet_i(rvmt_trace_packet)
  );

  initial begin
    if (!$value$plusargs("SMOKE_MEM=%s", smoke_mem)) begin
      smoke_mem = "cva6_smoke.mem";
    end
    $display("[rvmt] Preloading direct CVA6 smoke image: %s", smoke_mem);
    $readmemh(smoke_mem, i_sram.gen_cut[0].i_tc_sram_wrapper.i_tc_sram.init_val, 0, 1);
  end

  initial begin
    clk_i = 1'b0;
    forever begin
      #(CLOCK_PERIOD / 2) clk_i = ~clk_i;
    end
  end

  initial begin
    rst_ni = 1'b0;
    repeat (8) @(posedge clk_i);
    rst_ni = 1'b1;
  end

  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      cycles <= 0;
      tohost_q <= 32'h0;
    end else begin
      cycles <= cycles + 1;
      for (int port = 0; port < CVA6Cfg.NrCommitPorts; port++) begin
        if (rvfi_instr[port].valid && |rvfi_instr[port].mem_wmask &&
            rvfi_instr[port].mem_paddr == 64'h0000_0000_1000_0000 &&
            rvfi_instr[port].mem_wdata[0]) begin
          tohost_q <= rvfi_instr[port].mem_wdata[31:0];
        end
      end
    end
  end

  initial begin
    max_cycles = `RVMT_CVA6_MAX_CYCLES;
    if ($value$plusargs("MAX_CYCLES=%d", max_cycles)) begin
      $display("[rvmt] Direct CVA6 xsim smoke max cycles: %0d", max_cycles);
    end

    wait (rst_ni);
    while (!tohost_q[0] && cycles < max_cycles) begin
      @(posedge clk_i);
    end

    if (!tohost_q[0]) begin
      $fatal(1, "[rvmt] Direct CVA6 xsim smoke timed out after %0d cycles", max_cycles);
    end

    if ((tohost_q >> 1) != 0) begin
      $fatal(1, "[rvmt] Direct CVA6 xsim smoke failed: tohost=%0d", (tohost_q >> 1));
    end

    $display("[rvmt] Direct CVA6 xsim smoke PASS after %0d cycles", cycles);
    repeat (5) @(posedge clk_i);
    $finish;
  end

endmodule
