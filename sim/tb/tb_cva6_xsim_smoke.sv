module tb_cva6_xsim_smoke;

`ifndef RVMT_CVA6_MAX_CYCLES
`define RVMT_CVA6_MAX_CYCLES 50000
`endif

  localparam config_pkg::cva6_cfg_t CVA6Cfg = build_config_pkg::build_config(cva6_config_pkg::cva6_cfg);
  localparam int unsigned CLOCK_PERIOD = 20ns;
  localparam int unsigned RTC_CLOCK_PERIOD = 30_517ns;
  localparam int unsigned NUM_WORDS = 2**18;

  logic clk_i;
  logic rst_ni;
  logic rtc_i;
  logic [31:0] exit_o;
  logic [31:0] tohost_q;
  longint unsigned cycles;
  int unsigned max_cycles;
  string smoke_mem;

  ariane_testharness #(
      .CVA6Cfg(CVA6Cfg),
      .NUM_WORDS(NUM_WORDS),
      .InclSimDTM(1'b0),
      .StallRandomOutput(1'b0),
      .StallRandomInput(1'b0)
  ) dut (
      .clk_i(clk_i),
      .rtc_i(rtc_i),
      .rst_ni(rst_ni),
      .exit_o(exit_o)
  );

  initial begin
    if (!$value$plusargs("SMOKE_MEM=%s", smoke_mem)) begin
      smoke_mem = "cva6_smoke.mem";
    end
    $display("[rvmt] Preloading CVA6 xsim smoke image: %s", smoke_mem);
    $readmemh(smoke_mem, dut.i_sram.gen_cut[0].i_tc_sram_wrapper.i_tc_sram.init_val, 0, 1);
  end

  initial begin
    clk_i = 1'b0;
    forever begin
      #(CLOCK_PERIOD / 2) clk_i = ~clk_i;
    end
  end

  initial begin
    rtc_i = 1'b0;
    forever begin
      #(RTC_CLOCK_PERIOD / 2) rtc_i = 1'b1;
      #(RTC_CLOCK_PERIOD / 2) rtc_i = 1'b0;
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
        if (dut.rvfi_instr[port].valid && |dut.rvfi_instr[port].mem_wmask &&
            dut.rvfi_instr[port].mem_paddr == 64'h0000_0000_1000_0000 &&
            dut.rvfi_instr[port].mem_wdata[0]) begin
          tohost_q <= dut.rvfi_instr[port].mem_wdata[31:0];
        end
      end
    end
  end

  initial begin
    max_cycles = `RVMT_CVA6_MAX_CYCLES;
    if ($value$plusargs("MAX_CYCLES=%d", max_cycles)) begin
      $display("[rvmt] CVA6 xsim smoke max cycles: %0d", max_cycles);
    end

    wait (rst_ni);
    while (!tohost_q[0] && cycles < max_cycles) begin
      @(posedge clk_i);
    end

    if (!tohost_q[0]) begin
      $fatal(1, "[rvmt] CVA6 xsim smoke timed out after %0d cycles", max_cycles);
    end

    if ((tohost_q >> 1) != 0) begin
      $fatal(1, "[rvmt] CVA6 xsim smoke failed: tohost=%0d", (tohost_q >> 1));
    end

    $display("[rvmt] CVA6 xsim smoke PASS after %0d cycles", cycles);
    repeat (5) @(posedge clk_i);
    $finish;
  end

endmodule
