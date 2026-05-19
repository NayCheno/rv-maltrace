module tb_cva6_xsim_smoke;

`ifndef RVMT_CVA6_MAX_CYCLES
`define RVMT_CVA6_MAX_CYCLES 50000
`endif

  localparam config_pkg::cva6_cfg_t CVA6Cfg = build_config_pkg::build_config(cva6_config_pkg::cva6_cfg);
  localparam int unsigned CLOCK_PERIOD = 20ns;
  localparam int unsigned RTC_CLOCK_PERIOD = 30_517ns;
  localparam int unsigned NUM_WORDS = 2**18;
  localparam logic [63:0] UART_TOHOST_ADDR = 64'h0000_0000_1000_0000;
  localparam logic [63:0] DRAM_TOHOST_ADDR = ariane_soc::DRAMBase + 64'h20;
  localparam logic [63:0] EBREAK_PC = ariane_soc::DRAMBase + 64'h4;
  localparam logic [31:0] EBREAK_INSN = 32'h0010_0073;
  localparam logic [63:0] EBREAK_CAUSE = 64'd3;

  logic clk_i;
  logic rst_ni;
  logic rtc_i;
  logic [31:0] exit_o;
  logic [31:0] tohost_q;
  longint unsigned cycles;
  longint unsigned observed_retire_count;
  int unsigned max_cycles;
  int unsigned pass_retire_count;
  int unsigned pass_finish_countdown;
  string smoke_mem;
  bit debug_progress;
  bit store_path_only;
  bit pass_retire_done;
  bit force_fs_dirty;

  ariane_testharness #(
      .CVA6Cfg(CVA6Cfg),
      .NUM_WORDS(NUM_WORDS),
      .BOOT_ADDR(ariane_soc::DRAMBase),
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
    $readmemh(smoke_mem, dut.i_sram.gen_cut[0].i_tc_sram_wrapper.i_tc_sram.init_val, 0, NUM_WORDS - 1);
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
      observed_retire_count <= 0;
      pass_finish_countdown <= 0;
      pass_retire_done <= 1'b0;
      tohost_q <= 32'h0;
    end else begin
      cycles <= cycles + 1;
      if (pass_retire_done) begin
        if (pass_finish_countdown == 0) begin
          $display("[rvmt] CVA6 xsim smoke PASS after %0d cycles", cycles);
          $finish;
        end else begin
          pass_finish_countdown <= pass_finish_countdown - 1;
        end
      end
      if (debug_progress && dut.axi_ariane_req.ar_valid) begin
        $display(
            "[rvmt-debug] cycle=%0d core_ar valid ready=%0b addr=%016h len=%0d size=%0d id=%0h",
            cycles,
            dut.axi_ariane_resp.ar_ready,
            dut.axi_ariane_req.ar.addr,
            dut.axi_ariane_req.ar.len,
            dut.axi_ariane_req.ar.size,
            dut.axi_ariane_req.ar.id
        );
      end
      if (debug_progress && dut.axi_ariane_resp.r_valid) begin
        $display(
            "[rvmt-debug] cycle=%0d core_r ready=%0b data=%016h last=%0b resp=%0d id=%0h",
            cycles,
            dut.axi_ariane_req.r_ready,
            dut.axi_ariane_resp.r.data,
            dut.axi_ariane_resp.r.last,
            dut.axi_ariane_resp.r.resp,
            dut.axi_ariane_resp.r.id
        );
      end
      if (debug_progress && dut.axi_ariane_req.aw_valid) begin
        $display(
            "[rvmt-debug] cycle=%0d core_aw valid ready=%0b addr=%016h len=%0d size=%0d id=%0h",
            cycles,
            dut.axi_ariane_resp.aw_ready,
            dut.axi_ariane_req.aw.addr,
            dut.axi_ariane_req.aw.len,
            dut.axi_ariane_req.aw.size,
            dut.axi_ariane_req.aw.id
        );
      end
      if (debug_progress && dut.axi_ariane_req.w_valid) begin
        $display(
            "[rvmt-debug] cycle=%0d core_w valid ready=%0b data=%016h strb=%02h last=%0b",
            cycles,
            dut.axi_ariane_resp.w_ready,
            dut.axi_ariane_req.w.data,
            dut.axi_ariane_req.w.strb,
            dut.axi_ariane_req.w.last
        );
      end
      if (debug_progress && dut.axi_ariane_resp.b_valid) begin
        $display(
            "[rvmt-debug] cycle=%0d core_b ready=%0b resp=%0d id=%0h",
            cycles,
            dut.axi_ariane_req.b_ready,
            dut.axi_ariane_resp.b.resp,
            dut.axi_ariane_resp.b.id
        );
      end
      for (int port = 0; port < CVA6Cfg.NrCommitPorts; port++) begin
        if (debug_progress && dut.rvfi_instr[port].valid) begin
          $display(
              "[rvmt-debug] cycle=%0d retire port=%0d pc=%016h next=%016h insn=%08h trap=%0b cause=%016h",
              cycles,
              port,
              dut.rvfi_instr[port].pc_rdata,
              dut.rvfi_instr[port].pc_wdata,
              dut.rvfi_instr[port].insn[31:0],
              dut.rvfi_instr[port].trap[0],
              dut.rvfi_instr[port].cause
          );
        end
        if (pass_retire_count != 0 && !pass_retire_done && dut.rvfi_instr[port].valid) begin
          if (dut.rvfi_instr[port].trap[0]) begin
            $fatal(
                1,
                "[rvmt] CVA6 full-SoC retire-count gate trapped at pc=%016h insn=%08h cause=%016h",
                dut.rvfi_instr[port].pc_rdata,
                dut.rvfi_instr[port].insn[31:0],
                dut.rvfi_instr[port].cause
            );
          end
          observed_retire_count <= observed_retire_count + 1;
          if (observed_retire_count + 1 >= pass_retire_count) begin
            $display(
                "[rvmt] CVA6 full-SoC retire-count PASS after %0d retired instructions at cycle %0d",
                pass_retire_count,
                cycles
            );
            tohost_q <= 32'h1;
            pass_retire_done <= 1'b1;
            pass_finish_countdown <= 5;
          end
        end
        if (dut.rvfi_instr[port].valid && |dut.rvfi_instr[port].mem_wmask &&
            (dut.rvfi_instr[port].mem_paddr == UART_TOHOST_ADDR ||
             dut.rvfi_instr[port].mem_paddr == DRAM_TOHOST_ADDR)) begin
          if (store_path_only) begin
            $display(
                "[rvmt] CVA6 full-SoC store-path observed addr=%016h data=%016h strb=%016h",
                dut.rvfi_instr[port].mem_paddr,
                dut.rvfi_instr[port].mem_wdata,
                dut.rvfi_instr[port].mem_wmask
            );
            tohost_q <= 32'h1;
            $display("[rvmt] CVA6 xsim smoke PASS after %0d cycles", cycles);
            $finish;
          end else begin
            $display(
                "[rvmt] CVA6 full-SoC tohost observed addr=%016h data=%016h strb=%016h",
                dut.rvfi_instr[port].mem_paddr,
                dut.rvfi_instr[port].mem_wdata,
                dut.rvfi_instr[port].mem_wmask
            );
            tohost_q <= dut.rvfi_instr[port].mem_wdata[0] ? dut.rvfi_instr[port].mem_wdata[31:0] : 32'h1;
            $display("[rvmt] CVA6 xsim smoke PASS after %0d cycles", cycles);
            $finish;
          end
        end
        if (dut.rvfi_instr[port].valid && dut.rvfi_instr[port].insn[31:0] == EBREAK_INSN) begin
          tohost_q <= 32'h1;
        end
        if (dut.rvfi_instr[port].trap[0] &&
            dut.rvfi_instr[port].pc_rdata == EBREAK_PC &&
            dut.rvfi_instr[port].cause[CVA6Cfg.XLEN-1:0] == EBREAK_CAUSE[CVA6Cfg.XLEN-1:0]) begin
          tohost_q <= 32'h1;
        end
      end
    end
  end

  initial begin
    max_cycles = `RVMT_CVA6_MAX_CYCLES;
    pass_retire_count = 0;
    debug_progress = $test$plusargs("RVMT_DEBUG_PROGRESS");
    store_path_only = $test$plusargs("RVMT_STORE_PATH_ONLY");
    if ($value$plusargs("MAX_CYCLES=%d", max_cycles)) begin
      $display("[rvmt] CVA6 xsim smoke max cycles: %0d", max_cycles);
    end
    if ($value$plusargs("RVMT_PASS_RETIRE_COUNT=%d", pass_retire_count)) begin
      $display("[rvmt] CVA6 xsim smoke pass retire count: %0d", pass_retire_count);
    end
    if ($test$plusargs("RVMT_PASS_RETIRE_COUNT_1")) begin
      pass_retire_count = 1;
      $display("[rvmt] CVA6 xsim smoke pass retire count: %0d", pass_retire_count);
    end
    if ($test$plusargs("RVMT_PASS_RETIRE_COUNT_2")) begin
      pass_retire_count = 2;
      $display("[rvmt] CVA6 xsim smoke pass retire count: %0d", pass_retire_count);
    end
    if ($test$plusargs("RVMT_PASS_RETIRE_COUNT_3")) begin
      pass_retire_count = 3;
      $display("[rvmt] CVA6 xsim smoke pass retire count: %0d", pass_retire_count);
    end
    if ($test$plusargs("RVMT_PASS_RETIRE_COUNT_4")) begin
      pass_retire_count = 4;
      $display("[rvmt] CVA6 xsim smoke pass retire count: %0d", pass_retire_count);
    end
    if ($test$plusargs("RVMT_PASS_RETIRE_COUNT_5")) begin
      pass_retire_count = 5;
      $display("[rvmt] CVA6 xsim smoke pass retire count: %0d", pass_retire_count);
    end
    force_fs_dirty = $test$plusargs("RVMT_FORCE_FS_DIRTY");
    if (force_fs_dirty) begin
      force dut.i_ariane.i_cva6.fs = riscv::Dirty;
      $display("[rvmt] CVA6 xsim smoke forcing mstatus.FS visible state to Dirty");
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
