`timescale 1ns/1ps

module tb_trace_filter
  import trace_pkg::*;
;

  logic trace_valid_i;
  trace_packet_t trace_packet_i;
  logic enable_retire;
  logic enable_branch;
  logic enable_jump;
  logic enable_syscall;
  logic enable_trap;
  logic enable_context;
  logic enable_marker;
  logic enable_drop;
  logic pc_filter_enable;
  logic [63:0] pc_start;
  logic [63:0] pc_end;
  logic priv_filter_enable;
  logic [3:0] priv_mask;
  logic trace_valid_o;
  trace_packet_t trace_packet_o;

  trace_filter dut (
      .trace_valid_i(trace_valid_i),
      .trace_packet_i(trace_packet_i),
      .enable_retire_i(enable_retire),
      .enable_branch_i(enable_branch),
      .enable_jump_i(enable_jump),
      .enable_syscall_i(enable_syscall),
      .enable_trap_i(enable_trap),
      .enable_context_i(enable_context),
      .enable_marker_i(enable_marker),
      .enable_drop_i(enable_drop),
      .pc_filter_enable_i(pc_filter_enable),
      .pc_start_i(pc_start),
      .pc_end_i(pc_end),
      .priv_filter_enable_i(priv_filter_enable),
      .priv_mask_i(priv_mask),
      .trace_valid_o(trace_valid_o),
      .trace_packet_o(trace_packet_o)
  );

  function automatic trace_packet_t make_packet(
      input trace_evt_e evt,
      input logic [63:0] pc,
      input logic [1:0] priv,
      input logic [63:0] value
  );
    make_packet = trace_null_packet();
    make_packet.valid = 1'b1;
    make_packet.evt = evt;
    make_packet.pc = pc;
    make_packet.priv = priv;
    make_packet.value = value;
    make_packet.target = value;
    make_packet.cause = value;
    make_packet.a7 = value;
  endfunction

  task automatic expect_valid(input string label, input logic expected_valid);
    begin
      #1;
      if (trace_valid_o !== expected_valid) begin
        $fatal(1, "%s: expected trace_valid_o=%0b got %0b", label, expected_valid, trace_valid_o);
      end
    end
  endtask

  initial begin
    trace_valid_i = 1'b1;
    enable_retire = 1'b1;
    enable_branch = 1'b1;
    enable_jump = 1'b1;
    enable_syscall = 1'b1;
    enable_trap = 1'b1;
    enable_context = 1'b1;
    enable_marker = 1'b1;
    enable_drop = 1'b1;
    pc_filter_enable = 1'b1;
    pc_start = 64'h0000_0000_8000_0200;
    pc_end = 64'h0000_0000_8000_02ff;
    priv_filter_enable = 1'b1;
    priv_mask = 4'b0010;

    trace_packet_i = make_packet(EVT_RETIRE, 64'h0000_0000_0100_0100, TRACE_PRIV_M, 64'd0);
    expect_valid("out-of-range retire is filtered", 1'b0);

    trace_packet_i = make_packet(EVT_BRANCH, 64'h0000_0000_8000_0220, TRACE_PRIV_S, 64'h8000_0230);
    expect_valid("in-range branch passes", 1'b1);

    trace_packet_i = make_packet(EVT_BRANCH, 64'h0000_0000_8000_0120, TRACE_PRIV_S, 64'h8000_0130);
    expect_valid("out-of-range branch is filtered", 1'b0);

    trace_packet_i = make_packet(EVT_MARKER, 64'h0000_0000_0100_0100, TRACE_PRIV_U, 64'h0000_0000_b000_0f00);
    expect_valid("marker bypasses pc and priv filters", 1'b1);
    if (trace_packet_o.evt !== EVT_MARKER || trace_packet_o.value !== 64'h0000_0000_b000_0f00) begin
      $fatal(1, "marker packet was not preserved");
    end

    enable_marker = 1'b0;
    expect_valid("disabled marker is filtered", 1'b0);
    enable_marker = 1'b1;

    trace_packet_i = make_packet(EVT_DROP, 64'h0000_0000_0100_0200, TRACE_PRIV_M, 64'hd00d);
    expect_valid("drop bypasses pc and priv filters", 1'b1);

    $display("[PASS] trace_filter synthetic test finished");
    $finish;
  end

endmodule
