`timescale 1ns/1ps

module tb_trace_bram_ring
  import trace_pkg::*;
;

  localparam int unsigned DEPTH = 4;
  localparam int unsigned ADDR_WIDTH = 2;

  logic clk;
  logic rst_n;
  logic clear;
  logic capture_enable;
  logic freeze;
  logic trace_valid;
  trace_packet_t trace_packet;
  logic [ADDR_WIDTH-1:0] dump_index;
  trace_compact_record_t dump_record;
  logic dump_valid;
  logic [ADDR_WIDTH-1:0] write_index;
  logic [ADDR_WIDTH-1:0] oldest_index;
  logic [31:0] next_sequence;
  logic [63:0] event_count;
  logic [63:0] captured_count;
  logic [63:0] dropped_count;
  logic [63:0] wrap_count;
  logic [63:0] start_timestamp;
  logic [63:0] end_timestamp;
  logic full;

  trace_bram_ring #(
      .DEPTH(DEPTH),
      .ADDR_WIDTH(ADDR_WIDTH)
  ) dut (
      .clk_i(clk),
      .rst_ni(rst_n),
      .clear_i(clear),
      .capture_enable_i(capture_enable),
      .freeze_i(freeze),
      .trace_valid_i(trace_valid),
      .trace_packet_i(trace_packet),
      .dump_index_i(dump_index),
      .dump_record_o(dump_record),
      .dump_valid_o(dump_valid),
      .write_index_o(write_index),
      .oldest_index_o(oldest_index),
      .next_sequence_o(next_sequence),
      .event_count_o(event_count),
      .captured_count_o(captured_count),
      .dropped_count_o(dropped_count),
      .wrap_count_o(wrap_count),
      .start_timestamp_o(start_timestamp),
      .end_timestamp_o(end_timestamp),
      .full_o(full)
  );

  initial begin
    clk = 1'b0;
    forever #5 clk = ~clk;
  end

  function automatic trace_packet_t make_packet(
      input trace_evt_e evt,
      input logic [63:0] cycle,
      input logic [63:0] pc,
      input logic [63:0] primary
  );
    make_packet = trace_null_packet();
    make_packet.valid = 1'b1;
    make_packet.evt = evt;
    make_packet.cycle = cycle;
    make_packet.pc = pc;
    make_packet.instr = 32'h00000073;
    make_packet.value = primary;
    make_packet.target = primary;
    make_packet.cause = primary;
    make_packet.a7 = primary;
    make_packet.syscall_id = primary + 64'h100;
    make_packet.a0 = primary + 64'h200;
  endfunction

  task automatic push_packet(input trace_packet_t packet);
    begin
      @(negedge clk);
      trace_packet = packet;
      trace_valid = 1'b1;
      @(negedge clk);
      trace_valid = 1'b0;
      trace_packet = trace_null_packet();
    end
  endtask

  task automatic push_packet_with_clear(input trace_packet_t packet);
    begin
      @(negedge clk);
      clear = 1'b1;
      trace_packet = packet;
      trace_valid = 1'b1;
      @(negedge clk);
      clear = 1'b0;
      trace_valid = 1'b0;
      trace_packet = trace_null_packet();
    end
  endtask

  task automatic load_dump(input logic [ADDR_WIDTH-1:0] index);
    begin
      dump_index = index;
      @(negedge clk);
    end
  endtask

  task automatic expect_true(input bit condition, input string message);
    begin
      if (!condition) begin
        $fatal(1, "[FAIL] %s", message);
      end
    end
  endtask

  task automatic reset_ring();
    begin
      clear = 1'b0;
      capture_enable = 1'b1;
      freeze = 1'b0;
      trace_valid = 1'b0;
      trace_packet = trace_null_packet();
      dump_index = '0;
      rst_n = 1'b0;
      repeat (4) @(negedge clk);
      rst_n = 1'b1;
      repeat (2) @(negedge clk);
    end
  endtask

  initial begin
    reset_ring();

    push_packet(make_packet(EVT_MARKER, 64'd10, 64'h1000, 64'hb0000001));
    push_packet(make_packet(EVT_SYSCALL_ENTRY, 64'd11, 64'h1004, 64'd64));
    push_packet(make_packet(EVT_SYSCALL_RET, 64'd20, 64'h2000, 64'd1));
    @(negedge clk);

    expect_true(event_count == 64'd3, "event_count after first window");
    expect_true(captured_count == 64'd3, "captured_count after first window");
    expect_true(dropped_count == 64'd0, "dropped_count after first window");
    expect_true(wrap_count == 64'd0, "wrap_count after first window");
    expect_true(start_timestamp == 64'd10, "start timestamp");
    expect_true(end_timestamp == 64'd20, "end timestamp");
    expect_true(!full, "ring should not be full after three records");

    load_dump(2'd0);
    expect_true(dump_valid, "dump index 0 must be valid");
    expect_true(dump_record.seq == 32'd0, "first record sequence");
    expect_true(dump_record.evt == EVT_MARKER, "first record event");
    expect_true(dump_record.primary == 32'hb0000001, "marker primary field");

    @(negedge clk);
    clear = 1'b1;
    @(negedge clk);
    clear = 1'b0;
    @(negedge clk);
    expect_true(event_count == 64'd0, "clear resets event count");
    expect_true(captured_count == 64'd0, "clear resets captured count");

    push_packet_with_clear(make_packet(EVT_MARKER, 64'd30, 64'h4000, 64'hb0000002));
    push_packet(make_packet(EVT_SYSCALL_ENTRY, 64'd31, 64'h4004, 64'd64));
    @(negedge clk);

    expect_true(event_count == 64'd2, "clear plus marker starts a fresh window");
    expect_true(captured_count == 64'd2, "clear plus marker retains marker record");
    expect_true(dropped_count == 64'd0, "clear plus marker resets dropped count");
    expect_true(wrap_count == 64'd0, "clear plus marker resets wrap count");
    expect_true(start_timestamp == 64'd30, "clear plus marker start timestamp");
    expect_true(end_timestamp == 64'd31, "clear plus marker end timestamp");

    load_dump(2'd0);
    expect_true(dump_valid, "dump index 0 valid after clear plus marker");
    expect_true(dump_record.seq == 32'd0, "clear plus marker sequence");
    expect_true(dump_record.evt == EVT_MARKER, "clear plus marker event");
    expect_true(dump_record.primary == 32'hb0000002, "clear plus marker primary");

    @(negedge clk);
    clear = 1'b1;
    @(negedge clk);
    clear = 1'b0;
    @(negedge clk);

    for (int unsigned i = 0; i < 10; i++) begin
      push_packet(make_packet(EVT_BRANCH, 64'd100 + i, 64'h3000 + i, 64'h4000 + i));
    end
    @(negedge clk);

    expect_true(event_count == 64'd10, "event_count after overwrite run");
    expect_true(captured_count == 64'd4, "captured_count saturates at depth");
    expect_true(dropped_count == 64'd6, "dropped_count records overwritten entries");
    expect_true(wrap_count == 64'd2, "wrap_count after ten writes into depth four");
    expect_true(full, "ring should be full after overwrite run");
    expect_true(oldest_index == 2'd2, "oldest index points at write pointer when full");
    expect_true(start_timestamp == 64'd100, "start timestamp after clear");
    expect_true(end_timestamp == 64'd109, "end timestamp after overwrite run");

    load_dump(oldest_index);
    expect_true(dump_valid, "oldest index must be valid");
    expect_true(dump_record.seq == 32'd6, "oldest retained sequence after overwrite");
    expect_true(dump_record.primary == 32'h00004006, "oldest retained primary after overwrite");

    freeze = 1'b1;
    push_packet(make_packet(EVT_TRAP, 64'd200, 64'h5000, 64'd2));
    @(negedge clk);
    expect_true(event_count == 64'd10, "freeze prevents capture");

    push_packet_with_clear(make_packet(EVT_MARKER, 64'd210, 64'h6000, 64'hb0000003));
    @(negedge clk);
    expect_true(event_count == 64'd1, "clear plus marker restarts while frozen");
    expect_true(captured_count == 64'd1, "clear plus marker captures while frozen");
    expect_true(dropped_count == 64'd0, "clear plus marker resets drops while frozen");
    expect_true(wrap_count == 64'd0, "clear plus marker resets wraps while frozen");
    expect_true(write_index == 2'd1, "clear plus marker advances write pointer while frozen");
    expect_true(start_timestamp == 64'd210, "clear plus marker frozen start timestamp");
    expect_true(end_timestamp == 64'd210, "clear plus marker frozen end timestamp");

    load_dump(2'd0);
    expect_true(dump_valid, "dump index 0 valid after frozen clear plus marker");
    expect_true(dump_record.seq == 32'd0, "frozen clear plus marker sequence");
    expect_true(dump_record.evt == EVT_MARKER, "frozen clear plus marker event");
    expect_true(dump_record.primary == 32'hb0000003, "frozen clear plus marker primary");

    $display("[PASS] trace_bram_ring synthetic test finished");
    $finish;
  end

endmodule
