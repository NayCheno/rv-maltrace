`timescale 1ns/1ps

module tb_trace_uart_stream_sink
  import trace_pkg::*;
;

  localparam int unsigned CLK_HZ = 50_000_000;
  localparam int unsigned BAUD = 12_000_000;
  localparam real CLK_HALF_NS = 10.0;
  localparam real UART_BIT_NS = 1_000_000_000.0 / BAUD;
  localparam int unsigned MAX_RX_BYTES = 2048;

  logic clk;
  logic rst_n;
  logic trace_valid;
  trace_packet_t trace_packet;
  logic tx;
  logic active;
  logic [63:0] accepted_count;
  logic [63:0] dropped_count;
  logic done;

  byte unsigned rx_bytes [MAX_RX_BYTES];
  int unsigned rx_count;

  trace_uart_stream_sink #(
      .CLK_HZ(CLK_HZ),
      .BAUD(BAUD),
      .FIFO_DEPTH(64)
  ) dut (
      .clk_i(clk),
      .rst_ni(rst_n),
      .trace_valid_i(trace_valid),
      .trace_packet_i(trace_packet),
      .tx_o(tx),
      .active_o(active),
      .accepted_count_o(accepted_count),
      .dropped_count_o(dropped_count),
      .done_o(done)
  );

  initial begin
    clk = 1'b0;
    forever #CLK_HALF_NS clk = ~clk;
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

  task automatic uart_read_byte(output byte unsigned data);
    begin
      data = 8'h00;
      wait (tx == 1'b0);
      #(UART_BIT_NS * 1.5);
      for (int unsigned bit_index = 0; bit_index < 8; bit_index++) begin
        data[bit_index] = tx;
        #(UART_BIT_NS);
      end
      if (tx !== 1'b1) begin
        $fatal(1, "[FAIL] UART stop bit was not high");
      end
      #(UART_BIT_NS * 0.4);
    end
  endtask

  task automatic uart_receiver();
    byte unsigned data;
    begin
      forever begin
        uart_read_byte(data);
        if (rx_count < MAX_RX_BYTES) begin
          rx_bytes[rx_count] = data;
        end
        rx_count++;
      end
    end
  endtask

  function automatic bit has_magic_at(input int unsigned index);
    has_magic_at = index + 3 < rx_count &&
                   rx_bytes[index + 0] == 8'h52 &&
                   rx_bytes[index + 1] == 8'h56 &&
                   rx_bytes[index + 2] == 8'h4d &&
                   rx_bytes[index + 3] == 8'h54;
  endfunction

  function automatic longint unsigned load_le(input int unsigned index, input int unsigned width);
    longint unsigned value;
    begin
      value = 64'd0;
      for (int unsigned byte_index = 0; byte_index < width; byte_index++) begin
        value |= longint'(rx_bytes[index + byte_index]) << (8 * byte_index);
      end
      load_le = value;
    end
  endfunction

  task automatic expect_true(input bit condition, input string message);
    begin
      if (!condition) begin
        $fatal(1, "[FAIL] %s", message);
      end
    end
  endtask

  task automatic check_frames();
    int unsigned index;
    int unsigned magic_count;
    int unsigned data_frames;
    int unsigned data_records;
    int unsigned status_frames;
    int unsigned payload_len;
    longint unsigned status_accepted;
    longint unsigned status_dropped;
    longint unsigned status_next_sequence;
    longint unsigned status_word;
    begin
      index = 0;
      magic_count = 0;
      data_frames = 0;
      data_records = 0;
      status_frames = 0;
      status_accepted = 64'd0;
      status_dropped = 64'd0;
      status_next_sequence = 64'd0;
      status_word = 64'd0;

      while (index + 12 <= rx_count) begin
        if (!has_magic_at(index)) begin
          index++;
        end else begin
          magic_count++;
          payload_len = rx_bytes[index + 5];
          if (rx_bytes[index + 4] == 8'h7e) begin
            expect_true(payload_len == 0, "START frame payload length");
          end else if (rx_bytes[index + 4] == 8'h01) begin
            expect_true(payload_len > 0, "DATA frame must carry payload");
            expect_true((payload_len % 17) == 0, "DATA payload must be 17-byte aligned");
            data_frames++;
            data_records += payload_len / 17;
          end else if (rx_bytes[index + 4] == 8'h7f) begin
            expect_true(payload_len == 24, "STATUS frame payload length");
            status_frames++;
            status_accepted = load_le(index + 10, 8);
            status_dropped = load_le(index + 18, 8);
            status_next_sequence = load_le(index + 26, 4);
            status_word = load_le(index + 30, 4);
          end else begin
            $fatal(1, "[FAIL] unexpected UART frame type 0x%02x", rx_bytes[index + 4]);
          end
          index += 10 + payload_len + 2;
        end
      end

      expect_true(magic_count >= 3, "must emit START, DATA, and STATUS frame magic");
      expect_true(data_frames == 2, "20 accepted records should be split into 15-record and 5-record DATA frames");
      expect_true(data_records == 20, "DATA record count");
      expect_true(status_frames == 1, "STATUS frame count");
      expect_true(status_accepted == 20, "STATUS accepted count");
      expect_true(status_dropped == 0, "STATUS dropped count");
      expect_true(status_next_sequence == 20, "STATUS next sequence");
      expect_true((status_word & 64'd1) == 64'd1, "STATUS done bit");
    end
  endtask

  initial begin
    rst_n = 1'b0;
    trace_valid = 1'b0;
    trace_packet = trace_null_packet();
    rx_count = 0;
    repeat (8) @(negedge clk);
    rst_n = 1'b1;
    repeat (4) @(negedge clk);

    fork
      uart_receiver();
    join_none

    push_packet(make_packet(EVT_MARKER, 64'd10, 64'h1000, 64'hb0000a11));
    for (int unsigned packet_index = 0; packet_index < 19; packet_index++) begin
      push_packet(make_packet(EVT_SYSCALL_ENTRY, 64'd11 + packet_index, 64'h1004 + packet_index, 64'd56 + packet_index));
    end
    push_packet(make_packet(EVT_MARKER, 64'd40, 64'h2000, 64'he0000a11));

    wait (done);
    repeat (200) @(negedge clk);
    disable fork;

    expect_true(accepted_count == 64'd20, "accepted count output");
    expect_true(dropped_count == 64'd0, "dropped count output");
    expect_true(rx_count >= 400, "UART byte count");
    check_frames();

    $display("[PASS] trace_uart_stream_sink emitted framed UART stream");
    $finish;
  end

endmodule
