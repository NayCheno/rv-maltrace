`timescale 1ns/1ps

module trace_bram_ring
  import trace_pkg::*;
#(
    parameter int unsigned DEPTH = 1024,
    parameter int unsigned ADDR_WIDTH = (DEPTH <= 1) ? 1 : $clog2(DEPTH)
) (
    input  logic                         clk_i,
    input  logic                         rst_ni,
    input  logic                         clear_i,
    input  logic                         capture_enable_i,
    input  logic                         freeze_i,
    input  logic                         trace_valid_i,
    input  trace_packet_t                trace_packet_i,
    input  logic [ADDR_WIDTH-1:0]        dump_index_i,
    output trace_compact_record_t        dump_record_o,
    output logic                         dump_valid_o,
    output logic [ADDR_WIDTH-1:0]        write_index_o,
    output logic [ADDR_WIDTH-1:0]        oldest_index_o,
    output logic [31:0]                  next_sequence_o,
    output logic [63:0]                  event_count_o,
    output logic [63:0]                  captured_count_o,
    output logic [63:0]                  dropped_count_o,
    output logic [63:0]                  wrap_count_o,
    output logic [63:0]                  start_timestamp_o,
    output logic [63:0]                  end_timestamp_o,
    output logic                         full_o
);

  localparam logic [63:0] DEPTH_COUNT = DEPTH;
  localparam logic [ADDR_WIDTH-1:0] DEPTH_LAST = DEPTH - 1;
  localparam int unsigned RECORD_WIDTH = $bits(trace_compact_record_t);

  (* ram_style = "block" *) logic [RECORD_WIDTH-1:0] ring_mem_q [DEPTH];

  logic [ADDR_WIDTH-1:0] write_index_q;
  logic [31:0] next_sequence_q;
  logic [63:0] event_count_q;
  logic [63:0] captured_count_q;
  logic [63:0] dropped_count_q;
  logic [63:0] wrap_count_q;
  logic [63:0] start_timestamp_q;
  logic [63:0] end_timestamp_q;
  logic seen_event_q;
  trace_compact_record_t dump_record_q;
  logic dump_valid_q;

  logic capture_fire;
  logic capture_write;
  logic write_wrap;
  logic full_q;
  logic [63:0] dump_index_ext;
  logic [ADDR_WIDTH-1:0] write_index_d;
  logic [31:0] write_sequence_d;

  assign capture_fire = capture_enable_i && !freeze_i && trace_valid_i && trace_packet_i.valid;
  assign capture_write = rst_ni && capture_fire;
  assign write_index_d = clear_i ? '0 : write_index_q;
  assign write_sequence_d = clear_i ? 32'd0 : next_sequence_q;
  assign write_wrap = write_index_d == DEPTH_LAST;
  assign full_q = captured_count_q >= DEPTH_COUNT;
  assign dump_index_ext = {{(64 - ADDR_WIDTH){1'b0}}, dump_index_i};

  assign dump_record_o = dump_record_q;
  assign dump_valid_o = dump_valid_q;
  assign write_index_o = write_index_q;
  assign oldest_index_o = full_q ? write_index_q : '0;
  assign next_sequence_o = next_sequence_q;
  assign event_count_o = event_count_q;
  assign captured_count_o = captured_count_q;
  assign dropped_count_o = dropped_count_q;
  assign wrap_count_o = wrap_count_q;
  assign start_timestamp_o = start_timestamp_q;
  assign end_timestamp_o = end_timestamp_q;
  assign full_o = full_q;

  always_ff @(posedge clk_i) begin
    dump_record_q <= trace_compact_record_t'(ring_mem_q[dump_index_i]);
    if (capture_write) begin
      ring_mem_q[write_index_d] <= trace_compact_record(trace_packet_i, write_sequence_d);
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      write_index_q <= '0;
      next_sequence_q <= 32'd0;
      event_count_q <= 64'd0;
      captured_count_q <= 64'd0;
      dropped_count_q <= 64'd0;
      wrap_count_q <= 64'd0;
      start_timestamp_q <= 64'd0;
      end_timestamp_q <= 64'd0;
      seen_event_q <= 1'b0;
      dump_valid_q <= 1'b0;
    end else begin
      dump_valid_q <= full_q || (dump_index_ext < captured_count_q);

      if (clear_i) begin
        write_index_q <= '0;
        next_sequence_q <= 32'd0;
        event_count_q <= 64'd0;
        captured_count_q <= 64'd0;
        dropped_count_q <= 64'd0;
        wrap_count_q <= 64'd0;
        start_timestamp_q <= 64'd0;
        end_timestamp_q <= 64'd0;
        seen_event_q <= 1'b0;
        dump_valid_q <= 1'b0;
      end

      if (capture_write) begin
        next_sequence_q <= write_sequence_d + 32'd1;
        event_count_q <= clear_i ? 64'd1 : event_count_q + 64'd1;
        captured_count_q <= clear_i ? 64'd1 :
                            (full_q ? captured_count_q : captured_count_q + 64'd1);
        dropped_count_q <= clear_i ? 64'd0 :
                           (full_q ? dropped_count_q + 64'd1 : dropped_count_q);
        wrap_count_q <= clear_i ? (write_wrap ? 64'd1 : 64'd0) :
                        (write_wrap ? wrap_count_q + 64'd1 : wrap_count_q);
        write_index_q <= write_wrap ? '0 : write_index_d + 1'b1;
        start_timestamp_q <= (clear_i || !seen_event_q) ? trace_packet_i.cycle : start_timestamp_q;
        end_timestamp_q <= trace_packet_i.cycle;
        seen_event_q <= 1'b1;
      end
    end
  end

endmodule
