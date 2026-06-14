`timescale 1ns/1ps

module trace_uart_stream_sink
  import trace_pkg::*;
#(
    parameter int unsigned CLK_HZ = 50_000_000,
    parameter int unsigned BAUD = 12_000_000,
    parameter int unsigned FIFO_DEPTH = 64,
    parameter int unsigned FIFO_ADDR_WIDTH = (FIFO_DEPTH <= 1) ? 1 : $clog2(FIFO_DEPTH)
) (
    input  logic          clk_i,
    input  logic          rst_ni,
    input  logic          trace_valid_i,
    input  trace_packet_t trace_packet_i,
    output logic          tx_o,
    output logic          active_o,
    output logic [63:0]   accepted_count_o,
    output logic [63:0]   dropped_count_o,
    output logic          done_o
);

  localparam int unsigned RECORD_BITS = 136;
  localparam int unsigned RECORD_BYTES = 17;
  localparam int unsigned DATA_RECORDS_PER_FRAME = 15;
  localparam int unsigned DATA_PAYLOAD_BYTES = DATA_RECORDS_PER_FRAME * RECORD_BYTES;
  localparam int unsigned STATUS_BITS = 192;
  localparam int unsigned STATUS_BYTES = 24;
  localparam int unsigned HEADER_BYTES = 10;
  localparam int unsigned CRC_BYTES = 2;
  localparam int unsigned MAX_PAYLOAD_BYTES = DATA_PAYLOAD_BYTES;
  localparam int unsigned FRAME_BYTES = HEADER_BYTES + MAX_PAYLOAD_BYTES + CRC_BYTES;
  localparam logic [32:0] BAUD_STEP = BAUD;
  localparam logic [32:0] CLK_HZ_LIMIT = CLK_HZ;
  localparam logic [FIFO_ADDR_WIDTH:0] FIFO_DEPTH_COUNT = FIFO_DEPTH;
  localparam logic [FIFO_ADDR_WIDTH:0] DATA_RECORDS_PER_FRAME_COUNT = DATA_RECORDS_PER_FRAME;

  typedef enum logic [2:0] {
    ST_IDLE,
    ST_HEADER,
    ST_PAYLOAD,
    ST_CRC0,
    ST_CRC1
  } stream_state_e;

  trace_compact_record_t fifo_q [FIFO_DEPTH];
  logic [FIFO_ADDR_WIDTH-1:0] wr_ptr_q;
  logic [FIFO_ADDR_WIDTH-1:0] rd_ptr_q;
  logic [FIFO_ADDR_WIDTH:0] fifo_count_q;
  logic [31:0] seq_q;
  logic [63:0] accepted_count_q;
  logic [63:0] dropped_count_q;
  logic in_window_q;
  logic drain_q;
  logic done_q;

  stream_state_e stream_state_q;
  logic [31:0] current_seq_q;
  logic current_status_frame_q;
  logic [7:0] current_frame_type_q;
  logic [7:0] current_payload_len_q;
  logic [STATUS_BITS-1:0] current_status_payload_q;
  logic start_pending_q;
  logic status_pending_q;
  logic [7:0] header_index_q;
  logic [7:0] payload_index_q;
  logic [3:0] payload_record_index_q;
  logic [4:0] payload_record_byte_index_q;
  logic [3:0] current_record_count_q;
  logic [15:0] crc_q;

  logic uart_busy_q;
  logic [3:0] uart_bit_index_q;
  logic [31:0] baud_accum_q;
  logic [9:0] uart_shift_q;
  logic [32:0] baud_sum;
  logic [32:0] baud_sub;
  logic [31:0] baud_accum_next;
  logic baud_tick;

  logic marker_begin;
  logic marker_end;
  logic accept_trace;
  logic push_trace;
  logic fifo_full_after_pop;
  logic fifo_empty;
  logic [FIFO_ADDR_WIDTH:0] fifo_count_after_pop;
  logic [FIFO_ADDR_WIDTH:0] pop_count;
  logic byte_valid;
  logic [7:0] byte_next;
  logic [FIFO_ADDR_WIDTH-1:0] payload_rd_ptr;

  assign marker_begin = trace_valid_i &&
                        trace_packet_i.valid &&
                        trace_packet_i.evt == EVT_MARKER &&
                        trace_packet_i.value[31:28] == 4'hb;
  assign marker_end = trace_valid_i &&
                      trace_packet_i.valid &&
                      trace_packet_i.evt == EVT_MARKER &&
                      trace_packet_i.value[31:28] == 4'he;
  assign accept_trace = trace_valid_i && trace_packet_i.valid && in_window_q;
  assign fifo_count_after_pop = (fifo_count_q >= pop_count) ? (fifo_count_q - pop_count) : '0;
  assign fifo_full_after_pop = fifo_count_after_pop == FIFO_DEPTH_COUNT;
  assign push_trace = accept_trace && !fifo_full_after_pop;
  assign fifo_empty = fifo_count_q == '0;
  assign active_o = in_window_q || drain_q || start_pending_q || status_pending_q || !fifo_empty ||
                    stream_state_q != ST_IDLE || uart_busy_q;
  assign done_o = done_q;
  assign tx_o = uart_busy_q ? uart_shift_q[0] : 1'b1;
  assign accepted_count_o = accepted_count_q;
  assign dropped_count_o = dropped_count_q;
  assign baud_sum = {1'b0, baud_accum_q} + BAUD_STEP;
  assign baud_tick = baud_sum >= CLK_HZ_LIMIT;
  assign baud_sub = baud_sum - CLK_HZ_LIMIT;
  assign baud_accum_next = baud_tick ? baud_sub[31:0] : baud_sum[31:0];
  assign payload_rd_ptr = rd_ptr_q + payload_record_index_q;

  function automatic logic [31:0] compact_primary(input trace_packet_t packet);
    compact_primary = trace_packet_primary32(packet);
  endfunction

  function automatic logic [31:0] compact_aux(input trace_packet_t packet);
    compact_aux = trace_packet_aux32(packet);
  endfunction

  function automatic logic [7:0] record_byte(input trace_compact_record_t record, input logic [7:0] index);
    logic [RECORD_BITS-1:0] raw;
    begin
      raw = {
        record.aux,
        4'd0,
        record.primary,
        record.pc,
        record.cycle,
        record.evt
      };
      record_byte = raw[index * 8 +: 8];
    end
  endfunction

  function automatic logic [7:0] status_byte(input logic [STATUS_BITS-1:0] status, input logic [7:0] index);
    status_byte = status[index * 8 +: 8];
  endfunction

  function automatic logic [7:0] header_byte(
      input logic [7:0] index,
      input logic [7:0] frame_type,
      input logic [7:0] payload_len,
      input logic [31:0] seq
  );
    unique case (index)
      8'd0: header_byte = 8'h52; // R
      8'd1: header_byte = 8'h56; // V
      8'd2: header_byte = 8'h4d; // M
      8'd3: header_byte = 8'h54; // T
      8'd4: header_byte = frame_type;
      8'd5: header_byte = payload_len;
      8'd6: header_byte = seq[7:0];
      8'd7: header_byte = seq[15:8];
      8'd8: header_byte = seq[23:16];
      8'd9: header_byte = seq[31:24];
      default: header_byte = 8'h00;
    endcase
  endfunction

  function automatic logic [15:0] crc16_update(input logic [15:0] crc_i, input logic [7:0] data_i);
    logic [15:0] crc;
    begin
      crc = crc_i ^ {data_i, 8'h00};
      for (int unsigned i = 0; i < 8; i++) begin
        if (crc[15]) begin
          crc = (crc << 1) ^ 16'h1021;
        end else begin
          crc = crc << 1;
        end
      end
      crc16_update = crc;
    end
  endfunction

  always_comb begin
    byte_valid = 1'b0;
    byte_next = 8'h00;
    unique case (stream_state_q)
      ST_HEADER: begin
        byte_valid = 1'b1;
        byte_next = header_byte(header_index_q, current_frame_type_q, current_payload_len_q, current_seq_q);
      end
      ST_PAYLOAD: begin
        byte_valid = 1'b1;
        if (current_status_frame_q) begin
          byte_next = status_byte(current_status_payload_q, payload_index_q);
        end else begin
          byte_next = record_byte(fifo_q[payload_rd_ptr], payload_record_byte_index_q);
        end
      end
      ST_CRC0: begin
        byte_valid = 1'b1;
        byte_next = crc_q[7:0];
      end
      ST_CRC1: begin
        byte_valid = 1'b1;
        byte_next = crc_q[15:8];
      end
      default: begin
      end
    endcase
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      wr_ptr_q <= '0;
      rd_ptr_q <= '0;
      fifo_count_q <= '0;
      seq_q <= 32'd0;
      accepted_count_q <= 64'd0;
      dropped_count_q <= 64'd0;
      in_window_q <= 1'b0;
      drain_q <= 1'b0;
      done_q <= 1'b0;
    end else begin
      done_q <= 1'b0;

      if (marker_begin) begin
        in_window_q <= 1'b1;
        drain_q <= 1'b0;
        seq_q <= 32'd0;
        accepted_count_q <= 64'd0;
        dropped_count_q <= 64'd0;
        wr_ptr_q <= '0;
        rd_ptr_q <= '0;
        fifo_count_q <= '0;
      end else begin
        if (accept_trace) begin
          if (push_trace) begin
            fifo_q[wr_ptr_q] <= trace_compact_record(trace_packet_i, seq_q);
            wr_ptr_q <= wr_ptr_q + 1'b1;
            accepted_count_q <= accepted_count_q + 64'd1;
          end else begin
            dropped_count_q <= dropped_count_q + 64'd1;
          end
          seq_q <= seq_q + 32'd1;
        end

        if (marker_end) begin
          in_window_q <= 1'b0;
          drain_q <= 1'b1;
        end

        if (pop_count != '0) begin
          rd_ptr_q <= rd_ptr_q + pop_count[FIFO_ADDR_WIDTH-1:0];
        end

        fifo_count_q <= fifo_count_after_pop + {{FIFO_ADDR_WIDTH{1'b0}}, push_trace};
      end

      if (drain_q && fifo_empty && !status_pending_q && stream_state_q == ST_IDLE && !uart_busy_q) begin
        drain_q <= 1'b0;
        done_q <= 1'b1;
      end
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      stream_state_q <= ST_IDLE;
      current_seq_q <= 32'd0;
      current_status_frame_q <= 1'b0;
      current_frame_type_q <= 8'h01;
      current_payload_len_q <= RECORD_BYTES[7:0];
      current_status_payload_q <= '0;
      start_pending_q <= 1'b0;
      status_pending_q <= 1'b0;
      header_index_q <= 8'd0;
      payload_index_q <= 8'd0;
      payload_record_index_q <= 4'd0;
      payload_record_byte_index_q <= 5'd0;
      current_record_count_q <= 4'd0;
      crc_q <= 16'hffff;
      pop_count <= '0;
    end else begin
      pop_count <= '0;
      if (marker_begin) begin
        start_pending_q <= 1'b1;
        status_pending_q <= 1'b0;
      end else if (marker_end) begin
        status_pending_q <= 1'b1;
      end
      if (!uart_busy_q) begin
        unique case (stream_state_q)
          ST_IDLE: begin
            if (start_pending_q) begin
              current_seq_q <= 32'd0;
              current_status_frame_q <= 1'b0;
              current_frame_type_q <= 8'h7e;
              current_payload_len_q <= 8'd0;
              current_record_count_q <= 4'd0;
              header_index_q <= 8'd0;
              payload_index_q <= 8'd0;
              payload_record_index_q <= 4'd0;
              payload_record_byte_index_q <= 5'd0;
              crc_q <= 16'hffff;
              start_pending_q <= 1'b0;
              stream_state_q <= ST_HEADER;
            end else if (!fifo_empty &&
                         (fifo_count_q >= DATA_RECORDS_PER_FRAME_COUNT || drain_q)) begin
              current_seq_q <= fifo_q[rd_ptr_q].seq;
              current_status_frame_q <= 1'b0;
              current_frame_type_q <= 8'h01;
              if (fifo_count_q >= DATA_RECORDS_PER_FRAME_COUNT) begin
                current_record_count_q <= DATA_RECORDS_PER_FRAME;
                current_payload_len_q <= DATA_PAYLOAD_BYTES;
              end else begin
                current_record_count_q <= fifo_count_q[3:0];
                current_payload_len_q <= fifo_count_q * RECORD_BYTES;
              end
              header_index_q <= 8'd0;
              payload_index_q <= 8'd0;
              payload_record_index_q <= 4'd0;
              payload_record_byte_index_q <= 5'd0;
              crc_q <= 16'hffff;
              stream_state_q <= ST_HEADER;
            end else if (status_pending_q && drain_q) begin
              current_seq_q <= seq_q;
              current_status_frame_q <= 1'b1;
              current_frame_type_q <= 8'h7f;
              current_payload_len_q <= STATUS_BYTES[7:0];
              current_status_payload_q <= {
                  31'd0,
                  1'b1,
                  seq_q,
                  dropped_count_q,
                  accepted_count_q
              };
              header_index_q <= 8'd0;
              payload_index_q <= 8'd0;
              payload_record_index_q <= 4'd0;
              payload_record_byte_index_q <= 5'd0;
              current_record_count_q <= 4'd0;
              crc_q <= 16'hffff;
              status_pending_q <= 1'b0;
              stream_state_q <= ST_HEADER;
            end
          end
          ST_HEADER: begin
            crc_q <= crc16_update(crc_q, byte_next);
            if (header_index_q == HEADER_BYTES - 1) begin
              header_index_q <= 8'd0;
              if (current_payload_len_q == 8'd0) begin
                stream_state_q <= ST_CRC0;
              end else begin
                stream_state_q <= ST_PAYLOAD;
              end
            end else begin
              header_index_q <= header_index_q + 8'd1;
            end
          end
          ST_PAYLOAD: begin
            crc_q <= crc16_update(crc_q, byte_next);
            if (payload_index_q == current_payload_len_q - 1) begin
              payload_index_q <= 8'd0;
              if (!current_status_frame_q && current_frame_type_q == 8'h01) begin
                pop_count <= current_record_count_q;
              end
              stream_state_q <= ST_CRC0;
            end else begin
              payload_index_q <= payload_index_q + 8'd1;
              if (!current_status_frame_q && current_frame_type_q == 8'h01) begin
                if (payload_record_byte_index_q == RECORD_BYTES - 1) begin
                  payload_record_byte_index_q <= 5'd0;
                  payload_record_index_q <= payload_record_index_q + 4'd1;
                end else begin
                  payload_record_byte_index_q <= payload_record_byte_index_q + 5'd1;
                end
              end
            end
          end
          ST_CRC0: begin
            stream_state_q <= ST_CRC1;
          end
          ST_CRC1: begin
            stream_state_q <= ST_IDLE;
          end
          default: stream_state_q <= ST_IDLE;
        endcase
      end
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      uart_busy_q <= 1'b0;
      uart_bit_index_q <= 4'd0;
      baud_accum_q <= 32'd0;
      uart_shift_q <= 10'h3ff;
    end else begin
      if (uart_busy_q) begin
        baud_accum_q <= baud_accum_next;
        if (baud_tick) begin
          uart_shift_q <= {1'b1, uart_shift_q[9:1]};
          if (uart_bit_index_q == 4'd9) begin
            uart_busy_q <= 1'b0;
            uart_bit_index_q <= 4'd0;
          end else begin
            uart_bit_index_q <= uart_bit_index_q + 4'd1;
          end
        end
      end else if (byte_valid) begin
        uart_shift_q <= {1'b1, byte_next, 1'b0};
        uart_busy_q <= 1'b1;
        uart_bit_index_q <= 4'd0;
        baud_accum_q <= 32'd0;
      end
    end
  end

endmodule
