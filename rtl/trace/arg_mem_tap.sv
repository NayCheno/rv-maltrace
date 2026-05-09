module arg_mem_tap
  import trace_pkg::*;
#(
    parameter int MAX_CAPTURE_BYTES = 256,
    parameter int MAX_WATCH_CYCLES = 64
) (
    input  logic            clk_i,
    input  logic            rst_ni,
    input  logic [63:0]     cycle_i,
    input  trace_mem_mode_e mem_mode_i,

    input  logic            syscall_valid_i,
    input  trace_packet_t   syscall_packet_i,

    input  logic            mem_load_valid_i,
    input  logic [63:0]     mem_load_pc_i,
    input  logic [63:0]     mem_load_addr_i,
    input  logic [63:0]     mem_load_data_i,
    input  logic [ 2:0]     mem_load_size_i,
    input  logic [ 1:0]     priv_lvl_i,
    input  logic [63:0]     satp_i,

    output logic            trace_valid_o,
    output trace_packet_t   trace_packet_o
);

  localparam logic [63:0] SYS_OPENAT = 64'd56;
  localparam logic [63:0] SYS_WRITE  = 64'd64;
  localparam logic [63:0] SYS_EXECVE = 64'd221;
  localparam logic [63:0] MAX_CAPTURE_BYTES_64 = MAX_CAPTURE_BYTES;
  localparam logic [63:0] MAX_WATCH_CYCLES_64 = MAX_WATCH_CYCLES;

  logic        watch_active_q;
  logic [63:0] watch_base_q;
  logic [63:0] watch_limit_q;
  logic [63:0] watch_syscall_id_q;
  logic [ 2:0] watch_arg_index_q;
  logic [63:0] watch_age_q;

  logic entry_supported;
  logic entry_valid;
  logic ret_valid;
  logic capture_valid;
  logic capture_last;
  logic watch_timeout;
  logic [63:0] entry_base;
  logic [63:0] entry_len;
  logic [2:0]  entry_arg_index;
  logic [2:0]  capture_size;
  logic [63:0] remaining_bytes;
  logic [63:0] capture_end;
  logic [63:0] capture_data;

  function automatic logic data_has_zero_byte(input logic [63:0] data, input logic [2:0] size);
    data_has_zero_byte = 1'b0;
    for (int unsigned i = 0; i < 8; i++) begin
      if (i < size && data[i*8+:8] == 8'd0) begin
        data_has_zero_byte = 1'b1;
      end
    end
  endfunction

  function automatic logic [63:0] mask_data_to_size(input logic [63:0] data, input logic [2:0] size);
    mask_data_to_size = 64'd0;
    for (int unsigned i = 0; i < 8; i++) begin
      if (i < size) begin
        mask_data_to_size[i*8+:8] = data[i*8+:8];
      end
    end
  endfunction

  function automatic logic [63:0] bounded_len(input logic [63:0] requested_len);
    if (requested_len == 64'd0 || requested_len > MAX_CAPTURE_BYTES_64) begin
      bounded_len = MAX_CAPTURE_BYTES_64;
    end else begin
      bounded_len = requested_len;
    end
  endfunction

  always_comb begin
    entry_supported = 1'b0;
    entry_base = 64'd0;
    entry_len = MAX_CAPTURE_BYTES_64;
    entry_arg_index = 3'd0;

    unique case (syscall_packet_i.a7)
      SYS_OPENAT: begin
        entry_supported = syscall_packet_i.a1 != 64'd0;
        entry_base = syscall_packet_i.a1;
        entry_arg_index = 3'd1;
      end
      SYS_WRITE: begin
        entry_supported = syscall_packet_i.a1 != 64'd0;
        entry_base = syscall_packet_i.a1;
        entry_len = bounded_len(syscall_packet_i.a2);
        entry_arg_index = 3'd1;
      end
      SYS_EXECVE: begin
        entry_supported = syscall_packet_i.a0 != 64'd0;
        entry_base = syscall_packet_i.a0;
        entry_arg_index = 3'd0;
      end
      default: begin
      end
    endcase
  end

  assign entry_valid = mem_mode_i != TRACE_MEM_MODE_NONE &&
                       syscall_valid_i &&
                       syscall_packet_i.evt == EVT_SYSCALL_ENTRY &&
                       entry_supported;
  assign ret_valid = syscall_valid_i && syscall_packet_i.evt == EVT_SYSCALL_RET;

  assign remaining_bytes = watch_limit_q - mem_load_addr_i;
  always_comb begin
    if (remaining_bytes > 64'd7 || mem_load_size_i <= remaining_bytes[2:0]) begin
      capture_size = mem_load_size_i;
    end else begin
      capture_size = remaining_bytes[2:0];
    end
  end
  assign capture_end = mem_load_addr_i + {61'd0, capture_size};
  assign capture_data = mask_data_to_size(mem_load_data_i, capture_size);
  assign capture_valid = mem_mode_i != TRACE_MEM_MODE_NONE &&
                         watch_active_q &&
                         mem_load_valid_i &&
                         mem_load_size_i != 3'd0 &&
                         priv_lvl_i == TRACE_PRIV_S &&
                         mem_load_addr_i >= watch_base_q &&
                         mem_load_addr_i < watch_limit_q;
  assign capture_last = data_has_zero_byte(capture_data, capture_size) ||
                        capture_end >= watch_limit_q;
  assign watch_timeout = watch_active_q &&
                         MAX_WATCH_CYCLES_64 != 64'd0 &&
                         watch_age_q >= MAX_WATCH_CYCLES_64;
  assign trace_valid_o = capture_valid;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      watch_active_q <= 1'b0;
      watch_base_q <= 64'd0;
      watch_limit_q <= 64'd0;
      watch_syscall_id_q <= 64'd0;
      watch_arg_index_q <= 3'd0;
      watch_age_q <= 64'd0;
    end else begin
      if (ret_valid || (capture_valid && capture_last) || watch_timeout) begin
        watch_active_q <= 1'b0;
        watch_age_q <= 64'd0;
      end else if (watch_active_q) begin
        if (capture_valid) begin
          watch_age_q <= 64'd0;
        end else begin
          watch_age_q <= watch_age_q + 64'd1;
        end
      end
      if (entry_valid) begin
        watch_active_q <= 1'b1;
        watch_base_q <= entry_base;
        watch_limit_q <= entry_base + entry_len;
        watch_syscall_id_q <= syscall_packet_i.syscall_id;
        watch_arg_index_q <= entry_arg_index;
        watch_age_q <= 64'd0;
      end
    end
  end

  always_comb begin
    trace_packet_o = trace_null_packet();
    trace_packet_o.valid = trace_valid_o;
    trace_packet_o.evt = capture_valid ? EVT_ARG_MEM : EVT_NONE;
    trace_packet_o.cycle = cycle_i;
    trace_packet_o.pc = mem_load_pc_i;
    trace_packet_o.priv = priv_lvl_i;
    trace_packet_o.satp = satp_i;
    trace_packet_o.syscall_id = watch_syscall_id_q;
    trace_packet_o.arg_index = watch_arg_index_q;
    trace_packet_o.mem_addr = mem_load_addr_i;
    trace_packet_o.mem_data = mem_mode_i == TRACE_MEM_MODE_RANGE ? capture_data : 64'd0;
    trace_packet_o.mem_size = capture_size;
    trace_packet_o.mem_last = capture_last;
  end

endmodule
