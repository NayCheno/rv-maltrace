module trace_filter
  import trace_pkg::*;
(
    input  logic          trace_valid_i,
    input  trace_packet_t trace_packet_i,

    input  logic          enable_retire_i,
    input  logic          enable_branch_i,
    input  logic          enable_jump_i,
    input  logic          enable_syscall_i,
    input  logic          enable_trap_i,
    input  logic          enable_context_i,
    input  logic          enable_marker_i,
    input  logic          enable_drop_i,

    input  logic          pc_filter_enable_i,
    input  logic [63:0]   pc_start_i,
    input  logic [63:0]   pc_end_i,

    input  logic          priv_filter_enable_i,
    input  logic [ 3:0]   priv_mask_i,

    output logic          trace_valid_o,
    output trace_packet_t trace_packet_o
);

  logic event_enabled;
  logic pc_enabled;
  logic priv_enabled;

  always_comb begin
    unique case (trace_packet_i.evt)
      EVT_RETIRE: event_enabled = enable_retire_i;
      EVT_BRANCH: event_enabled = enable_branch_i;
      EVT_JUMP:   event_enabled = enable_jump_i;
      EVT_SYSCALL_ENTRY,
      EVT_SYSCALL_RET,
      EVT_ARG_MEM: event_enabled = enable_syscall_i;
      EVT_TRAP:    event_enabled = enable_trap_i;
      EVT_CSR,
      EVT_SATP,
      EVT_PRIV:    event_enabled = enable_context_i;
      EVT_MARKER:  event_enabled = enable_marker_i;
      EVT_DROP:    event_enabled = enable_drop_i;
      default:    event_enabled = 1'b0;
    endcase
  end

  assign pc_enabled = !pc_filter_enable_i ||
                      (trace_packet_i.pc >= pc_start_i && trace_packet_i.pc <= pc_end_i);
  assign priv_enabled = !priv_filter_enable_i || priv_mask_i[trace_packet_i.priv];

  assign trace_valid_o = trace_valid_i && event_enabled && pc_enabled && priv_enabled;

  always_comb begin
    trace_packet_o = trace_valid_o ? trace_packet_i : trace_null_packet();
  end

endmodule
