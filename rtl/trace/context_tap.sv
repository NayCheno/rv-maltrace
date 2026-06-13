`timescale 1ns/1ps

module context_tap
  import trace_pkg::*;
(
    input  logic          clk_i,
    input  logic          rst_ni,
    input  logic [63:0]   cycle_i,
    input  logic          commit_valid_i,
    input  logic [63:0]   commit_pc_i,
    input  logic [31:0]   commit_instr_i,
    input  logic          commit_exception_i,
    input  logic          commit_kill_i,
    input  logic          trap_valid_i,
    input  logic [63:0]   trap_pc_i,
    input  logic          csr_valid_i,
    input  logic [11:0]   csr_addr_i,
    input  logic [63:0]   csr_wdata_i,
    input  logic [ 1:0]   priv_lvl_i,
    input  logic [63:0]   satp_i,
    output logic          trace_valid_o,
    output trace_packet_t trace_packet_o
);

  logic [1:0] priv_shadow_q;
  logic [63:0] last_boundary_pc_q;
  logic [63:0] last_boundary_cycle_q;
  logic        pending_priv_valid_q;
  logic [1:0]  pending_old_priv_q;
  logic [1:0]  pending_new_priv_q;
  logic [63:0] pending_pc_q;
  logic [63:0] pending_cycle_q;

  logic       boundary_valid;
  logic       csr_event;
  logic       priv_capture;
  logic       priv_event;
  logic       priv_output;
  logic [63:0] event_pc;
  logic [63:0] priv_event_pc;
  logic [63:0] priv_event_cycle;
  logic [1:0]  priv_event_old;
  logic [1:0]  priv_event_new;

  assign boundary_valid = (commit_valid_i && !commit_kill_i) || trap_valid_i;
  assign csr_event = commit_valid_i && !commit_exception_i && !commit_kill_i
                     && csr_valid_i && trace_is_watched_csr(csr_addr_i);
  assign priv_capture = !pending_priv_valid_q && priv_lvl_i != priv_shadow_q;
  assign priv_event = pending_priv_valid_q || priv_capture;
  assign priv_output = !csr_event && priv_event;
  assign trace_valid_o = csr_event || priv_event;
  assign event_pc = trap_valid_i ? trap_pc_i : commit_pc_i;
  assign priv_event_pc = pending_priv_valid_q ? pending_pc_q :
                         (boundary_valid ? event_pc : last_boundary_pc_q);
  assign priv_event_cycle = pending_priv_valid_q ? pending_cycle_q : cycle_i;
  assign priv_event_old = pending_priv_valid_q ? pending_old_priv_q : priv_shadow_q;
  assign priv_event_new = pending_priv_valid_q ? pending_new_priv_q : priv_lvl_i;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      priv_shadow_q          <= TRACE_PRIV_M;
      last_boundary_pc_q     <= 64'd0;
      last_boundary_cycle_q  <= 64'd0;
      pending_priv_valid_q   <= 1'b0;
      pending_old_priv_q     <= TRACE_PRIV_M;
      pending_new_priv_q     <= TRACE_PRIV_M;
      pending_pc_q           <= 64'd0;
      pending_cycle_q        <= 64'd0;
    end else begin
      if (boundary_valid) begin
        last_boundary_pc_q    <= event_pc;
        last_boundary_cycle_q <= cycle_i;
      end

      if (priv_output) begin
        priv_shadow_q        <= priv_event_new;
        pending_priv_valid_q <= 1'b0;
      end else if (priv_capture) begin
        pending_priv_valid_q <= 1'b1;
        pending_old_priv_q   <= priv_shadow_q;
        pending_new_priv_q   <= priv_lvl_i;
        pending_pc_q         <= boundary_valid ? event_pc : last_boundary_pc_q;
        pending_cycle_q      <= boundary_valid ? cycle_i : last_boundary_cycle_q;
      end
    end
  end

  always_comb begin
    trace_packet_o = trace_null_packet();
    trace_packet_o.valid    = trace_valid_o;
    trace_packet_o.evt      = !trace_valid_o ? EVT_NONE :
                              csr_event ? (csr_addr_i == TRACE_CSR_SATP ? EVT_SATP : EVT_CSR) :
                              EVT_PRIV;
    trace_packet_o.cycle    = csr_event ? cycle_i : priv_event_cycle;
    trace_packet_o.pc       = csr_event ? event_pc : priv_event_pc;
    trace_packet_o.instr    = commit_instr_i;
    trace_packet_o.priv     = priv_lvl_i;
    trace_packet_o.old_priv = csr_event ? priv_shadow_q : priv_event_old;
    trace_packet_o.new_priv = csr_event ? priv_lvl_i : priv_event_new;
    trace_packet_o.satp     = csr_addr_i == TRACE_CSR_SATP ? csr_wdata_i : satp_i;
    trace_packet_o.csr      = csr_event ? csr_addr_i : 12'h000;
    trace_packet_o.value    = csr_event ? csr_wdata_i : {62'd0, priv_event_new};
  end

endmodule
