module branch_tap
  import trace_pkg::*;
(
    input  logic          clk_i,
    input  logic          rst_ni,
    input  logic [63:0]   cycle_i,
    input  logic          commit_valid_i,
    input  logic [63:0]   commit_pc_i,
    input  logic [31:0]   commit_instr_i,
    input  logic [63:0]   next_pc_i,
    input  logic          jalr_target_valid_i,
    input  logic [63:0]   jalr_target_i,
    input  logic          commit_exception_i,
    input  logic          commit_kill_i,
    input  logic [ 1:0]   priv_lvl_i,
    input  logic [63:0]   satp_i,
    output logic          trace_valid_o,
    output trace_packet_t trace_packet_o
);

  localparam logic [6:0] OPCODE_BRANCH = 7'b1100011;
  localparam logic [6:0] OPCODE_JAL    = 7'b1101111;
  localparam logic [6:0] OPCODE_JALR   = 7'b1100111;

  logic [6:0] opcode;
  logic       is_branch;
  logic       is_jal;
  logic       is_jalr;
  logic [63:0] branch_imm;
  logic [63:0] jal_imm;
  logic [63:0] branch_taken_target;
  logic [63:0] branch_fallthrough;
  logic [63:0] jump_target;
  logic        branch_taken;

  assign opcode    = commit_instr_i[6:0];
  assign is_branch = opcode == OPCODE_BRANCH;
  assign is_jal    = opcode == OPCODE_JAL;
  assign is_jalr   = opcode == OPCODE_JALR;

  assign branch_imm = {
    {51{commit_instr_i[31]}},
    commit_instr_i[31],
    commit_instr_i[7],
    commit_instr_i[30:25],
    commit_instr_i[11:8],
    1'b0
  };

  assign jal_imm = {
    {43{commit_instr_i[31]}},
    commit_instr_i[31],
    commit_instr_i[19:12],
    commit_instr_i[20],
    commit_instr_i[30:21],
    1'b0
  };

  assign branch_taken_target = commit_pc_i + branch_imm;
  assign branch_fallthrough  = commit_pc_i + 64'd4;
  assign branch_taken        = next_pc_i == branch_taken_target;
  assign jump_target         = is_jal ? commit_pc_i + jal_imm :
                               ((jalr_target_valid_i ? jalr_target_i : next_pc_i) & ~64'd1);

  assign trace_valid_o = commit_valid_i && !commit_exception_i && !commit_kill_i
                         && (is_branch || is_jal || is_jalr);

  always_comb begin
    trace_packet_o = trace_null_packet();
    trace_packet_o.valid  = trace_valid_o;
    trace_packet_o.evt    = !trace_valid_o ? EVT_NONE : (is_branch ? EVT_BRANCH : EVT_JUMP);
    trace_packet_o.cycle  = cycle_i;
    trace_packet_o.pc     = commit_pc_i;
    trace_packet_o.instr  = commit_instr_i;
    trace_packet_o.taken  = is_branch ? branch_taken : 1'b1;
    trace_packet_o.target = is_branch ? (branch_taken ? branch_taken_target : branch_fallthrough) : jump_target;
    trace_packet_o.priv   = priv_lvl_i;
    trace_packet_o.satp   = satp_i;
  end

endmodule
