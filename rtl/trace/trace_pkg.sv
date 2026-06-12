package trace_pkg;

  typedef enum logic [3:0] {
    EVT_NONE          = 4'd0,
    EVT_RETIRE        = 4'd1,
    EVT_BRANCH        = 4'd2,
    EVT_JUMP          = 4'd3,
    EVT_SYSCALL_ENTRY = 4'd4,
    EVT_SYSCALL_RET   = 4'd5,
    EVT_TRAP          = 4'd6,
    EVT_CSR           = 4'd7,
    EVT_SATP          = 4'd8,
    EVT_PRIV          = 4'd9,
    EVT_ARG_MEM       = 4'd10,
    EVT_DROP          = 4'd11,
    EVT_MARKER        = 4'd12
  } trace_evt_e;

  localparam logic [1:0] TRACE_PRIV_U = 2'b00;
  localparam logic [1:0] TRACE_PRIV_S = 2'b01;
  localparam logic [1:0] TRACE_PRIV_H = 2'b10;
  localparam logic [1:0] TRACE_PRIV_M = 2'b11;

  typedef enum logic [1:0] {
    TRACE_MEM_MODE_NONE  = 2'd0,
    TRACE_MEM_MODE_ADDR  = 2'd1,
    TRACE_MEM_MODE_RANGE = 2'd2
  } trace_mem_mode_e;

  localparam trace_mem_mode_e TRACE_MEM_MODE_DEFAULT = TRACE_MEM_MODE_NONE;

  localparam logic [11:0] TRACE_CSR_SSTATUS = 12'h100;
  localparam logic [11:0] TRACE_CSR_STVEC   = 12'h105;
  localparam logic [11:0] TRACE_CSR_SEPC    = 12'h141;
  localparam logic [11:0] TRACE_CSR_SCAUSE  = 12'h142;
  localparam logic [11:0] TRACE_CSR_STVAL   = 12'h143;
  localparam logic [11:0] TRACE_CSR_SATP    = 12'h180;
  localparam logic [11:0] TRACE_CSR_MSTATUS = 12'h300;
  localparam logic [11:0] TRACE_CSR_MEDELEG = 12'h302;
  localparam logic [11:0] TRACE_CSR_MIDELEG = 12'h303;

  typedef struct packed {
    logic        valid;
    trace_evt_e  evt;
    logic [63:0] cycle;
    logic [63:0] pc;
    logic [31:0] instr;
    logic [63:0] target;
    logic        taken;
    logic [ 1:0] priv;
    logic [ 1:0] old_priv;
    logic [ 1:0] new_priv;
    logic [63:0] satp;
    logic [11:0] csr;
    logic [63:0] value;
    logic [63:0] cause;
    logic [63:0] tval;
    logic [63:0] syscall_id;
    logic [63:0] duration;
    logic [ 2:0] arg_index;
    logic [63:0] mem_addr;
    logic [63:0] mem_data;
    logic [ 2:0] mem_size;
    logic        mem_last;
    logic [63:0] a0;
    logic [63:0] a1;
    logic [63:0] a2;
    logic [63:0] a3;
    logic [63:0] a4;
    logic [63:0] a5;
    logic [63:0] a6;
    logic [63:0] a7;
  } trace_packet_t;

  typedef struct packed {
    logic [31:0] seq;
    logic [31:0] aux;
    logic [31:0] primary;
    logic [31:0] pc;
    logic [31:0] cycle;
    trace_evt_e  evt;
  } trace_compact_record_t;

  function automatic trace_packet_t trace_null_packet();
    trace_null_packet = '0;
    trace_null_packet.evt = EVT_NONE;
  endfunction

  function automatic logic [31:0] trace_packet_primary32(input trace_packet_t packet);
    trace_packet_primary32 = 32'd0;
    unique case (packet.evt)
      EVT_RETIRE: begin
        trace_packet_primary32 = packet.instr;
      end
      EVT_BRANCH,
      EVT_JUMP: begin
        trace_packet_primary32 = packet.target[31:0];
      end
      EVT_SYSCALL_ENTRY: begin
        trace_packet_primary32 = packet.a7[31:0];
      end
      EVT_SYSCALL_RET: begin
        trace_packet_primary32 = packet.syscall_id[31:0];
      end
      EVT_TRAP: begin
        trace_packet_primary32 = packet.cause[31:0];
      end
      EVT_CSR: begin
        trace_packet_primary32 = {20'd0, packet.csr};
      end
      EVT_SATP: begin
        trace_packet_primary32 = packet.satp[31:0];
      end
      EVT_PRIV: begin
        trace_packet_primary32 = {30'd0, packet.old_priv};
      end
      EVT_ARG_MEM: begin
        trace_packet_primary32 = packet.mem_addr[31:0];
      end
      EVT_DROP,
      EVT_MARKER: begin
        trace_packet_primary32 = packet.value[31:0];
      end
      default: begin
        trace_packet_primary32 = 32'd0;
      end
    endcase
  endfunction

  function automatic logic [31:0] trace_packet_aux32(input trace_packet_t packet);
    trace_packet_aux32 = 32'd0;
    unique case (packet.evt)
      EVT_BRANCH,
      EVT_JUMP: begin
        trace_packet_aux32 = {31'd0, packet.taken};
      end
      EVT_SYSCALL_ENTRY: begin
        trace_packet_aux32 = packet.syscall_id[31:0];
      end
      EVT_SYSCALL_RET: begin
        trace_packet_aux32 = packet.a0[31:0];
      end
      EVT_TRAP: begin
        trace_packet_aux32 = packet.tval[31:0];
      end
      EVT_CSR,
      EVT_SATP: begin
        trace_packet_aux32 = packet.value[31:0];
      end
      EVT_PRIV: begin
        trace_packet_aux32 = {30'd0, packet.new_priv};
      end
      EVT_ARG_MEM: begin
        trace_packet_aux32 = packet.mem_data[31:0];
      end
      default: begin
        trace_packet_aux32 = 32'd0;
      end
    endcase
  endfunction

  function automatic trace_compact_record_t trace_compact_record(
      input trace_packet_t packet,
      input logic [31:0] seq
  );
    trace_compact_record = '0;
    trace_compact_record.seq = seq;
    trace_compact_record.aux = trace_packet_aux32(packet);
    trace_compact_record.primary = trace_packet_primary32(packet);
    trace_compact_record.pc = packet.pc[31:0];
    trace_compact_record.cycle = packet.cycle[31:0];
    trace_compact_record.evt = packet.evt;
  endfunction

  function automatic logic trace_is_watched_csr(input logic [11:0] csr_i);
    unique case (csr_i)
      TRACE_CSR_MSTATUS,
      TRACE_CSR_SSTATUS,
      TRACE_CSR_SATP,
      TRACE_CSR_STVEC,
      TRACE_CSR_SEPC,
      TRACE_CSR_SCAUSE,
      TRACE_CSR_STVAL,
      TRACE_CSR_MEDELEG,
      TRACE_CSR_MIDELEG: trace_is_watched_csr = 1'b1;
      default: trace_is_watched_csr = 1'b0;
    endcase
  endfunction

endpackage
