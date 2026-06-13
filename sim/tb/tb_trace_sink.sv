`timescale 1ns/1ps

module tb_trace_sink
  import trace_pkg::*;
(
    input logic          clk_i,
    input logic          rst_ni,
    input logic          trace_valid_i,
    input trace_packet_t trace_packet_i
);

  string result_dir;
  string trace_path;
  int trace_fd;

  function automatic string evt_name(input trace_evt_e evt);
    unique case (evt)
      EVT_RETIRE: evt_name = "RETIRE";
      EVT_BRANCH: evt_name = "BRANCH";
      EVT_JUMP:   evt_name = "JUMP";
      EVT_SYSCALL_ENTRY: evt_name = "SYSCALL_ENTRY";
      EVT_SYSCALL_RET:   evt_name = "SYSCALL_RET";
      EVT_TRAP:          evt_name = "TRAP";
      EVT_CSR:           evt_name = "CSR";
      EVT_SATP:          evt_name = "SATP";
      EVT_PRIV:          evt_name = "PRIV";
      EVT_ARG_MEM:       evt_name = "ARG_MEM";
      EVT_MARKER:        evt_name = "MARKER";
      EVT_DROP:          evt_name = "DROP";
      default:           evt_name = "NONE";
    endcase
  endfunction

  function automatic string priv_name(input logic [1:0] priv);
    unique case (priv)
      TRACE_PRIV_U: priv_name = "U";
      TRACE_PRIV_S: priv_name = "S";
      TRACE_PRIV_H: priv_name = "H";
      TRACE_PRIV_M: priv_name = "M";
      default:      priv_name = "X";
    endcase
  endfunction

  task automatic write_packet(input trace_packet_t packet);
    $fwrite(
        trace_fd,
        "{\"cycle\":%0d,\"evt\":\"%s\",\"pc\":\"0x%016h\",\"instr\":\"0x%08h\"",
        packet.cycle,
        evt_name(packet.evt),
        packet.pc,
        packet.instr
    );

    unique case (packet.evt)
      EVT_RETIRE: begin
        $fwrite(trace_fd, ",\"priv\":\"%s\"", priv_name(packet.priv));
      end
      EVT_BRANCH: begin
        $fwrite(trace_fd, ",\"taken\":%s,\"target\":\"0x%016h\"", packet.taken ? "true" : "false", packet.target);
      end
      EVT_JUMP: begin
        $fwrite(trace_fd, ",\"target\":\"0x%016h\"", packet.target);
      end
      EVT_SYSCALL_ENTRY: begin
        $fwrite(
            trace_fd,
            ",\"priv\":\"%s\",\"syscall_id\":\"0x%016h\",\"a0\":\"0x%016h\",\"a1\":\"0x%016h\",\"a2\":\"0x%016h\",\"a3\":\"0x%016h\",\"a4\":\"0x%016h\",\"a5\":\"0x%016h\",\"a6\":\"0x%016h\",\"a7\":\"0x%016h\"",
            priv_name(packet.priv),
            packet.syscall_id,
            packet.a0,
            packet.a1,
            packet.a2,
            packet.a3,
            packet.a4,
            packet.a5,
            packet.a6,
            packet.a7
        );
      end
      EVT_SYSCALL_RET: begin
        $fwrite(
            trace_fd,
            ",\"priv\":\"%s\",\"target\":\"0x%016h\",\"syscall_id\":\"0x%016h\",\"duration\":%0d,\"a0\":\"0x%016h\"",
            priv_name(packet.priv),
            packet.target,
            packet.syscall_id,
            packet.duration,
            packet.a0
        );
      end
      EVT_ARG_MEM: begin
        $fwrite(
            trace_fd,
            ",\"priv\":\"%s\",\"syscall_id\":\"0x%016h\",\"arg_index\":%0d,\"mem_addr\":\"0x%016h\",\"mem_data\":\"0x%016h\",\"mem_size\":%0d,\"mem_last\":%s",
            priv_name(packet.priv),
            packet.syscall_id,
            packet.arg_index,
            packet.mem_addr,
            packet.mem_data,
            packet.mem_size,
            packet.mem_last ? "true" : "false"
        );
      end
      EVT_TRAP: begin
        $fwrite(
            trace_fd,
            ",\"priv\":\"%s\",\"cause\":\"0x%016h\",\"tval\":\"0x%016h\"",
            priv_name(packet.priv),
            packet.cause,
            packet.tval
        );
      end
      EVT_CSR, EVT_SATP: begin
        $fwrite(
            trace_fd,
            ",\"priv\":\"%s\",\"csr\":\"0x%03h\",\"value\":\"0x%016h\",\"satp\":\"0x%016h\"",
            priv_name(packet.priv),
            packet.csr,
            packet.value,
            packet.satp
        );
      end
      EVT_PRIV: begin
        $fwrite(
            trace_fd,
            ",\"old_priv\":\"%s\",\"new_priv\":\"%s\"",
            priv_name(packet.old_priv),
            priv_name(packet.new_priv)
        );
      end
      EVT_DROP, EVT_MARKER: begin
        $fwrite(trace_fd, ",\"value\":\"0x%016h\"", packet.value);
      end
      default: begin
      end
    endcase

    $fwrite(trace_fd, "}\n");
    $fflush(trace_fd);
  endtask

  initial begin
    if (!$value$plusargs("RESULT_DIR=%s", result_dir)) begin
      result_dir = "results/vivado_sim/smoke";
    end
    trace_path = {result_dir, "/trace.jsonl"};
    trace_fd = $fopen(trace_path, "w");
    if (trace_fd == 0) begin
      $fatal(1, "Could not open trace output: %s", trace_path);
    end
  end

  always_ff @(posedge clk_i) begin
    if (rst_ni && trace_valid_i && trace_packet_i.valid) begin
      write_packet(trace_packet_i);
    end
  end

  final begin
    if (trace_fd != 0) begin
      $fclose(trace_fd);
    end
  end

endmodule
