`timescale 1ns/1ps

module arg_shadow #(
    parameter int WB_PORTS = 1
) (
    input  logic                         clk_i,
    input  logic                         rst_ni,
    input  logic [WB_PORTS-1:0]          wb_valid_i,
    input  logic [WB_PORTS-1:0]          wb_kill_i,
    input  logic [WB_PORTS-1:0][4:0]     wb_rd_i,
    input  logic [WB_PORTS-1:0][63:0]    wb_data_i,
    output logic [7:0][63:0]             args_o
);

  logic [7:0][63:0] args_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      args_q <= '0;
    end else begin
      for (int unsigned i = 0; i < WB_PORTS; i++) begin
        if (wb_valid_i[i] && !wb_kill_i[i] && wb_rd_i[i] inside {[5'd10:5'd17]}) begin
          args_q[wb_rd_i[i] - 5'd10] <= wb_data_i[i];
        end
      end
    end
  end

  always_comb begin
    args_o = args_q;
    for (int unsigned i = 0; i < WB_PORTS; i++) begin
      if (wb_valid_i[i] && !wb_kill_i[i] && wb_rd_i[i] inside {[5'd10:5'd17]}) begin
        args_o[wb_rd_i[i] - 5'd10] = wb_data_i[i];
      end
    end
  end

endmodule
