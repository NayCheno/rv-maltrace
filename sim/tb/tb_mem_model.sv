module tb_mem_model (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        req_i,
    input  logic        we_i,
    input  logic [63:0] addr_i,
    input  logic [63:0] wdata_i,
    output logic [63:0] rdata_o,
    output logic        finish_o,
    output logic        pass_o
);

  localparam logic [63:0] TOHOST = 64'h0000_0000_1000_0000;
  logic [63:0] mem [0:255];

  assign rdata_o = mem[addr_i[10:3]];

  initial begin
    for (int i = 0; i < 256; i++) begin
      mem[i] = 64'd0;
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      finish_o <= 1'b0;
      pass_o   <= 1'b0;
    end else if (req_i && we_i) begin
      if (addr_i == TOHOST) begin
        finish_o <= 1'b1;
        pass_o   <= wdata_i == 64'd1;
      end else begin
        mem[addr_i[10:3]] <= wdata_i;
      end
    end
  end

endmodule
