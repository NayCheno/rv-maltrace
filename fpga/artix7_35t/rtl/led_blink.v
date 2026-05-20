`timescale 1ns / 1ps

module led_blink (
    input  wire       clk50,
    input  wire       reset_n,
    output wire [3:0] led
);

  reg [25:0] counter = 26'd0;

  always @(posedge clk50) begin
    if (!reset_n) begin
      counter <= 26'd0;
    end else begin
      counter <= counter + 26'd1;
    end
  end

  assign led = counter[25:22];

endmodule
