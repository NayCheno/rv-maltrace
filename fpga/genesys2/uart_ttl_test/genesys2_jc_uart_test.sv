`timescale 1ns / 1ps
`default_nettype none

module genesys2_jc_uart_test (
    input  wire       clk_p,
    input  wire       clk_n,
    input  wire       uart_rx,
    output wire       uart_tx,
    output wire [1:0] led
);
    localparam integer CLK_HZ = 200_000_000;
    localparam integer BAUD = 115_200;
    localparam integer CLKS_PER_BIT = CLK_HZ / BAUD;
    localparam integer BANNER_INTERVAL = CLK_HZ / 2;
    localparam integer BANNER_LEN = 19;

    wire clk_ibuf;
    wire clk;

    IBUFDS #(
        .DIFF_TERM("TRUE"),
        .IBUF_LOW_PWR("FALSE")
    ) i_clk_ibuf (
        .I(clk_p),
        .IB(clk_n),
        .O(clk_ibuf)
    );

    BUFG i_clk_bufg (
        .I(clk_ibuf),
        .O(clk)
    );

    reg [7:0] rst_shift = 8'h00;
    always @(posedge clk) begin
        rst_shift <= {rst_shift[6:0], 1'b1};
    end
    wire rst_n = &rst_shift;

    reg        tx_start;
    reg [7:0]  tx_data;
    wire       tx_busy;
    wire       rx_valid;
    wire [7:0] rx_data;

    uart_tx #(
        .CLKS_PER_BIT(CLKS_PER_BIT)
    ) i_uart_tx (
        .clk(clk),
        .rst_n(rst_n),
        .start(tx_start),
        .data(tx_data),
        .tx(uart_tx),
        .busy(tx_busy)
    );

    uart_rx #(
        .CLKS_PER_BIT(CLKS_PER_BIT)
    ) i_uart_rx (
        .clk(clk),
        .rst_n(rst_n),
        .rx(uart_rx),
        .valid(rx_valid),
        .data(rx_data)
    );

    reg [31:0] tick_count;
    reg        sending_banner;
    reg [5:0]  banner_index;
    reg        pending_echo;
    reg [7:0]  echo_data;
    reg        tx_wait_busy;
    reg        led_banner;
    reg        led_echo;

    assign led[0] = led_banner;
    assign led[1] = led_echo;

    function automatic [7:0] banner_byte(input [5:0] index);
        begin
            case (index)
                6'd0:  banner_byte = "R";
                6'd1:  banner_byte = "V";
                6'd2:  banner_byte = "M";
                6'd3:  banner_byte = "T";
                6'd4:  banner_byte = " ";
                6'd5:  banner_byte = "J";
                6'd6:  banner_byte = "C";
                6'd7:  banner_byte = " ";
                6'd8:  banner_byte = "U";
                6'd9:  banner_byte = "A";
                6'd10: banner_byte = "R";
                6'd11: banner_byte = "T";
                6'd12: banner_byte = " ";
                6'd13: banner_byte = "T";
                6'd14: banner_byte = "E";
                6'd15: banner_byte = "S";
                6'd16: banner_byte = "T";
                6'd17: banner_byte = 8'h0d;
                6'd18: banner_byte = 8'h0a;
                default: banner_byte = 8'h20;
            endcase
        end
    endfunction

    always @(posedge clk) begin
        tx_start <= 1'b0;

        if (!rst_n) begin
            tx_data <= 8'h00;
            tick_count <= 32'd0;
            sending_banner <= 1'b0;
            banner_index <= 6'd0;
            pending_echo <= 1'b0;
            echo_data <= 8'h00;
            tx_wait_busy <= 1'b0;
            led_banner <= 1'b0;
            led_echo <= 1'b0;
        end else begin
            if (tx_busy) begin
                tx_wait_busy <= 1'b0;
            end

            if (rx_valid) begin
                pending_echo <= 1'b1;
                echo_data <= rx_data;
                led_echo <= ~led_echo;
            end

            if (!tx_busy && !tx_wait_busy) begin
                if (sending_banner) begin
                    tx_data <= banner_byte(banner_index);
                    tx_start <= 1'b1;
                    tx_wait_busy <= 1'b1;
                    if (banner_index == BANNER_LEN - 1) begin
                        sending_banner <= 1'b0;
                        banner_index <= 6'd0;
                    end else begin
                        banner_index <= banner_index + 6'd1;
                    end
                end else if (pending_echo) begin
                    tx_data <= echo_data;
                    tx_start <= 1'b1;
                    tx_wait_busy <= 1'b1;
                    pending_echo <= 1'b0;
                end else if (tick_count == BANNER_INTERVAL - 1) begin
                    tick_count <= 32'd0;
                    sending_banner <= 1'b1;
                    led_banner <= ~led_banner;
                end else begin
                    tick_count <= tick_count + 32'd1;
                end
            end
        end
    end
endmodule

module uart_tx #(
    parameter integer CLKS_PER_BIT = 1736
) (
    input  wire      clk,
    input  wire      rst_n,
    input  wire      start,
    input  wire [7:0] data,
    output reg       tx,
    output reg       busy
);
    localparam [1:0] S_IDLE  = 2'd0;
    localparam [1:0] S_START = 2'd1;
    localparam [1:0] S_DATA  = 2'd2;
    localparam [1:0] S_STOP  = 2'd3;

    reg [1:0] state;
    reg [15:0] clk_count;
    reg [2:0] bit_index;
    reg [7:0] data_r;

    always @(posedge clk) begin
        if (!rst_n) begin
            state <= S_IDLE;
            tx <= 1'b1;
            busy <= 1'b0;
            clk_count <= 16'd0;
            bit_index <= 3'd0;
            data_r <= 8'h00;
        end else begin
            case (state)
                S_IDLE: begin
                    tx <= 1'b1;
                    busy <= 1'b0;
                    clk_count <= 16'd0;
                    bit_index <= 3'd0;
                    if (start) begin
                        data_r <= data;
                        busy <= 1'b1;
                        tx <= 1'b0;
                        state <= S_START;
                    end
                end

                S_START: begin
                    busy <= 1'b1;
                    if (clk_count == CLKS_PER_BIT - 1) begin
                        clk_count <= 16'd0;
                        tx <= data_r[0];
                        state <= S_DATA;
                    end else begin
                        clk_count <= clk_count + 16'd1;
                    end
                end

                S_DATA: begin
                    if (clk_count == CLKS_PER_BIT - 1) begin
                        clk_count <= 16'd0;
                        if (bit_index == 3'd7) begin
                            tx <= 1'b1;
                            state <= S_STOP;
                        end else begin
                            bit_index <= bit_index + 3'd1;
                            tx <= data_r[bit_index + 3'd1];
                        end
                    end else begin
                        clk_count <= clk_count + 16'd1;
                    end
                end

                S_STOP: begin
                    if (clk_count == CLKS_PER_BIT - 1) begin
                        state <= S_IDLE;
                        busy <= 1'b0;
                        clk_count <= 16'd0;
                    end else begin
                        clk_count <= clk_count + 16'd1;
                    end
                end

                default: begin
                    state <= S_IDLE;
                end
            endcase
        end
    end
endmodule

module uart_rx #(
    parameter integer CLKS_PER_BIT = 1736
) (
    input  wire       clk,
    input  wire       rst_n,
    input  wire       rx,
    output reg        valid,
    output reg [7:0]  data
);
    localparam [1:0] S_IDLE  = 2'd0;
    localparam [1:0] S_START = 2'd1;
    localparam [1:0] S_DATA  = 2'd2;
    localparam [1:0] S_STOP  = 2'd3;

    reg rx_meta;
    reg rx_sync;
    reg [1:0] state;
    reg [15:0] clk_count;
    reg [2:0] bit_index;

    always @(posedge clk) begin
        rx_meta <= rx;
        rx_sync <= rx_meta;
    end

    always @(posedge clk) begin
        valid <= 1'b0;

        if (!rst_n) begin
            state <= S_IDLE;
            clk_count <= 16'd0;
            bit_index <= 3'd0;
            data <= 8'h00;
        end else begin
            case (state)
                S_IDLE: begin
                    clk_count <= 16'd0;
                    bit_index <= 3'd0;
                    if (rx_sync == 1'b0) begin
                        state <= S_START;
                    end
                end

                S_START: begin
                    if (clk_count == (CLKS_PER_BIT / 2)) begin
                        if (rx_sync == 1'b0) begin
                            clk_count <= 16'd0;
                            state <= S_DATA;
                        end else begin
                            state <= S_IDLE;
                        end
                    end else begin
                        clk_count <= clk_count + 16'd1;
                    end
                end

                S_DATA: begin
                    if (clk_count == CLKS_PER_BIT - 1) begin
                        clk_count <= 16'd0;
                        data[bit_index] <= rx_sync;
                        if (bit_index == 3'd7) begin
                            bit_index <= 3'd0;
                            state <= S_STOP;
                        end else begin
                            bit_index <= bit_index + 3'd1;
                        end
                    end else begin
                        clk_count <= clk_count + 16'd1;
                    end
                end

                S_STOP: begin
                    if (clk_count == CLKS_PER_BIT - 1) begin
                        valid <= 1'b1;
                        clk_count <= 16'd0;
                        state <= S_IDLE;
                    end else begin
                        clk_count <= clk_count + 16'd1;
                    end
                end

                default: begin
                    state <= S_IDLE;
                end
            endcase
        end
    end
endmodule

`default_nettype wire
