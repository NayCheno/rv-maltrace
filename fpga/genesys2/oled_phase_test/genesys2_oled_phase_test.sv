`timescale 1ns / 1ps
`default_nettype none

module genesys2_oled_phase_test (
    input  wire       clk_p,
    input  wire       clk_n,
    input  wire [3:0] sw,
    output wire [7:0] led,
    output wire       oled_dc,
    output wire       oled_res,
    output wire       oled_sclk,
    output wire       oled_sdin,
    output wire       oled_vbat,
    output wire       oled_vdd
);
    localparam integer CLK_HZ = 200_000_000;
    localparam integer PHASE_INTERVAL = CLK_HZ * 2;

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

    reg [15:0] rst_shift = 16'h0000;
    always @(posedge clk) begin
        rst_shift <= {rst_shift[14:0], 1'b1};
    end
    wire rst_n = &rst_shift;

    reg [3:0] sw_meta;
    reg [3:0] sw_sync;
    always @(posedge clk) begin
        sw_meta <= sw;
        sw_sync <= sw_meta;
    end

    reg [31:0] phase_count;
    reg [2:0]  auto_phase;
    always @(posedge clk) begin
        if (!rst_n) begin
            phase_count <= 32'd0;
            auto_phase <= 3'd0;
        end else if (phase_count == PHASE_INTERVAL - 1) begin
            phase_count <= 32'd0;
            auto_phase <= auto_phase + 3'd1;
        end else begin
            phase_count <= phase_count + 32'd1;
        end
    end

    wire       manual_mode = sw_sync[3];
    wire [2:0] display_phase = manual_mode ? sw_sync[2:0] : auto_phase;
    wire       oled_ready;
    wire       oled_updating;

    genesys2_oled_status #(
        .CLK_HZ(CLK_HZ),
        .SPI_HALF_CYCLES(10)
    ) i_oled_status (
        .clk(clk),
        .rst_n(rst_n),
        .phase(display_phase),
        .manual_mode(manual_mode),
        .oled_dc(oled_dc),
        .oled_res(oled_res),
        .oled_sclk(oled_sclk),
        .oled_sdin(oled_sdin),
        .oled_vbat(oled_vbat),
        .oled_vdd(oled_vdd),
        .ready(oled_ready),
        .updating(oled_updating)
    );

    assign led[2:0] = display_phase;
    assign led[3] = manual_mode;
    assign led[4] = oled_updating;
    assign led[5] = phase_count[27];
    assign led[6] = rst_n;
    assign led[7] = oled_ready;
endmodule

module genesys2_oled_status #(
    parameter integer CLK_HZ = 200_000_000,
    parameter integer SPI_HALF_CYCLES = 10
) (
    input  wire       clk,
    input  wire       rst_n,
    input  wire [2:0] phase,
    input  wire       manual_mode,
    output reg        oled_dc,
    output reg        oled_res,
    output wire       oled_sclk,
    output wire       oled_sdin,
    output reg        oled_vbat,
    output reg        oled_vdd,
    output reg        ready,
    output wire       updating
);
    localparam integer CYCLES_1MS = CLK_HZ / 1000;
    localparam integer CYCLES_100MS = CLK_HZ / 10;
    localparam integer REFRESH_CYCLES = CLK_HZ / 4;
    localparam integer INIT_LEN = 25;
    localparam integer ADDR_LEN = 6;

    localparam [4:0] S_VDD_WAIT       = 5'd0;
    localparam [4:0] S_RES_LOW        = 5'd1;
    localparam [4:0] S_RES_HIGH       = 5'd2;
    localparam [4:0] S_INIT_START     = 5'd3;
    localparam [4:0] S_INIT_WAIT      = 5'd4;
    localparam [4:0] S_VBAT_WAIT      = 5'd5;
    localparam [4:0] S_ADDR_START     = 5'd6;
    localparam [4:0] S_ADDR_WAIT      = 5'd7;
    localparam [4:0] S_DATA_START     = 5'd8;
    localparam [4:0] S_DATA_WAIT      = 5'd9;
    localparam [4:0] S_DISP_ON_START  = 5'd10;
    localparam [4:0] S_DISP_ON_WAIT   = 5'd11;
    localparam [4:0] S_REFRESH_WAIT   = 5'd12;

    reg [4:0]  state;
    reg [31:0] delay_count;
    reg [31:0] refresh_count;
    reg [4:0]  init_index;
    reg [2:0]  addr_index;
    reg [8:0]  frame_index;
    reg        frame_clear;
    reg [2:0]  frame_phase;
    reg        frame_manual;
    reg [2:0]  rendered_phase;
    reg        rendered_manual;

    reg        spi_start;
    reg [7:0]  spi_data;
    wire       spi_busy;
    wire       spi_done;

    oled_spi_byte #(
        .SPI_HALF_CYCLES(SPI_HALF_CYCLES)
    ) i_spi (
        .clk(clk),
        .rst_n(rst_n),
        .start(spi_start),
        .data(spi_data),
        .sclk(oled_sclk),
        .sdin(oled_sdin),
        .busy(spi_busy),
        .done(spi_done)
    );

    assign updating = (state == S_INIT_START) ||
                      (state == S_INIT_WAIT) ||
                      (state == S_ADDR_START) ||
                      (state == S_ADDR_WAIT) ||
                      (state == S_DATA_START) ||
                      (state == S_DATA_WAIT) ||
                      (state == S_DISP_ON_START) ||
                      (state == S_DISP_ON_WAIT) ||
                      spi_busy;

    function automatic [7:0] font5x7(input [7:0] ch, input [2:0] col);
        reg [39:0] bits;
        begin
            case (ch)
                "0": bits = {8'h3e, 8'h45, 8'h49, 8'h51, 8'h3e};
                "1": bits = {8'h00, 8'h40, 8'h7f, 8'h42, 8'h00};
                "2": bits = {8'h46, 8'h49, 8'h51, 8'h61, 8'h42};
                "3": bits = {8'h31, 8'h4b, 8'h45, 8'h41, 8'h21};
                "4": bits = {8'h10, 8'h7f, 8'h12, 8'h14, 8'h18};
                "5": bits = {8'h39, 8'h45, 8'h45, 8'h45, 8'h27};
                "6": bits = {8'h30, 8'h49, 8'h49, 8'h4a, 8'h3c};
                "7": bits = {8'h03, 8'h05, 8'h09, 8'h71, 8'h01};
                "8": bits = {8'h36, 8'h49, 8'h49, 8'h49, 8'h36};
                "9": bits = {8'h1e, 8'h29, 8'h49, 8'h49, 8'h06};
                "A": bits = {8'h7e, 8'h11, 8'h11, 8'h11, 8'h7e};
                "B": bits = {8'h36, 8'h49, 8'h49, 8'h49, 8'h7f};
                "C": bits = {8'h22, 8'h41, 8'h41, 8'h41, 8'h3e};
                "D": bits = {8'h1c, 8'h22, 8'h41, 8'h41, 8'h7f};
                "E": bits = {8'h41, 8'h49, 8'h49, 8'h49, 8'h7f};
                "F": bits = {8'h01, 8'h09, 8'h09, 8'h09, 8'h7f};
                "G": bits = {8'h7a, 8'h49, 8'h49, 8'h41, 8'h3e};
                "H": bits = {8'h7f, 8'h08, 8'h08, 8'h08, 8'h7f};
                "I": bits = {8'h00, 8'h41, 8'h7f, 8'h41, 8'h00};
                "J": bits = {8'h01, 8'h3f, 8'h41, 8'h40, 8'h20};
                "K": bits = {8'h41, 8'h22, 8'h14, 8'h08, 8'h7f};
                "L": bits = {8'h40, 8'h40, 8'h40, 8'h40, 8'h7f};
                "M": bits = {8'h7f, 8'h02, 8'h0c, 8'h02, 8'h7f};
                "N": bits = {8'h7f, 8'h10, 8'h08, 8'h04, 8'h7f};
                "O": bits = {8'h3e, 8'h41, 8'h41, 8'h41, 8'h3e};
                "P": bits = {8'h06, 8'h09, 8'h09, 8'h09, 8'h7f};
                "Q": bits = {8'h5e, 8'h21, 8'h51, 8'h41, 8'h3e};
                "R": bits = {8'h46, 8'h29, 8'h19, 8'h09, 8'h7f};
                "S": bits = {8'h31, 8'h49, 8'h49, 8'h49, 8'h46};
                "T": bits = {8'h01, 8'h01, 8'h7f, 8'h01, 8'h01};
                "U": bits = {8'h3f, 8'h40, 8'h40, 8'h40, 8'h3f};
                "V": bits = {8'h1f, 8'h20, 8'h40, 8'h20, 8'h1f};
                "W": bits = {8'h7f, 8'h20, 8'h18, 8'h20, 8'h7f};
                "X": bits = {8'h63, 8'h14, 8'h08, 8'h14, 8'h63};
                "Y": bits = {8'h07, 8'h08, 8'h70, 8'h08, 8'h07};
                "Z": bits = {8'h61, 8'h51, 8'h49, 8'h45, 8'h43};
                "-": bits = {8'h08, 8'h08, 8'h08, 8'h08, 8'h08};
                ":": bits = {8'h00, 8'h36, 8'h36, 8'h00, 8'h00};
                default: bits = 40'h0000000000;
            endcase
            font5x7 = bits[col * 8 +: 8];
        end
    endfunction

    function automatic [7:0] phase_name_char(input [2:0] phase_i, input [4:0] pos);
        begin
            phase_name_char = " ";
            case (phase_i)
                3'd0: begin
                    case (pos)
                        5'd0: phase_name_char = "P";
                        5'd1: phase_name_char = "R";
                        5'd2: phase_name_char = "E";
                        5'd3: phase_name_char = "F";
                        5'd4: phase_name_char = "L";
                        5'd5: phase_name_char = "I";
                        5'd6: phase_name_char = "G";
                        5'd7: phase_name_char = "H";
                        5'd8: phase_name_char = "T";
                    endcase
                end
                3'd1: begin
                    case (pos)
                        5'd0: phase_name_char = "C";
                        5'd1: phase_name_char = "H";
                        5'd2: phase_name_char = "E";
                        5'd3: phase_name_char = "C";
                        5'd4: phase_name_char = "K";
                        5'd5: phase_name_char = "S";
                    endcase
                end
                3'd2: begin
                    case (pos)
                        5'd0: phase_name_char = "B";
                        5'd1: phase_name_char = "U";
                        5'd2: phase_name_char = "I";
                        5'd3: phase_name_char = "L";
                        5'd4: phase_name_char = "D";
                    endcase
                end
                3'd3: begin
                    case (pos)
                        5'd0: phase_name_char = "P";
                        5'd1: phase_name_char = "R";
                        5'd2: phase_name_char = "O";
                        5'd3: phase_name_char = "G";
                        5'd4: phase_name_char = "R";
                        5'd5: phase_name_char = "A";
                        5'd6: phase_name_char = "M";
                    endcase
                end
                3'd4: begin
                    case (pos)
                        5'd0: phase_name_char = "U";
                        5'd1: phase_name_char = "A";
                        5'd2: phase_name_char = "R";
                        5'd3: phase_name_char = "T";
                        5'd4: phase_name_char = " ";
                        5'd5: phase_name_char = "B";
                        5'd6: phase_name_char = "M";
                    endcase
                end
                3'd5: begin
                    case (pos)
                        5'd0: phase_name_char = "T";
                        5'd1: phase_name_char = "R";
                        5'd2: phase_name_char = "A";
                        5'd3: phase_name_char = "C";
                        5'd4: phase_name_char = "E";
                        5'd5: phase_name_char = " ";
                        5'd6: phase_name_char = "B";
                        5'd7: phase_name_char = "U";
                        5'd8: phase_name_char = "I";
                        5'd9: phase_name_char = "L";
                        5'd10: phase_name_char = "D";
                    endcase
                end
                3'd6: begin
                    case (pos)
                        5'd0: phase_name_char = "T";
                        5'd1: phase_name_char = "R";
                        5'd2: phase_name_char = "A";
                        5'd3: phase_name_char = "C";
                        5'd4: phase_name_char = "E";
                        5'd5: phase_name_char = " ";
                        5'd6: phase_name_char = "V";
                        5'd7: phase_name_char = "A";
                        5'd8: phase_name_char = "L";
                        5'd9: phase_name_char = "I";
                        5'd10: phase_name_char = "D";
                    endcase
                end
                3'd7: begin
                    case (pos)
                        5'd0: phase_name_char = "L";
                        5'd1: phase_name_char = "I";
                        5'd2: phase_name_char = "N";
                        5'd3: phase_name_char = "U";
                        5'd4: phase_name_char = "X";
                        5'd5: phase_name_char = " ";
                        5'd6: phase_name_char = "C";
                        5'd7: phase_name_char = "L";
                        5'd8: phase_name_char = "A";
                        5'd9: phase_name_char = "I";
                        5'd10: phase_name_char = "M";
                    endcase
                end
            endcase
        end
    endfunction

    function automatic [7:0] mode_line_char(input manual_i, input [4:0] pos);
        begin
            mode_line_char = " ";
            if (manual_i) begin
                case (pos)
                    5'd0: mode_line_char = "M";
                    5'd1: mode_line_char = "A";
                    5'd2: mode_line_char = "N";
                    5'd3: mode_line_char = "U";
                    5'd4: mode_line_char = "A";
                    5'd5: mode_line_char = "L";
                    5'd7: mode_line_char = "S";
                    5'd8: mode_line_char = "W";
                    5'd9: mode_line_char = "2";
                    5'd10: mode_line_char = ":";
                    5'd11: mode_line_char = "0";
                    5'd13: mode_line_char = "S";
                    5'd14: mode_line_char = "E";
                    5'd15: mode_line_char = "L";
                    5'd16: mode_line_char = "E";
                    5'd17: mode_line_char = "C";
                    5'd18: mode_line_char = "T";
                endcase
            end else begin
                case (pos)
                    5'd0: mode_line_char = "A";
                    5'd1: mode_line_char = "U";
                    5'd2: mode_line_char = "T";
                    5'd3: mode_line_char = "O";
                    5'd5: mode_line_char = "C";
                    5'd6: mode_line_char = "Y";
                    5'd7: mode_line_char = "C";
                    5'd8: mode_line_char = "L";
                    5'd9: mode_line_char = "E";
                    5'd11: mode_line_char = "P";
                    5'd12: mode_line_char = "0";
                    5'd13: mode_line_char = "-";
                    5'd14: mode_line_char = "P";
                    5'd15: mode_line_char = "7";
                endcase
            end
        end
    endfunction

    function automatic [7:0] footer_line_char(input [4:0] pos);
        begin
            footer_line_char = " ";
            case (pos)
                5'd0: footer_line_char = "G";
                5'd1: footer_line_char = "E";
                5'd2: footer_line_char = "N";
                5'd3: footer_line_char = "E";
                5'd4: footer_line_char = "S";
                5'd5: footer_line_char = "Y";
                5'd6: footer_line_char = "S";
                5'd7: footer_line_char = "2";
                5'd9: footer_line_char = "1";
                5'd10: footer_line_char = "2";
                5'd11: footer_line_char = "8";
                5'd12: footer_line_char = "X";
                5'd13: footer_line_char = "3";
                5'd14: footer_line_char = "2";
            endcase
        end
    endfunction

    function automatic [7:0] line_char(
        input [1:0] row,
        input [4:0] pos,
        input [2:0] phase_i,
        input manual_i
    );
        begin
            line_char = " ";
            case (row)
                2'd0: begin
                    case (pos)
                        5'd0: line_char = "R";
                        5'd1: line_char = "V";
                        5'd2: line_char = "M";
                        5'd3: line_char = "T";
                        5'd5: line_char = "O";
                        5'd6: line_char = "L";
                        5'd7: line_char = "E";
                        5'd8: line_char = "D";
                        5'd10: line_char = "S";
                        5'd11: line_char = "T";
                        5'd12: line_char = "A";
                        5'd13: line_char = "T";
                        5'd14: line_char = "U";
                        5'd15: line_char = "S";
                    endcase
                end
                2'd1: begin
                    case (pos)
                        5'd0: line_char = "P";
                        5'd1: line_char = 8'h30 + {5'b00000, phase_i};
                        default: begin
                            if (pos >= 5'd3) begin
                                line_char = phase_name_char(phase_i, pos - 5'd3);
                            end
                        end
                    endcase
                end
                2'd2: line_char = mode_line_char(manual_i, pos);
                2'd3: line_char = footer_line_char(pos);
            endcase
        end
    endfunction

    function automatic [7:0] frame_data(
        input [8:0] index,
        input [2:0] phase_i,
        input manual_i,
        input clear_i
    );
        reg [1:0] row;
        reg [6:0] col;
        reg [4:0] char_pos;
        reg [2:0] glyph_col;
        reg [7:0] ch;
        begin
            if (clear_i) begin
                frame_data = 8'h00;
            end else begin
                row = index[8:7];
                col = index[6:0];
                if (col >= 7'd126) begin
                    frame_data = 8'h00;
                end else begin
                    char_pos = col / 7'd6;
                    glyph_col = col % 7'd6;
                    ch = line_char(row, char_pos, phase_i, manual_i);
                    frame_data = (glyph_col == 3'd5) ? 8'h00 : font5x7(ch, glyph_col);
                end
            end
        end
    endfunction

    function automatic [7:0] init_cmd(input [4:0] index);
        begin
            case (index)
                5'd0:  init_cmd = 8'hae;
                5'd1:  init_cmd = 8'hd5;
                5'd2:  init_cmd = 8'h80;
                5'd3:  init_cmd = 8'ha8;
                5'd4:  init_cmd = 8'h1f;
                5'd5:  init_cmd = 8'hd3;
                5'd6:  init_cmd = 8'h00;
                5'd7:  init_cmd = 8'h40;
                5'd8:  init_cmd = 8'h8d;
                5'd9:  init_cmd = 8'h14;
                5'd10: init_cmd = 8'hd9;
                5'd11: init_cmd = 8'hf1;
                5'd12: init_cmd = 8'hdb;
                5'd13: init_cmd = 8'h40;
                5'd14: init_cmd = 8'h81;
                5'd15: init_cmd = 8'h0f;
                5'd16: init_cmd = 8'ha0;
                5'd17: init_cmd = 8'hc0;
                5'd18: init_cmd = 8'hda;
                5'd19: init_cmd = 8'h00;
                5'd20: init_cmd = 8'h20;
                5'd21: init_cmd = 8'h00;
                5'd22: init_cmd = 8'ha4;
                5'd23: init_cmd = 8'ha6;
                5'd24: init_cmd = 8'h2e;
                default: init_cmd = 8'h00;
            endcase
        end
    endfunction

    function automatic [7:0] addr_cmd(input [2:0] index);
        begin
            case (index)
                3'd0: addr_cmd = 8'h21;
                3'd1: addr_cmd = 8'h00;
                3'd2: addr_cmd = 8'h7f;
                3'd3: addr_cmd = 8'h22;
                3'd4: addr_cmd = 8'h00;
                3'd5: addr_cmd = 8'h03;
                default: addr_cmd = 8'h00;
            endcase
        end
    endfunction

    always @(posedge clk) begin
        spi_start <= 1'b0;

        if (!rst_n) begin
            state <= S_VDD_WAIT;
            delay_count <= 32'd0;
            refresh_count <= 32'd0;
            init_index <= 5'd0;
            addr_index <= 3'd0;
            frame_index <= 9'd0;
            frame_clear <= 1'b1;
            frame_phase <= 3'd0;
            frame_manual <= 1'b0;
            rendered_phase <= 3'd7;
            rendered_manual <= 1'b1;
            oled_dc <= 1'b0;
            oled_res <= 1'b1;
            oled_vbat <= 1'b1;
            oled_vdd <= 1'b1;
            ready <= 1'b0;
            spi_data <= 8'h00;
        end else begin
            case (state)
                S_VDD_WAIT: begin
                    oled_dc <= 1'b0;
                    oled_res <= 1'b1;
                    oled_vbat <= 1'b1;
                    oled_vdd <= 1'b0;
                    ready <= 1'b0;
                    if (delay_count == CYCLES_1MS - 1) begin
                        delay_count <= 32'd0;
                        state <= S_RES_LOW;
                    end else begin
                        delay_count <= delay_count + 32'd1;
                    end
                end

                S_RES_LOW: begin
                    oled_res <= 1'b0;
                    if (delay_count == CYCLES_1MS - 1) begin
                        delay_count <= 32'd0;
                        state <= S_RES_HIGH;
                    end else begin
                        delay_count <= delay_count + 32'd1;
                    end
                end

                S_RES_HIGH: begin
                    oled_res <= 1'b1;
                    if (delay_count == CYCLES_1MS - 1) begin
                        delay_count <= 32'd0;
                        init_index <= 5'd0;
                        state <= S_INIT_START;
                    end else begin
                        delay_count <= delay_count + 32'd1;
                    end
                end

                S_INIT_START: begin
                    if (!spi_busy) begin
                        oled_dc <= 1'b0;
                        spi_data <= init_cmd(init_index);
                        spi_start <= 1'b1;
                        state <= S_INIT_WAIT;
                    end
                end

                S_INIT_WAIT: begin
                    if (spi_done) begin
                        if (init_index == INIT_LEN - 1) begin
                            delay_count <= 32'd0;
                            state <= S_VBAT_WAIT;
                        end else begin
                            init_index <= init_index + 5'd1;
                            state <= S_INIT_START;
                        end
                    end
                end

                S_VBAT_WAIT: begin
                    oled_vbat <= 1'b0;
                    if (delay_count == CYCLES_100MS - 1) begin
                        delay_count <= 32'd0;
                        frame_clear <= 1'b1;
                        frame_phase <= phase;
                        frame_manual <= manual_mode;
                        addr_index <= 3'd0;
                        state <= S_ADDR_START;
                    end else begin
                        delay_count <= delay_count + 32'd1;
                    end
                end

                S_ADDR_START: begin
                    if (!spi_busy) begin
                        oled_dc <= 1'b0;
                        spi_data <= addr_cmd(addr_index);
                        spi_start <= 1'b1;
                        state <= S_ADDR_WAIT;
                    end
                end

                S_ADDR_WAIT: begin
                    if (spi_done) begin
                        if (addr_index == ADDR_LEN - 1) begin
                            frame_index <= 9'd0;
                            state <= S_DATA_START;
                        end else begin
                            addr_index <= addr_index + 3'd1;
                            state <= S_ADDR_START;
                        end
                    end
                end

                S_DATA_START: begin
                    if (!spi_busy) begin
                        oled_dc <= 1'b1;
                        spi_data <= frame_data(frame_index, frame_phase, frame_manual, frame_clear);
                        spi_start <= 1'b1;
                        state <= S_DATA_WAIT;
                    end
                end

                S_DATA_WAIT: begin
                    if (spi_done) begin
                        if (frame_index == 9'd511) begin
                            if (frame_clear) begin
                                state <= S_DISP_ON_START;
                            end else begin
                                rendered_phase <= frame_phase;
                                rendered_manual <= frame_manual;
                                refresh_count <= 32'd0;
                                ready <= 1'b1;
                                state <= S_REFRESH_WAIT;
                            end
                        end else begin
                            frame_index <= frame_index + 9'd1;
                            state <= S_DATA_START;
                        end
                    end
                end

                S_DISP_ON_START: begin
                    if (!spi_busy) begin
                        oled_dc <= 1'b0;
                        spi_data <= 8'haf;
                        spi_start <= 1'b1;
                        state <= S_DISP_ON_WAIT;
                    end
                end

                S_DISP_ON_WAIT: begin
                    if (spi_done) begin
                        frame_clear <= 1'b0;
                        frame_phase <= phase;
                        frame_manual <= manual_mode;
                        addr_index <= 3'd0;
                        state <= S_ADDR_START;
                    end
                end

                S_REFRESH_WAIT: begin
                    if ((phase != rendered_phase) ||
                        (manual_mode != rendered_manual) ||
                        (refresh_count == REFRESH_CYCLES - 1)) begin
                        refresh_count <= 32'd0;
                        frame_clear <= 1'b0;
                        frame_phase <= phase;
                        frame_manual <= manual_mode;
                        addr_index <= 3'd0;
                        state <= S_ADDR_START;
                    end else begin
                        refresh_count <= refresh_count + 32'd1;
                    end
                end

                default: begin
                    state <= S_VDD_WAIT;
                end
            endcase
        end
    end
endmodule

module oled_spi_byte #(
    parameter integer SPI_HALF_CYCLES = 10
) (
    input  wire      clk,
    input  wire      rst_n,
    input  wire      start,
    input  wire [7:0] data,
    output reg       sclk,
    output reg       sdin,
    output reg       busy,
    output reg       done
);
    localparam integer DIV_WIDTH = (SPI_HALF_CYCLES <= 2) ? 1 : $clog2(SPI_HALF_CYCLES);
    localparam [1:0] S_IDLE = 2'd0;
    localparam [1:0] S_LOW  = 2'd1;
    localparam [1:0] S_HIGH = 2'd2;

    reg [1:0] state;
    reg [DIV_WIDTH-1:0] div_count;
    reg [2:0] bit_index;
    reg [7:0] data_shift;

    always @(posedge clk) begin
        done <= 1'b0;

        if (!rst_n) begin
            state <= S_IDLE;
            div_count <= {DIV_WIDTH{1'b0}};
            bit_index <= 3'd7;
            data_shift <= 8'h00;
            sclk <= 1'b0;
            sdin <= 1'b0;
            busy <= 1'b0;
        end else begin
            case (state)
                S_IDLE: begin
                    sclk <= 1'b0;
                    busy <= 1'b0;
                    div_count <= {DIV_WIDTH{1'b0}};
                    bit_index <= 3'd7;
                    if (start) begin
                        data_shift <= data;
                        sdin <= data[7];
                        busy <= 1'b1;
                        state <= S_LOW;
                    end
                end

                S_LOW: begin
                    busy <= 1'b1;
                    if (div_count == SPI_HALF_CYCLES - 1) begin
                        div_count <= {DIV_WIDTH{1'b0}};
                        sclk <= 1'b1;
                        state <= S_HIGH;
                    end else begin
                        div_count <= div_count + {{(DIV_WIDTH-1){1'b0}}, 1'b1};
                    end
                end

                S_HIGH: begin
                    busy <= 1'b1;
                    if (div_count == SPI_HALF_CYCLES - 1) begin
                        div_count <= {DIV_WIDTH{1'b0}};
                        sclk <= 1'b0;
                        if (bit_index == 3'd0) begin
                            done <= 1'b1;
                            busy <= 1'b0;
                            state <= S_IDLE;
                        end else begin
                            bit_index <= bit_index - 3'd1;
                            sdin <= data_shift[bit_index - 3'd1];
                            state <= S_LOW;
                        end
                    end else begin
                        div_count <= div_count + {{(DIV_WIDTH-1){1'b0}}, 1'b1};
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
