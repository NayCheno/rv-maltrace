`timescale 1ns / 1ps
`default_nettype none

module rvmt_genesys2_oled_status #(
    parameter int unsigned CLK_HZ = 50_000_000,
    parameter int unsigned SPI_HALF_CYCLES = 10
) (
    input  wire       clk,
    input  wire       rst_n,
    input  wire [2:0] phase,
    input  wire       manual_mode,
    input  wire [9:0] temperature_celsius,
    input  wire       temperature_valid,
    input  wire [3:0] fan_pwm_setting,
    output logic      oled_dc,
    output logic      oled_res,
    output wire       oled_sclk,
    output wire       oled_sdin,
    output logic      oled_vbat,
    output logic      oled_vdd,
    output logic      ready,
    output wire       updating
);
    localparam int unsigned CYCLES_1MS = CLK_HZ / 1000;
    localparam int unsigned CYCLES_100MS = CLK_HZ / 10;
    localparam int unsigned REFRESH_CYCLES = CLK_HZ / 4;
    localparam int unsigned INIT_LEN = 25;
    localparam int unsigned ADDR_LEN = 6;

    localparam logic [127:0] HEADER_TEXT = "RVMT GENESYS2   ";
    localparam logic [127:0] MODE_AUTO_TEXT = "AUTO HW STATUS  ";
    localparam logic [127:0] MODE_MANUAL_TEXT = "MANUAL SW2:0    ";
    localparam logic [127:0] PHASE_RESET_TEXT = "RESET           ";
    localparam logic [127:0] PHASE_BOOTING_TEXT = "BOOTING         ";
    localparam logic [127:0] PHASE_LINUX_BOOT_TEXT = "LINUX BOOT      ";
    localparam logic [127:0] PHASE_UART_XFER_TEXT = "UART XFER       ";
    localparam logic [127:0] PHASE_TESTING_TEXT = "TESTING         ";
    localparam logic [127:0] PHASE_TRACE_CAP_TEXT = "TRACE CAP       ";
    localparam logic [127:0] PHASE_PTR_SNAP_TEXT = "PTR SNAP        ";
    localparam logic [127:0] PHASE_DONE_IDLE_TEXT = "DONE IDLE       ";

    localparam logic [4:0] S_VDD_WAIT       = 5'd0;
    localparam logic [4:0] S_RES_LOW        = 5'd1;
    localparam logic [4:0] S_RES_HIGH       = 5'd2;
    localparam logic [4:0] S_INIT_START     = 5'd3;
    localparam logic [4:0] S_INIT_WAIT      = 5'd4;
    localparam logic [4:0] S_VBAT_WAIT      = 5'd5;
    localparam logic [4:0] S_ADDR_START     = 5'd6;
    localparam logic [4:0] S_ADDR_WAIT      = 5'd7;
    localparam logic [4:0] S_DATA_START     = 5'd8;
    localparam logic [4:0] S_DATA_WAIT      = 5'd9;
    localparam logic [4:0] S_DISP_ON_START  = 5'd10;
    localparam logic [4:0] S_DISP_ON_WAIT   = 5'd11;
    localparam logic [4:0] S_REFRESH_WAIT   = 5'd12;

    logic [4:0]  state;
    logic [31:0] delay_count;
    logic [31:0] refresh_count;
    logic [4:0]  init_index;
    logic [2:0]  addr_index;
    logic [8:0]  frame_index;
    logic        frame_clear;
    logic [2:0]  frame_phase;
    logic        frame_manual;
    logic [9:0]  frame_temperature_celsius;
    logic        frame_temperature_valid;
    logic [3:0]  frame_fan_pwm_setting;
    logic [2:0]  rendered_phase;
    logic        rendered_manual;
    logic [9:0]  rendered_temperature_celsius;
    logic        rendered_temperature_valid;
    logic [3:0]  rendered_fan_pwm_setting;

    logic        spi_start;
    logic [7:0]  spi_data;
    wire         spi_busy;
    wire         spi_done;

    rvmt_oled_spi_byte #(
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
        logic [39:0] bits;
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

    function automatic [7:0] text16_char(input logic [127:0] text, input [4:0] pos);
        logic [4:0] byte_index;
        begin
            text16_char = " ";
            if (pos < 5'd16) begin
                byte_index = 5'd15 - pos;
                text16_char = text[byte_index * 8 +: 8];
            end
        end
    endfunction

    function automatic [127:0] phase_text(input [2:0] phase_i);
        begin
            unique case (phase_i)
                3'd0: phase_text = PHASE_RESET_TEXT;
                3'd1: phase_text = PHASE_BOOTING_TEXT;
                3'd2: phase_text = PHASE_LINUX_BOOT_TEXT;
                3'd3: phase_text = PHASE_UART_XFER_TEXT;
                3'd4: phase_text = PHASE_TESTING_TEXT;
                3'd5: phase_text = PHASE_TRACE_CAP_TEXT;
                3'd6: phase_text = PHASE_PTR_SNAP_TEXT;
                3'd7: phase_text = PHASE_DONE_IDLE_TEXT;
            endcase
        end
    endfunction

    function automatic [7:0] digit_char(input logic [3:0] digit);
        begin
            digit_char = 8'h30 + {4'd0, digit};
        end
    endfunction

    function automatic [7:0] temperature_status_char(
        input [4:0] pos,
        input logic [9:0] temp_c_i,
        input logic temp_valid_i,
        input logic [3:0] fan_i
    );
        logic [9:0] temp_clamped;
        begin
            temp_clamped = temp_c_i > 10'd999 ? 10'd999 : temp_c_i;
            temperature_status_char = " ";
            unique case (pos)
                5'd0:  temperature_status_char = "T";
                5'd1:  temperature_status_char = "M";
                5'd2:  temperature_status_char = "P";
                5'd3:  temperature_status_char = " ";
                5'd4:  temperature_status_char = temp_valid_i ? digit_char((temp_clamped / 10'd100) % 10'd10) : "-";
                5'd5:  temperature_status_char = temp_valid_i ? digit_char((temp_clamped / 10'd10) % 10'd10) : "-";
                5'd6:  temperature_status_char = temp_valid_i ? digit_char(temp_clamped % 10'd10) : "-";
                5'd7:  temperature_status_char = "C";
                5'd8:  temperature_status_char = " ";
                5'd9:  temperature_status_char = "F";
                5'd10: temperature_status_char = "A";
                5'd11: temperature_status_char = "N";
                5'd12: temperature_status_char = " ";
                5'd13: temperature_status_char = digit_char(({6'd0, fan_i} / 10'd10) % 10'd10);
                5'd14: temperature_status_char = digit_char({6'd0, fan_i} % 10'd10);
                default: temperature_status_char = " ";
            endcase
        end
    endfunction

    function automatic [7:0] line_char(
        input [1:0] row,
        input [4:0] pos,
        input [2:0] phase_i,
        input manual_i,
        input [9:0] temp_c_i,
        input temp_valid_i,
        input [3:0] fan_i
    );
        begin
            line_char = " ";
            unique case (row)
                2'd0: line_char = text16_char(HEADER_TEXT, pos);
                2'd1: begin
                    unique case (pos)
                        5'd0: line_char = "P";
                        5'd1: line_char = 8'h30 + {5'b00000, phase_i};
                        5'd2: line_char = " ";
                        default: line_char = text16_char(phase_text(phase_i), pos - 5'd3);
                    endcase
                end
                2'd2: line_char = temperature_status_char(pos, temp_c_i, temp_valid_i, fan_i);
                2'd3: line_char = text16_char(manual_i ? MODE_MANUAL_TEXT : MODE_AUTO_TEXT, pos);
            endcase
        end
    endfunction

    function automatic [7:0] frame_data(
        input [8:0] index,
        input [2:0] phase_i,
        input manual_i,
        input [9:0] temp_c_i,
        input temp_valid_i,
        input [3:0] fan_i,
        input clear_i
    );
        logic [1:0] row;
        logic [6:0] col;
        logic [4:0] char_pos;
        logic [2:0] glyph_col;
        logic [7:0] ch;
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
                    ch = line_char(row, char_pos, phase_i, manual_i, temp_c_i, temp_valid_i, fan_i);
                    frame_data = (glyph_col == 3'd5) ? 8'h00 : font5x7(ch, glyph_col);
                end
            end
        end
    endfunction

    function automatic [7:0] init_cmd(input [4:0] index);
        begin
            unique case (index)
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
            unique case (index)
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

    always_ff @(posedge clk) begin
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
            frame_temperature_celsius <= 10'd0;
            frame_temperature_valid <= 1'b0;
            frame_fan_pwm_setting <= 4'd0;
            rendered_phase <= 3'd7;
            rendered_manual <= 1'b1;
            rendered_temperature_celsius <= 10'd0;
            rendered_temperature_valid <= 1'b0;
            rendered_fan_pwm_setting <= 4'd0;
            oled_dc <= 1'b0;
            oled_res <= 1'b1;
            oled_vbat <= 1'b1;
            oled_vdd <= 1'b1;
            ready <= 1'b0;
            spi_data <= 8'h00;
        end else begin
            unique case (state)
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
                        frame_temperature_celsius <= temperature_celsius;
                        frame_temperature_valid <= temperature_valid;
                        frame_fan_pwm_setting <= fan_pwm_setting;
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
                        spi_data <= frame_data(
                            frame_index,
                            frame_phase,
                            frame_manual,
                            frame_temperature_celsius,
                            frame_temperature_valid,
                            frame_fan_pwm_setting,
                            frame_clear
                        );
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
                                rendered_temperature_celsius <= frame_temperature_celsius;
                                rendered_temperature_valid <= frame_temperature_valid;
                                rendered_fan_pwm_setting <= frame_fan_pwm_setting;
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
                        frame_temperature_celsius <= temperature_celsius;
                        frame_temperature_valid <= temperature_valid;
                        frame_fan_pwm_setting <= fan_pwm_setting;
                        addr_index <= 3'd0;
                        state <= S_ADDR_START;
                    end
                end

                S_REFRESH_WAIT: begin
                    if ((phase != rendered_phase) ||
                        (manual_mode != rendered_manual) ||
                        (temperature_celsius != rendered_temperature_celsius) ||
                        (temperature_valid != rendered_temperature_valid) ||
                        (fan_pwm_setting != rendered_fan_pwm_setting) ||
                        (refresh_count == REFRESH_CYCLES - 1)) begin
                        refresh_count <= 32'd0;
                        frame_clear <= 1'b0;
                        frame_phase <= phase;
                        frame_manual <= manual_mode;
                        frame_temperature_celsius <= temperature_celsius;
                        frame_temperature_valid <= temperature_valid;
                        frame_fan_pwm_setting <= fan_pwm_setting;
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

module rvmt_oled_spi_byte #(
    parameter int unsigned SPI_HALF_CYCLES = 10
) (
    input  wire      clk,
    input  wire      rst_n,
    input  wire      start,
    input  wire [7:0] data,
    output logic     sclk,
    output logic     sdin,
    output logic     busy,
    output logic     done
);
    localparam int unsigned DIV_WIDTH = (SPI_HALF_CYCLES <= 2) ? 1 : $clog2(SPI_HALF_CYCLES);
    localparam logic [1:0] S_IDLE = 2'd0;
    localparam logic [1:0] S_LOW  = 2'd1;
    localparam logic [1:0] S_HIGH = 2'd2;

    logic [1:0] state;
    logic [DIV_WIDTH-1:0] div_count;
    logic [2:0] bit_index;
    logic [7:0] data_shift;

    always_ff @(posedge clk) begin
        done <= 1'b0;

        if (!rst_n) begin
            state <= S_IDLE;
            div_count <= '0;
            bit_index <= 3'd7;
            data_shift <= 8'h00;
            sclk <= 1'b0;
            sdin <= 1'b0;
            busy <= 1'b0;
        end else begin
            unique case (state)
                S_IDLE: begin
                    sclk <= 1'b0;
                    busy <= 1'b0;
                    div_count <= '0;
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
                        div_count <= '0;
                        sclk <= 1'b1;
                        state <= S_HIGH;
                    end else begin
                        div_count <= div_count + 1'b1;
                    end
                end

                S_HIGH: begin
                    busy <= 1'b1;
                    if (div_count == SPI_HALF_CYCLES - 1) begin
                        div_count <= '0;
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
                        div_count <= div_count + 1'b1;
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
