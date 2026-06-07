set_property -dict {PACKAGE_PIN AD12 IOSTANDARD LVDS} [get_ports clk_p]
set_property -dict {PACKAGE_PIN AD11 IOSTANDARD LVDS} [get_ports clk_n]
create_clock -period 5.000 -name sys_clk [get_ports clk_p]

set_property -dict {PACKAGE_PIN AC26 IOSTANDARD LVCMOS33 DRIVE 8 SLEW SLOW} [get_ports uart_tx]
set_property -dict {PACKAGE_PIN AJ27 IOSTANDARD LVCMOS33 PULLUP TRUE} [get_ports uart_rx]

set_property -dict {PACKAGE_PIN T28 IOSTANDARD LVCMOS33} [get_ports {led[0]}]
set_property -dict {PACKAGE_PIN V19 IOSTANDARD LVCMOS33} [get_ports {led[1]}]
