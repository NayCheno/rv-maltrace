## EmbedFire Shengteng Pro A35T / XC7A35T-FGG484-2 minimal sanity constraints.

set_property PACKAGE_PIN W19 [get_ports clk50]
set_property IOSTANDARD LVCMOS33 [get_ports clk50]
create_clock -name clk50 -period 20.000 [get_ports clk50]

set_property PACKAGE_PIN N15 [get_ports reset_n]
set_property IOSTANDARD LVCMOS33 [get_ports reset_n]

set_property PACKAGE_PIN M21 [get_ports {led[0]}]
set_property PACKAGE_PIN L21 [get_ports {led[1]}]
set_property PACKAGE_PIN K21 [get_ports {led[2]}]
set_property PACKAGE_PIN K22 [get_ports {led[3]}]
set_property IOSTANDARD LVCMOS33 [get_ports {led[*]}]
